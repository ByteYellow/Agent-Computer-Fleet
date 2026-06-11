package telemetry

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/ids"
)

type EventRecord struct {
	ID         string
	RunID      string
	SessionID  string
	ToolCallID string
	ProcessID  string
	SnapshotID string
	Source     string
	EventType  string
	Payload    string
	CreatedAt  string
}

type IngestEvent struct {
	RunID      string
	RolloutID  string
	AttemptID  string
	SessionID  string
	ToolCallID string
	ProcessID  string
	SnapshotID string
	Source     string
	EventType  string
	Payload    string
}

type Filter struct {
	RunID      string
	SessionID  string
	Type       string
	ToolCallID string
}

func ListEvents(db *sql.DB, runID, sessionID string) ([]EventRecord, error) {
	return ListEventsFiltered(db, Filter{RunID: runID, SessionID: sessionID})
}

func ListEventsFiltered(db *sql.DB, filter Filter) ([]EventRecord, error) {
	query := `SELECT id, COALESCE(run_id, ''), COALESCE(session_id, ''), COALESCE(tool_call_id, ''),
		COALESCE(process_id, ''), COALESCE(snapshot_id, ''), source, event_type, payload, created_at
		FROM events`
	args := []any{}
	clauses := []string{}
	if filter.RunID != "" {
		clauses = append(clauses, "run_id = ?")
		args = append(args, filter.RunID)
	}
	if filter.SessionID != "" {
		clauses = append(clauses, "session_id = ?")
		args = append(args, filter.SessionID)
	}
	if filter.Type != "" {
		clauses = append(clauses, "event_type = ?")
		args = append(args, filter.Type)
	}
	if filter.ToolCallID != "" {
		clauses = append(clauses, "tool_call_id = ?")
		args = append(args, filter.ToolCallID)
	}
	if len(clauses) > 0 {
		query += " WHERE " + clauses[0]
		for i := 1; i < len(clauses); i++ {
			query += " AND " + clauses[i]
		}
	}
	query += " ORDER BY created_at ASC"
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []EventRecord
	for rows.Next() {
		var event EventRecord
		if err := rows.Scan(&event.ID, &event.RunID, &event.SessionID, &event.ToolCallID, &event.ProcessID, &event.SnapshotID, &event.Source, &event.EventType, &event.Payload, &event.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func IngestFiltered(db *sql.DB, event IngestEvent) (string, error) {
	if event.EventType == "" {
		return "", fmt.Errorf("event_type is required")
	}
	if !AllowedEventType(event.EventType) {
		return "", fmt.Errorf("telemetry event %q rejected by filtered driver", event.EventType)
	}
	if event.Source == "" {
		event.Source = "filtered_telemetry"
	}
	if event.Payload == "" {
		event.Payload = "{}"
	}
	eventID := ids.New("evt")
	now := time.Now().UTC().Format(time.RFC3339Nano)
	payload := event.Payload
	if event.RolloutID != "" || event.AttemptID != "" {
		payload = fmt.Sprintf(`{"rollout_id":%q,"attempt_id":%q,"payload":%s}`, event.RolloutID, event.AttemptID, event.Payload)
	}
	_, err := db.Exec(`INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, snapshot_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		eventID, event.RunID, event.SessionID, event.ToolCallID, event.ProcessID, event.SnapshotID, event.Source, event.EventType, payload, now)
	if err != nil {
		return "", err
	}
	priority := "normal"
	if event.EventType == "metadata_ip" || event.EventType == "private_cidr" || event.EventType == "secret_path" || event.EventType == "policy_verdict" {
		priority = "high"
	}
	if event.RolloutID != "" || event.AttemptID != "" || event.SnapshotID != "" {
		_, _ = db.Exec(`INSERT INTO evidence_events
			(id, run_id, rollout_id, attempt_id, session_id, tool_call_id, snapshot_id, event_type, priority, payload, status, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?)`,
			ids.New("evidence"), event.RunID, event.RolloutID, event.AttemptID, event.SessionID, event.ToolCallID, event.SnapshotID, event.EventType, priority, payload, now)
	}
	if event.SnapshotID != "" && highRiskEvent(event.EventType) {
		_ = taintSnapshotAndDescendants(db, event.SnapshotID, event.RunID, event.EventType, now)
	}
	return eventID, nil
}

func AllowedEventType(eventType string) bool {
	switch eventType {
	case "execve", "network_connect", "metadata_ip", "private_cidr", "secret_path", "abnormal_process_tree", "policy_verdict", "resource_pressure":
		return true
	default:
		return false
	}
}

func highRiskEvent(eventType string) bool {
	switch eventType {
	case "metadata_ip", "private_cidr", "secret_path", "policy_verdict":
		return true
	default:
		return false
	}
}

func taintSnapshotAndDescendants(db *sql.DB, snapshotID, runID, reason, now string) error {
	queue := []string{snapshotID}
	seen := map[string]bool{}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if seen[current] {
			continue
		}
		seen[current] = true
		if _, err := db.Exec(`UPDATE snapshots SET status = 'tainted', tainted = 1 WHERE id = ?`, current); err != nil {
			return err
		}
		rows, err := db.Query(`SELECT e.child_id FROM snapshot_edges e JOIN snapshots s ON s.id = e.child_id WHERE e.parent_id = ?`, current)
		if err != nil {
			return err
		}
		for rows.Next() {
			var child string
			if err := rows.Scan(&child); err != nil {
				rows.Close()
				return err
			}
			queue = append(queue, child)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}
	for id := range seen {
		_, _ = db.Exec(`INSERT INTO events (id, run_id, snapshot_id, source, event_type, payload, created_at)
			VALUES (?, ?, ?, 'filtered_telemetry', 'snapshot_tainted', ?, ?)`,
			ids.New("evt"), runID, id, fmt.Sprintf(`{"reason":%q,"root_snapshot_id":%q}`, reason, snapshotID), now)
	}
	return nil
}
