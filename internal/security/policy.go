package security

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/ids"
)

type Event struct {
	Source     string   `json:"source"`
	EventType  string   `json:"event_type"`
	RunID      string   `json:"run_id"`
	SessionID  string   `json:"session_id"`
	ToolCallID string   `json:"tool_call_id"`
	ProcessID  string   `json:"process_id"`
	SnapshotID string   `json:"snapshot_id"`
	DstIP      string   `json:"dst_ip"`
	Path       string   `json:"path"`
	Args       []string `json:"args"`
}

type Decision struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

type DecisionRecord struct {
	ID        string
	EventID   string
	RunID     string
	SessionID string
	Decision  string
	Reason    string
	CreatedAt string
}

type Engine struct {
	SecretPathPatterns []string
}

func DefaultEngine() Engine {
	return Engine{SecretPathPatterns: []string{".env", "id_rsa", "secret", "credentials"}}
}

func (e Engine) Evaluate(event Event) Decision {
	if event.DstIP == "169.254.169.254" || strings.Contains(strings.Join(event.Args, " "), "169.254.169.254") {
		return Decision{Decision: "quarantine", Reason: "metadata IP access"}
	}
	if event.DstIP != "" && isPrivateIP(event.DstIP) {
		return Decision{Decision: "deny", Reason: "private CIDR access"}
	}
	for _, pattern := range e.SecretPathPatterns {
		if strings.Contains(event.Path, pattern) {
			return Decision{Decision: "kill", Reason: "secret path access"}
		}
	}
	return Decision{Decision: "allow", Reason: "no policy matched"}
}

func EvaluateJSONL(path string, out io.Writer) error {
	return evaluateJSONL(path, out, nil)
}

func EvaluateJSONLWithState(db *sql.DB, path string, out io.Writer) error {
	return evaluateJSONL(path, out, db)
}

func EvaluateAndPersist(db *sql.DB, event Event, rawPayload string) (DecisionRecord, error) {
	decision := DefaultEngine().Evaluate(event)
	return persistDecision(db, event, rawPayload, decision)
}

func PersistDecision(db *sql.DB, event Event, rawPayload string, decision Decision) (DecisionRecord, error) {
	return persistDecision(db, event, rawPayload, decision)
}

func ListDecisions(db *sql.DB, runID string) ([]DecisionRecord, error) {
	query := `SELECT id, COALESCE(event_id, ''), COALESCE(run_id, ''), COALESCE(session_id, ''), decision, reason, created_at
		FROM policy_decisions`
	args := []any{}
	if runID != "" {
		query += ` WHERE run_id = ?`
		args = append(args, runID)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []DecisionRecord
	for rows.Next() {
		var record DecisionRecord
		if err := rows.Scan(&record.ID, &record.EventID, &record.RunID, &record.SessionID, &record.Decision, &record.Reason, &record.CreatedAt); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func evaluateJSONL(path string, out io.Writer, db *sql.DB) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	engine := DefaultEngine()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return err
		}
		decision := engine.Evaluate(event)
		if db != nil {
			if _, err := persistDecision(db, event, line, decision); err != nil {
				return err
			}
		}
		row := map[string]any{"event": event, "decision": decision.Decision, "reason": decision.Reason}
		b, _ := json.Marshal(row)
		fmt.Fprintln(out, string(b))
	}
	return scanner.Err()
}

func persistDecision(db *sql.DB, event Event, rawPayload string, decision Decision) (DecisionRecord, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	eventID := ids.New("evt")
	_, err := db.Exec(`INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, snapshot_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, eventID, event.RunID, event.SessionID, event.ToolCallID, event.ProcessID, event.SnapshotID, event.Source, event.EventType, rawPayload, now)
	if err != nil {
		return DecisionRecord{}, err
	}
	record := DecisionRecord{
		ID:        ids.New("dec"),
		EventID:   eventID,
		RunID:     event.RunID,
		SessionID: event.SessionID,
		Decision:  decision.Decision,
		Reason:    decision.Reason,
		CreatedAt: now,
	}
	_, err = db.Exec(`INSERT INTO policy_decisions (id, event_id, run_id, session_id, decision, reason, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, record.ID, eventID, event.RunID, event.SessionID, decision.Decision, decision.Reason, now)
	if err != nil {
		return DecisionRecord{}, err
	}
	blockCount := int64(0)
	quarantineCount := int64(0)
	if decision.Decision != "allow" {
		blockCount = 1
	}
	switch decision.Decision {
	case "quarantine":
		quarantineCount = 1
		if event.SessionID != "" {
			_, _ = db.Exec(`UPDATE sessions SET status = 'quarantined', updated_at = ? WHERE id = ?`, now, event.SessionID)
			_, _ = db.Exec(`UPDATE snapshots SET status = 'tainted' WHERE session_id = ?`, event.SessionID)
		}
	case "kill":
		if event.SessionID != "" {
			_, _ = db.Exec(`UPDATE sessions SET status = 'stopped', updated_at = ? WHERE id = ?`, now, event.SessionID)
			_, _ = db.Exec(`UPDATE snapshots SET status = 'tainted' WHERE session_id = ?`, event.SessionID)
		}
		if event.ProcessID != "" {
			_, _ = db.Exec(`UPDATE processes SET status = 'killed', ended_at = ? WHERE id = ?`, now, event.ProcessID)
		}
	}
	if event.RunID != "" {
		_, _ = db.Exec(`INSERT INTO cost_samples (id, run_id, session_id, policy_block_count, quarantine_count, created_at)
			VALUES (?, ?, ?, ?, ?, ?)`, ids.New("cost"), event.RunID, event.SessionID, blockCount, quarantineCount, now)
	}
	return record, nil
}

func isPrivateIP(raw string) bool {
	ip := net.ParseIP(raw)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback()
}
