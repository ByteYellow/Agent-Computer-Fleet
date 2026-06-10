package telemetry

import "database/sql"

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
