package telemetry

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/redact"
)

type EventRecord struct {
	ID                    string  `json:"id"`
	RunID                 string  `json:"run_id"`
	SessionID             string  `json:"session_id"`
	ToolCallID            string  `json:"tool_call_id"`
	ProcessID             string  `json:"process_id"`
	SnapshotID            string  `json:"snapshot_id"`
	RawEventID            string  `json:"raw_event_id"`
	CorrelationMethod     string  `json:"correlation_method"`
	CorrelationConfidence float64 `json:"correlation_confidence"`
	CorrelationClass      string  `json:"correlation_class,omitempty"`
	BindingSource         string  `json:"binding_source,omitempty"`
	SelfLaunched          bool    `json:"self_launched,omitempty"`
	ContainerID           string  `json:"container_id"`
	CgroupID              string  `json:"cgroup_id"`
	PID                   int64   `json:"pid"`
	TGID                  int64   `json:"tgid"`
	PPID                  int64   `json:"ppid"`
	Source                string  `json:"source"`
	EventType             string  `json:"event_type"`
	Payload               string  `json:"payload"`
	CreatedAt             string  `json:"created_at"`
}

type BatchRecord struct {
	ID             string `json:"id"`
	RunID          string `json:"run_id"`
	Format         string `json:"format"`
	Path           string `json:"path"`
	FileSHA256     string `json:"file_sha256"`
	Read           int    `json:"read"`
	Ingested       int    `json:"ingested"`
	Skipped        int    `json:"skipped"`
	Failed         int    `json:"failed"`
	EventIDsSHA256 string `json:"event_ids_sha256"`
	CreatedAt      string `json:"created_at"`
}

type IngestEvent struct {
	RunID       string
	RolloutID   string
	AttemptID   string
	SessionID   string
	ToolCallID  string
	ProcessID   string
	SnapshotID  string
	RawEventID  string
	ContainerID string
	CgroupID    string
	PID         int64
	TGID        int64
	PPID        int64
	Timestamp   string
	Source      string
	EventType   string
	Payload     string
	// BindingSource records which binding tier produced this event's
	// correlation (e.g. ai_asserted, zero_sdk_record, control_plane). When the
	// event is resolved against a stored binding it is overwritten from the
	// matched binding; callers with directly-provided context may set it so the
	// self-launched dimension is preserved on the provided_context path.
	BindingSource string
}

type Filter struct {
	RunID      string
	SessionID  string
	Type       string
	ToolCallID string
}

type ListOptions struct {
	Filter Filter
	Limit  int
	Cursor string
}

type ListResult struct {
	SchemaVersion string        `json:"schema_version"`
	Filter        Filter        `json:"filter"`
	Limit         int           `json:"limit"`
	Cursor        string        `json:"cursor,omitempty"`
	NextCursor    string        `json:"next_cursor,omitempty"`
	HasMore       bool          `json:"has_more"`
	EventCount    int           `json:"event_count"`
	TotalCount    int           `json:"total_count"`
	ResultSetID   string        `json:"result_set_id"`
	PageHash      string        `json:"page_hash"`
	Events        []EventRecord `json:"events"`
}

func ListEvents(db *sql.DB, runID, sessionID string) ([]EventRecord, error) {
	return ListEventsFiltered(db, Filter{RunID: runID, SessionID: sessionID})
}

func ListBatches(db *sql.DB, runID string) ([]BatchRecord, error) {
	query := `SELECT id, COALESCE(run_id, ''), format, path, file_sha256, read_count, ingested_count,
		skipped_count, failed_count, event_ids_sha256, created_at FROM telemetry_batches`
	args := []any{}
	if strings.TrimSpace(runID) != "" {
		query += ` WHERE run_id = ?`
		args = append(args, runID)
	}
	query += ` ORDER BY created_at ASC`
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var batches []BatchRecord
	for rows.Next() {
		var batch BatchRecord
		if err := rows.Scan(&batch.ID, &batch.RunID, &batch.Format, &batch.Path, &batch.FileSHA256, &batch.Read, &batch.Ingested, &batch.Skipped, &batch.Failed, &batch.EventIDsSHA256, &batch.CreatedAt); err != nil {
			return nil, err
		}
		batches = append(batches, batch)
	}
	return batches, rows.Err()
}

func ListEventsFiltered(db *sql.DB, filter Filter) ([]EventRecord, error) {
	result, err := ListEventsPage(db, ListOptions{Filter: filter, Limit: -1})
	if err != nil {
		return nil, err
	}
	return result.Events, nil
}

func ListEventsPage(db *sql.DB, opts ListOptions) (ListResult, error) {
	limit := opts.Limit
	unbounded := limit < 0
	if limit == 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	cursorCreatedAt, cursorID, err := parseEventCursor(opts.Cursor)
	if err != nil {
		return ListResult{}, err
	}
	query := `SELECT id, COALESCE(run_id, ''), COALESCE(session_id, ''), COALESCE(tool_call_id, ''),
		COALESCE(process_id, ''), COALESCE(snapshot_id, ''), COALESCE(raw_event_id, ''),
		COALESCE(correlation_method, ''), COALESCE(correlation_confidence, 0),
		COALESCE(container_id, ''), COALESCE(cgroup_id, ''), COALESCE(pid, 0),
		COALESCE(tgid, 0), COALESCE(ppid, 0), COALESCE(binding_source, ''),
		source, event_type, payload, created_at
		FROM events`
	args := []any{}
	clauses := eventFilterClauses(opts.Filter, &args)
	if opts.Cursor != "" {
		clauses = append(clauses, "(created_at > ? OR (created_at = ? AND id > ?))")
		args = append(args, cursorCreatedAt, cursorCreatedAt, cursorID)
	}
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY created_at ASC, id ASC"
	if !unbounded {
		query += " LIMIT ?"
		args = append(args, limit+1)
	}
	rows, err := db.Query(query, args...)
	if err != nil {
		return ListResult{}, err
	}
	defer rows.Close()
	var events []EventRecord
	for rows.Next() {
		var event EventRecord
		if err := rows.Scan(&event.ID, &event.RunID, &event.SessionID, &event.ToolCallID, &event.ProcessID, &event.SnapshotID, &event.RawEventID, &event.CorrelationMethod, &event.CorrelationConfidence, &event.ContainerID, &event.CgroupID, &event.PID, &event.TGID, &event.PPID, &event.BindingSource, &event.Source, &event.EventType, &event.Payload, &event.CreatedAt); err != nil {
			return ListResult{}, err
		}
		event.CorrelationClass = CorrelationClass(event.Source, event.CorrelationMethod, event.ContainerID, event.CorrelationConfidence)
		event.SelfLaunched = SelfLaunched(event.Source, event.BindingSource)
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return ListResult{}, err
	}
	hasMore := !unbounded && len(events) > limit
	if hasMore {
		events = events[:limit]
	}
	nextCursor := ""
	if hasMore && len(events) > 0 {
		last := events[len(events)-1]
		nextCursor = formatEventCursor(last.CreatedAt, last.ID)
	}
	total, err := countEvents(db, opts.Filter)
	if err != nil {
		return ListResult{}, err
	}
	resultSetID, pageHash, err := eventListIntegrity(opts.Filter, total, events, limit, opts.Cursor)
	if err != nil {
		return ListResult{}, err
	}
	return ListResult{
		SchemaVersion: "agentprovenance.telemetry_events/v1",
		Filter:        opts.Filter,
		Limit:         limit,
		Cursor:        opts.Cursor,
		NextCursor:    nextCursor,
		HasMore:       hasMore,
		EventCount:    len(events),
		TotalCount:    total,
		ResultSetID:   resultSetID,
		PageHash:      pageHash,
		Events:        events,
	}, nil
}

func eventFilterClauses(filter Filter, args *[]any) []string {
	clauses := []string{}
	if filter.RunID != "" {
		clauses = append(clauses, "run_id = ?")
		*args = append(*args, filter.RunID)
	}
	if filter.SessionID != "" {
		clauses = append(clauses, "session_id = ?")
		*args = append(*args, filter.SessionID)
	}
	if filter.Type != "" {
		clauses = append(clauses, "event_type = ?")
		*args = append(*args, filter.Type)
	}
	if filter.ToolCallID != "" {
		clauses = append(clauses, "tool_call_id = ?")
		*args = append(*args, filter.ToolCallID)
	}
	return clauses
}

func countEvents(db *sql.DB, filter Filter) (int, error) {
	query := `SELECT COALESCE(COUNT(*), 0) FROM events`
	args := []any{}
	clauses := eventFilterClauses(filter, &args)
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	var total int
	err := db.QueryRow(query, args...).Scan(&total)
	return total, err
}

func formatEventCursor(createdAt, id string) string {
	raw, _ := json.Marshal(map[string]any{"v": 1, "created_at": createdAt, "id": id})
	return base64.RawURLEncoding.EncodeToString(raw)
}

func parseEventCursor(cursor string) (string, string, error) {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return "", "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", "", fmt.Errorf("invalid telemetry cursor")
	}
	var payload struct {
		Version   int    `json:"v"`
		CreatedAt string `json:"created_at"`
		ID        string `json:"id"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", "", fmt.Errorf("invalid telemetry cursor")
	}
	if payload.Version != 1 || payload.CreatedAt == "" || payload.ID == "" {
		return "", "", fmt.Errorf("invalid telemetry cursor")
	}
	return payload.CreatedAt, payload.ID, nil
}

func eventListIntegrity(filter Filter, total int, events []EventRecord, limit int, cursor string) (string, string, error) {
	resultPayload := map[string]any{
		"kind":        "telemetry_events_result_set",
		"filter":      filter,
		"total_count": total,
	}
	resultRaw, err := json.Marshal(resultPayload)
	if err != nil {
		return "", "", err
	}
	resultSum := sha256.Sum256(resultRaw)
	pagePayload := map[string]any{
		"kind":          "telemetry_events_page",
		"result_set_id": fmt.Sprintf("sha256:%x", resultSum[:]),
		"limit":         limit,
		"cursor":        cursor,
		"event_ids":     eventIDs(events),
	}
	pageRaw, err := json.Marshal(pagePayload)
	if err != nil {
		return "", "", err
	}
	pageSum := sha256.Sum256(pageRaw)
	return fmt.Sprintf("sha256:%x", resultSum[:]), fmt.Sprintf("sha256:%x", pageSum[:]), nil
}

func eventIDs(events []EventRecord) []string {
	ids := make([]string, 0, len(events))
	for _, event := range events {
		ids = append(ids, event.ID)
	}
	return ids
}

type sqlStore interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

func IngestFiltered(db *sql.DB, event IngestEvent) (string, error) {
	return ingestFilteredWithStore(db, db, event)
}

func ingestFilteredWithStore(db *sql.DB, store sqlStore, event IngestEvent) (string, error) {
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
	if err := ValidateRawPayload(event.EventType, event.Payload); err != nil {
		return "", err
	}
	// Mask secrets at the capture boundary: raw telemetry (an execve's full argv,
	// a captured TLS body) can carry a live API key, and this payload flows on to
	// the store, the dashboard, --json output, and signed bundles. Redacting here
	// keeps the store itself clean; policy targets (IPs, file paths) and LLM
	// semantics live in different fields and are preserved.
	event.Payload = redact.RedactString(event.Payload)
	raw := correlation.RawIdentity{
		RunID:       event.RunID,
		ProcessID:   event.ProcessID,
		ContainerID: event.ContainerID,
		CgroupID:    event.CgroupID,
		PID:         event.PID,
		TGID:        event.TGID,
		PPID:        event.PPID,
		Timestamp:   event.Timestamp,
	}
	method := "provided_context"
	confidence := 1.0
	bindingSource := event.BindingSource
	if event.RunID == "" || event.SessionID == "" || event.ToolCallID == "" || event.ProcessID == "" {
		match, ok, err := correlation.Resolve(db, raw)
		if err != nil {
			return "", err
		}
		if ok {
			bindingSource = match.BindingSource
			if event.RunID == "" {
				event.RunID = match.RunID
			}
			if event.SessionID == "" {
				event.SessionID = match.SessionID
			}
			if event.ToolCallID == "" {
				event.ToolCallID = match.ToolCallID
			}
			if event.ProcessID == "" {
				event.ProcessID = match.ProcessID
			}
			if event.AttemptID == "" {
				event.AttemptID = match.AttemptID
			}
			if event.AttemptID != "" && (event.RolloutID == "" || event.SnapshotID == "") {
				var rolloutID, snapshotID string
				_ = store.QueryRow(`SELECT COALESCE(rollout_id, ''), COALESCE(snapshot_id, '') FROM fork_attempts WHERE id = ?`, event.AttemptID).Scan(&rolloutID, &snapshotID)
				if event.RolloutID == "" {
					event.RolloutID = rolloutID
				}
				if event.SnapshotID == "" {
					event.SnapshotID = snapshotID
				}
			}
			if event.ContainerID == "" {
				event.ContainerID = match.ContainerID
			}
			if event.CgroupID == "" {
				event.CgroupID = match.CgroupID
			}
			if event.PID == 0 {
				event.PID = match.PID
			}
			method = match.Method
			confidence = match.Confidence
			event.Payload = correlation.EventPayloadWithCorrelation(event.Payload, match, true)
		} else if event.RunID == "" || event.SessionID == "" || event.ToolCallID == "" {
			method = "unresolved"
			confidence = 0
			event.Payload = correlation.EventPayloadWithCorrelation(event.Payload, correlation.Match{}, false)
		}
	}
	if event.Source == "record_process_sample" && event.EventType == "process_observed" {
		method = "zero_sdk_process_tree"
		if confidence == 1.0 {
			confidence = 0.9
		}
	}
	eventID := ids.New("evt")
	now := time.Now().UTC().Format(time.RFC3339Nano)
	payload := event.Payload
	if event.RolloutID != "" || event.AttemptID != "" {
		payload = fmt.Sprintf(`{"rollout_id":%q,"attempt_id":%q,"payload":%s}`, event.RolloutID, event.AttemptID, event.Payload)
	}
	_, err := store.Exec(`INSERT INTO events
		(id, run_id, session_id, tool_call_id, process_id, snapshot_id, raw_event_id, correlation_method, correlation_confidence, container_id, cgroup_id, pid, tgid, ppid, binding_source, source, event_type, payload, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		eventID, event.RunID, event.SessionID, event.ToolCallID, event.ProcessID, event.SnapshotID, event.RawEventID, method, confidence, event.ContainerID, event.CgroupID, event.PID, event.TGID, event.PPID, bindingSource, event.Source, event.EventType, payload, now)
	if err != nil {
		return "", err
	}
	_ = recordRuntimeCausalityEdges(store, event, eventID, now)
	// Consume process_exit to CLOSE the exiting pid's correlation window, so a
	// later event that reuses the pid does not over-bind to this dead scope.
	// Use the event's own timestamp when present (chronological close), else now.
	if event.EventType == "process_exit" && event.PID != 0 {
		_ = correlation.CloseBindingByPID(store, event.PID, firstNonEmpty(event.Timestamp, now))
	}
	priority := "normal"
	if event.EventType == "metadata_ip" || event.EventType == "private_cidr" || event.EventType == "secret_path" || event.EventType == "policy_verdict" {
		priority = "high"
	}
	if event.RolloutID != "" || event.AttemptID != "" || event.SnapshotID != "" {
		_, _ = store.Exec(`INSERT INTO evidence_events
			(id, run_id, rollout_id, attempt_id, session_id, tool_call_id, snapshot_id, event_type, priority, payload, status, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?)`,
			ids.New("evidence"), event.RunID, event.RolloutID, event.AttemptID, event.SessionID, event.ToolCallID, event.SnapshotID, event.EventType, priority, payload, now)
	}
	if event.SnapshotID != "" && highRiskEvent(event.EventType) {
		_ = taintSnapshotAndDescendants(store, event.SnapshotID, event.RunID, event.EventType, now)
	}
	return eventID, nil
}

func AllowedEventType(eventType string) bool {
	switch eventType {
	case "execve", "process_exit", "process_observed", "file_open", "file_write", "network_connect", "metadata_ip", "private_cidr", "secret_path", "abnormal_process_tree", "policy_verdict", "resource_pressure", "tls_write", "tls_read", "setuid", "setgid", "ptrace", "file_rename", "file_unlink", "dns_query":
		return true
	default:
		return false
	}
}

func recordRuntimeCausalityEdges(db sqlStore, event IngestEvent, eventID, now string) error {
	if event.RunID == "" {
		return nil
	}
	rolloutID := event.RolloutID
	if rolloutID == "" && event.AttemptID != "" {
		_ = db.QueryRow(`SELECT COALESCE(rollout_id, '') FROM fork_attempts WHERE id = ?`, event.AttemptID).Scan(&rolloutID)
	}
	eventNode := "runtime_event/" + eventID
	insert := func(fromID, toID, edgeType string) {
		if fromID == "" || toID == "" {
			return
		}
		_, _ = db.Exec(`INSERT INTO graph_edges (id, run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			ids.New("edge"), event.RunID, rolloutID, fromID, toID, edgeType, eventID, now)
	}
	insert(event.AttemptID, eventNode, "runtime_attempt_event")
	insert(event.ToolCallID, event.ProcessID, "runtime_tool_call_process")
	insert(event.ToolCallID, eventNode, "runtime_tool_call_event")
	insert(event.ProcessID, eventNode, "runtime_process_event")
	insert(event.SnapshotID, eventNode, "runtime_snapshot_event")
	if event.ProcessID != "" && event.PID != 0 {
		processNode := fmt.Sprintf("runtime_process/pid/%d", event.PID)
		insert(event.ProcessID, processNode, "runtime_process_observed")
		insert(processNode, eventNode, "runtime_process_event")
	}
	if event.PID != 0 && event.PPID != 0 {
		parentNode := fmt.Sprintf("runtime_process/pid/%d", event.PPID)
		childNode := fmt.Sprintf("runtime_process/pid/%d", event.PID)
		insert(parentNode, childNode, "runtime_process_parent")
		insert(childNode, parentNode, "runtime_process_child_of")
	}
	if event.PID != 0 && event.TGID != 0 && event.TGID != event.PID {
		threadGroupNode := fmt.Sprintf("runtime_process/tgid/%d", event.TGID)
		processNode := fmt.Sprintf("runtime_process/pid/%d", event.PID)
		insert(threadGroupNode, processNode, "runtime_process_thread")
	}
	if event.EventType == "file_write" || event.EventType == "file_open" {
		path := payloadPath(event.Payload)
		if path == "" {
			// Passive node-side capture (no workspace) writes absolute host paths,
			// which payloadPath rejects; keep substantive ones as file nodes so the
			// file lens works without a record workspace diff.
			path = substantiveAbsFilePath(event.Payload)
		}
		if path != "" {
			fileNode := "workspace_file/" + path
			insert(eventNode, fileNode, "runtime_event_file")
			if event.ProcessID != "" {
				insert(event.ProcessID, fileNode, "runtime_process_file")
			}
			if event.ToolCallID != "" {
				insert(event.ToolCallID, fileNode, "runtime_tool_call_file")
			}
			if event.AttemptID != "" {
				insert(event.AttemptID, fileNode, "runtime_attempt_file")
			}
		}
	}
	// Intent -> action causal edge: if a TLS response (the model's decision) was
	// observed in the same scope shortly before this action event, link it. This
	// is the "LLM intent caused this syscall" edge over the verifiable DAG.
	if llmActionEventType(event.EventType) {
		if intentID := recentLLMIntent(db, event.RunID, event.ProcessID, now); intentID != "" {
			insert("runtime_event/"+intentID, eventNode, "llm_intent_caused")
		}
	}
	// Request -> response pairing: when a TLS response arrives, link it to the
	// most recent TLS request in the same scope. This forms the llm_call as a
	// DERIVED edge over the trusted tls_write/tls_read events -- not a new,
	// model-forgeable raw event type. A streaming (SSE) response surfaces as many
	// tls_read events, so we dedup: the first response segment wins and a request
	// gets exactly one llm_call edge. (Full chunk reassembly is a deferred TODO.)
	if event.EventType == "tls_read" {
		if reqID := recentLLMRequest(db, event.RunID, event.ProcessID, now); reqID != "" {
			fromNode := "runtime_event/" + reqID
			if !edgeExists(db, fromNode, "llm_call") {
				insert(fromNode, eventNode, "llm_call")
			}
		}
	}
	return nil
}

// edgeExists reports whether a graph edge of edgeType already originates from
// fromID, so callers can keep a relationship 1:1 (e.g. one request -> one
// llm_call despite a streamed, multi-segment response).
func edgeExists(db sqlStore, fromID, edgeType string) bool {
	var x int
	return db.QueryRow(`SELECT 1 FROM graph_edges WHERE from_id = ? AND edge_type = ? LIMIT 1`, fromID, edgeType).Scan(&x) == nil
}

// llmActionEventType reports whether an event is an "action" that an LLM
// response could plausibly have caused (exec/egress/file effects).
func llmActionEventType(eventType string) bool {
	switch eventType {
	case "execve", "network_connect", "metadata_ip", "private_cidr", "file_write", "secret_path":
		return true
	default:
		return false
	}
}

// recentLLMIntent returns the id of the most recent tls_read (LLM response)
// event in the same scope within the pairing window before now, or "".
func recentLLMIntent(db sqlStore, runID, processID, now string) string {
	return recentScopedEvent(db, "tls_read", runID, processID, now)
}

// recentLLMRequest returns the id of the most recent tls_write (LLM request)
// event in the same scope within the pairing window before now, or "".
func recentLLMRequest(db sqlStore, runID, processID, now string) string {
	return recentScopedEvent(db, "tls_write", runID, processID, now)
}

// recentScopedEvent returns the id of the most recent event of eventType in the
// same run (and process, when known) within a 2-minute window before now, or ""
// if none. now and stored created_at are RFC3339Nano UTC, so lexical string
// comparison is chronological.
func recentScopedEvent(db sqlStore, eventType, runID, processID, now string) string {
	if runID == "" {
		return ""
	}
	windowStart := now
	if t, err := time.Parse(time.RFC3339Nano, now); err == nil {
		windowStart = t.Add(-2 * time.Minute).UTC().Format(time.RFC3339Nano)
	}
	query := `SELECT id FROM events WHERE run_id = ? AND event_type = ?
		AND created_at <= ? AND created_at >= ?`
	args := []any{runID, eventType, now, windowStart}
	if processID != "" {
		query += ` AND process_id = ?`
		args = append(args, processID)
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT 1`
	var id string
	_ = db.QueryRow(query, args...).Scan(&id)
	return id
}

// substantiveAbsFilePath returns the absolute file path from a raw file event's
// payload when it is a real file worth a graph node, or "" for the pseudo-file
// noise a passive sensor sees a lot of (/dev/null, /proc, /sys, sockets, pipes).
// Relative paths return "" here — those are payloadPath's (workspace) job.
func substantiveAbsFilePath(payload string) string {
	var decoded any
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		return ""
	}
	p := strings.TrimSpace(findPayloadPath(decoded))
	if !strings.HasPrefix(p, "/") || p == "/dev/null" {
		return ""
	}
	for _, pre := range []string{"/dev/", "/proc/", "/sys/", "/run/", "pipe:", "socket:", "anon_inode:"} {
		if strings.HasPrefix(p, pre) {
			return ""
		}
	}
	return p
}

func payloadPath(payload string) string {
	var decoded any
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		return ""
	}
	path := findPayloadPath(decoded)
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "/workspace/")
	path = strings.TrimPrefix(path, "./")
	if path == "." || path == ".." || strings.HasPrefix(path, "../") || strings.HasPrefix(path, "/") {
		return ""
	}
	return path
}

func findPayloadPath(value any) string {
	switch typed := value.(type) {
	case map[string]any:
		for _, key := range []string{"path", "file"} {
			if raw, ok := typed[key].(string); ok && raw != "" {
				return raw
			}
		}
		for _, key := range []string{"raw", "payload", "event"} {
			if nested, ok := typed[key]; ok {
				if path := findPayloadPath(nested); path != "" {
					return path
				}
			}
		}
	case []any:
		for _, item := range typed {
			if path := findPayloadPath(item); path != "" {
				return path
			}
		}
	}
	return ""
}

func highRiskEvent(eventType string) bool {
	switch eventType {
	case "metadata_ip", "private_cidr", "secret_path", "policy_verdict":
		return true
	default:
		return false
	}
}

func taintSnapshotAndDescendants(db sqlStore, snapshotID, runID, reason, now string) error {
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
