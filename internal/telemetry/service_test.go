package telemetry

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestIngestFilteredCorrelatesRawRuntimeEvent(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	started := time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
	if _, err := correlation.RecordBinding(db, correlation.Binding{
		RunID:         "run-1",
		SessionID:     "session-1",
		AttemptID:     "attempt-1",
		ToolCallID:    "tool-1",
		ProcessID:     "proc-1",
		ContainerID:   "container-1",
		CgroupID:      "cgroup-1",
		PID:           1234,
		StartedAt:     started,
		BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := IngestFiltered(db, IngestEvent{
		RawEventID:  "raw-1",
		ContainerID: "container-1",
		PID:         1234,
		TGID:        1200,
		PPID:        42,
		EventType:   "execve",
		Source:      "tetragon_jsonl",
		Payload:     `{"argv":["sh","-lc","echo hi"]}`,
	}); err != nil {
		t.Fatal(err)
	}

	events, err := ListEventsFiltered(db, Filter{RunID: "run-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	event := events[0]
	if event.RunID != "run-1" || event.SessionID != "session-1" || event.ToolCallID != "tool-1" || event.ProcessID != "proc-1" {
		t.Fatalf("event correlation = %+v, want run/session/tool/process", event)
	}
	if !strings.Contains(event.CorrelationMethod, "container_time_window") || event.CorrelationConfidence <= 0 {
		t.Fatalf("correlation method/confidence = %q %.2f", event.CorrelationMethod, event.CorrelationConfidence)
	}
	if !strings.Contains(event.Payload, `"binding_id"`) {
		t.Fatalf("payload missing correlation binding: %s", event.Payload)
	}
	for _, edgeType := range []string{"runtime_tool_call_process", "runtime_tool_call_event", "runtime_process_event", "runtime_process_observed", "runtime_process_parent", "runtime_process_child_of", "runtime_process_thread"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE edge_type = ?`, edgeType).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			t.Fatalf("missing runtime causality edge %s", edgeType)
		}
	}
}

func TestIngestFilteredLeavesUnresolvedRawEvent(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := IngestFiltered(db, IngestEvent{
		RawEventID: "raw-missing",
		PID:        9999,
		EventType:  "execve",
		Source:     "falco_jsonl",
		Payload:    `{"argv":["unknown"]}`,
	}); err != nil {
		t.Fatal(err)
	}
	events, err := ListEventsFiltered(db, Filter{Type: "execve"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	event := events[0]
	if event.ToolCallID != "" || event.CorrelationMethod != "unresolved" || event.CorrelationConfidence != 0 {
		t.Fatalf("unresolved event = %+v", event)
	}
}

func TestIngestFilteredCorrelatesCgroupScopedRuntimeEvent(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	started := time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
	if _, err := correlation.RecordBinding(db, correlation.Binding{
		RunID:         "run-1",
		SessionID:     "session-1",
		AttemptID:     "attempt-1",
		ToolCallID:    "tool-1",
		ProcessID:     "proc-1",
		ContainerID:   "container-1",
		CgroupID:      "cgroup-1",
		StartedAt:     started,
		BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := IngestFiltered(db, IngestEvent{
		RawEventID: "raw-cgroup-1",
		CgroupID:   "cgroup-1",
		EventType:  "network_connect",
		Source:     "tetragon_jsonl",
		Payload:    `{"dst":"api.example.com:443"}`,
	}); err != nil {
		t.Fatal(err)
	}

	events, err := ListEventsFiltered(db, Filter{RunID: "run-1", Type: "network_connect"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	event := events[0]
	if event.ToolCallID != "tool-1" || event.ProcessID != "proc-1" {
		t.Fatalf("event correlation = %+v, want tool/process", event)
	}
	if event.CorrelationMethod != "cgroup_time_window:cgroup_id+time" {
		t.Fatalf("correlation method = %q", event.CorrelationMethod)
	}
	var edgeCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE edge_type = 'runtime_tool_call_event' AND from_id = 'tool-1'`).Scan(&edgeCount); err != nil {
		t.Fatal(err)
	}
	if edgeCount == 0 {
		t.Fatalf("missing runtime_tool_call_event edge for cgroup-scoped event")
	}
}

func TestIngestFilteredAcceptsFileRuntimeEvents(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := IngestFiltered(db, IngestEvent{
		RunID:      "run-1",
		SessionID:  "session-1",
		ToolCallID: "tool-1",
		ProcessID:  "process-1",
		AttemptID:  "attempt-1",
		EventType:  "file_write",
		Source:     "native_runtime",
		Payload:    `{"path":"calculator.py","op":"write"}`,
	}); err != nil {
		t.Fatal(err)
	}
	var edges int
	if err := db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE edge_type = 'runtime_process_event'`).Scan(&edges); err != nil {
		t.Fatal(err)
	}
	if edges != 1 {
		t.Fatalf("runtime_process_event edges=%d, want 1", edges)
	}
	for _, edgeType := range []string{"runtime_event_file", "runtime_process_file", "runtime_tool_call_file", "runtime_attempt_file"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE edge_type = ? AND to_id = 'workspace_file/calculator.py'`, edgeType).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("%s edges=%d, want 1", edgeType, count)
		}
	}
}

func TestIngestFilteredRejectsContextInRawPayload(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := IngestFiltered(db, IngestEvent{
		EventType: "execve",
		Source:    "tetragon_jsonl",
		Payload:   `{"argv":["pytest","-q"],"tool_call_id":"tool-leaked"}`,
	}); err == nil || !strings.Contains(err.Error(), "tool_call_id") {
		t.Fatalf("expected raw payload context rejection, got %v", err)
	}
}

func TestIngestFilteredRejectsInvalidEventSchema(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := IngestFiltered(db, IngestEvent{
		EventType: "file_write",
		Source:    "native_runtime",
		Payload:   `{"op":"write"}`,
	}); err == nil || !strings.Contains(err.Error(), "requires a non-traversal path or file") {
		t.Fatalf("expected file_write schema rejection, got %v", err)
	}
	// Path traversal is still rejected even though absolute host paths are allowed.
	if _, err := IngestFiltered(db, IngestEvent{
		EventType: "file_write",
		Source:    "native_runtime",
		Payload:   `{"path":"../escape"}`,
	}); err == nil || !strings.Contains(err.Error(), "non-traversal") {
		t.Fatalf("expected file_write traversal rejection, got %v", err)
	}
	// Absolute host paths from system telemetry are accepted.
	if _, err := IngestFiltered(db, IngestEvent{
		EventType: "file_write",
		Source:    "native_runtime",
		Payload:   `{"path":"/tmp/agentprov-demo"}`,
	}); err != nil {
		t.Fatalf("expected absolute host path to be accepted, got %v", err)
	}
}

func TestListEventsPageUsesOpaqueCursor(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for i := 0; i < 5; i++ {
		if _, err := IngestFiltered(db, IngestEvent{
			RunID:     "run-page",
			EventType: "execve",
			Source:    "native_runtime",
			Payload:   `{"argv":["echo","page"]}`,
		}); err != nil {
			t.Fatal(err)
		}
	}

	page1, err := ListEventsPage(db, ListOptions{Filter: Filter{RunID: "run-page"}, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if page1.SchemaVersion != "agentprovenance.telemetry_events/v1" || page1.EventCount != 2 || page1.TotalCount != 5 || !page1.HasMore || page1.NextCursor == "" {
		t.Fatalf("unexpected page1: %+v", page1)
	}
	if strings.Contains(page1.NextCursor, "|") || strings.Contains(page1.NextCursor, "evt-") {
		t.Fatalf("cursor should be opaque: %q", page1.NextCursor)
	}
	if page1.ResultSetID == "" || page1.PageHash == "" {
		t.Fatalf("missing integrity fields: %+v", page1)
	}

	page2, err := ListEventsPage(db, ListOptions{Filter: Filter{RunID: "run-page"}, Limit: 2, Cursor: page1.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if page2.EventCount != 2 || page2.Cursor != page1.NextCursor {
		t.Fatalf("unexpected page2: %+v", page2)
	}
	if page2.Events[0].ID == page1.Events[0].ID || page2.Events[0].ID == page1.Events[1].ID {
		t.Fatalf("page2 repeated page1 event: page1=%+v page2=%+v", page1.Events, page2.Events)
	}
	if page2.ResultSetID != page1.ResultSetID {
		t.Fatalf("paged result_set_id changed: page1=%s page2=%s", page1.ResultSetID, page2.ResultSetID)
	}
	if page2.PageHash == "" || page2.PageHash == page1.PageHash {
		t.Fatalf("page hash should be present and page-specific: page1=%s page2=%s", page1.PageHash, page2.PageHash)
	}

	all, err := ListEventsFiltered(db, Filter{RunID: "run-page"})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 {
		t.Fatalf("legacy list returned %d events, want 5", len(all))
	}
	if _, err := ListEventsPage(db, ListOptions{Filter: Filter{RunID: "run-page"}, Limit: 2, Cursor: "2"}); err == nil {
		t.Fatalf("old-style cursor should be rejected")
	}
}

func TestProcessExitClosesCorrelationWindow(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// An open binding for OS pid 4242 in run-x.
	if _, err := correlation.RecordBinding(db, correlation.Binding{
		RunID: "run-x", SessionID: "s", AttemptID: "a", ToolCallID: "tc", ProcessID: "p",
		PID: 4242, StartedAt: "2026-01-01T00:00:00.000000000Z", BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}

	// While open, a pid-tier event resolves to the run.
	id1, err := IngestFiltered(db, IngestEvent{
		PID: 4242, Timestamp: "2026-01-01T00:00:10.000000000Z",
		EventType: "execve", Source: "tetragon_jsonl", Payload: `{"argv":["sh","-lc","echo a"]}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	ev1 := getEvent(t, db, id1)
	if ev1.RunID != "run-x" {
		t.Fatalf("event before exit should resolve to run-x, got %q (%s)", ev1.RunID, ev1.CorrelationMethod)
	}

	// process_exit for pid 4242 closes the binding window.
	if _, err := IngestFiltered(db, IngestEvent{
		PID: 4242, Timestamp: "2026-01-01T00:00:20.000000000Z",
		EventType: "process_exit", Source: "agentprov_ebpf", Payload: `{"exit_code":0}`,
	}); err != nil {
		t.Fatal(err)
	}
	bindings, err := correlation.ListBindings(db, correlation.BindingFilter{RunID: "run-x"})
	if err != nil || len(bindings) != 1 {
		t.Fatalf("bindings=%d err=%v", len(bindings), err)
	}
	if bindings[0].EndedAt == "" {
		t.Fatal("process_exit must close the binding (ended_at set)")
	}

	// A LATER event reusing pid 4242 must NOT over-bind to the dead scope.
	id2, err := IngestFiltered(db, IngestEvent{
		PID: 4242, Timestamp: "2026-01-01T00:00:30.000000000Z",
		EventType: "execve", Source: "tetragon_jsonl", Payload: `{"argv":["sh","-lc","echo b"]}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	ev2 := getEvent(t, db, id2)
	if ev2.RunID == "run-x" {
		t.Fatalf("event after exit must NOT bind to the closed scope, got run-x (%s)", ev2.CorrelationMethod)
	}
}

func getEvent(t *testing.T, db *sql.DB, id string) EventRecord {
	t.Helper()
	events, err := ListEventsFiltered(db, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("event %s not found", id)
	return EventRecord{}
}

// TestIngestFilteredRedactsSecretsButKeepsDetectionTargets pins the capture-time
// redaction contract: a live API key captured in an execve's argv must be masked
// in the stored event, while the policy detection target in the same command
// (the metadata IP) must survive untouched — redaction cannot blind the signal.
func TestIngestFilteredRedactsSecretsButKeepsDetectionTargets(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const key = "sk-003fe97861dc48ebba10d6d391e4cebe"
	if _, err := IngestFiltered(db, IngestEvent{
		RunID:      "run-red",
		RawEventID: "raw-red",
		PID:        4242,
		EventType:  "execve",
		Source:     "agentprov_ebpf",
		Payload:    `{"argv":["curl","-H","x-api-key:","` + key + `","http://169.254.169.254/latest/meta-data/"]}`,
	}); err != nil {
		t.Fatal(err)
	}

	events, err := ListEventsFiltered(db, Filter{RunID: "run-red"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	payload := events[0].Payload
	if strings.Contains(payload, key) {
		t.Errorf("API key survived in stored event: %s", payload)
	}
	if !strings.Contains(payload, "169.254.169.254") {
		t.Errorf("detection target (metadata IP) was lost: %s", payload)
	}
}
