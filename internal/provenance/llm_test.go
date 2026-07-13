package provenance

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/store"
)

// TestMaterializeLLMCallsDirectLink proves the llm_call node connects directly to
// the syscall its response caused (lifting the ingest-time llm_intent_caused edge
// from the tls_read event up to the llm_call).
func TestMaterializeLLMCallsDirectLink(t *testing.T) {
	paths, err := store.Init(filepath.Join(t.TempDir(), ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := ObjectStore{DB: db, Paths: paths}
	const run = "run-dl"
	ins := func(id, etype, payload string) {
		if _, err := db.Exec(`INSERT INTO events (id, run_id, source, event_type, payload, created_at)
			VALUES (?, ?, 'agentprov_ebpf', ?, ?, '2026-01-01T00:00:01Z')`, id, run, etype, payload); err != nil {
			t.Fatal(err)
		}
	}
	ins("ev-req", "tls_write", `{"content":"{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"go\"}]}"}`)
	// The model decides to run a specific command via tool_use.
	ins("ev-resp", "tls_read", `{"content":"{\"model\":\"m\",\"stop_reason\":\"tool_use\",\"content\":[{\"type\":\"tool_use\",\"name\":\"bash\",\"input\":{\"command\":\"cat /home/u/.aws/credentials\"}}]}"}`)
	// The syscall that ran exactly that command -- and an unrelated one that must NOT link.
	ins("ev-exec", "execve", `{"payload":{"raw":{"command":"cat /home/u/.aws/credentials"}}}`)
	ins("ev-other", "execve", `{"payload":{"raw":{"command":"ls -la /tmp"}}}`)
	if _, err := db.Exec(`INSERT INTO graph_edges (id, run_id, from_id, to_id, edge_type, created_at)
		VALUES (?, ?, 'runtime_event/ev-req', 'runtime_event/ev-resp', 'llm_call', '2026-01-01T00:00:02Z')`, ids.New("edge"), run); err != nil {
		t.Fatal(err)
	}

	if _, err := MaterializeLLMCalls(st, db, run); err != nil {
		t.Fatal(err)
	}
	// Only the command-matched execve links; the unrelated one does not.
	var caused, other int
	db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id=? AND from_id='llm_call/ev-req' AND to_id='runtime_event/ev-exec' AND edge_type='llm_caused'`, run).Scan(&caused)
	db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id=? AND to_id='runtime_event/ev-other' AND edge_type='llm_caused'`, run).Scan(&other)
	if caused != 1 {
		t.Errorf("llm_caused edge llm_call -> matching execve = %d, want 1", caused)
	}
	if other != 0 {
		t.Errorf("unrelated execve got %d llm_caused edges, want 0 (command-match must be precise)", other)
	}
}

// When the eBPF execve truncates its argv (losing the script path), the record
// process sample still carries the full /proc/cmdline command -- so command-match
// stays robust and the llm_caused edge survives argv truncation.
func TestCommandMatchedActionsRobustToExecveTruncation(t *testing.T) {
	paths, err := store.Init(filepath.Join(t.TempDir(), ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const run = "run-trunc"
	ins := func(id, etype, payload string) {
		if _, err := db.Exec(`INSERT INTO events (id, run_id, source, event_type, payload, created_at)
			VALUES (?, ?, 'x', ?, ?, '2026-01-01T00:00:01Z')`, id, run, etype, payload); err != nil {
			t.Fatal(err)
		}
	}
	decided := "python3 ../pysnake-helper/setup.py install --user"
	// The execve for that command came through truncated to just the program.
	ins("ev-exec", "execve", `{"payload":{"raw":{"command":"/usr/bin/python3"}}}`)
	// The record sample of the same process kept the full /proc/cmdline command.
	ins("ev-proc", "process_observed", `{"payload":{"command":"python3 ../pysnake-helper/setup.py install --user","pid":913280}}`)
	// An unrelated sample must not match.
	ins("ev-other", "process_observed", `{"payload":{"command":"ls -la /tmp/build","pid":42}}`)

	got, err := commandMatchedActions(db, run, []string{decided})
	if err != nil {
		t.Fatal(err)
	}
	has := func(node string) bool {
		for _, g := range got {
			if g == node {
				return true
			}
		}
		return false
	}
	if !has("runtime_event/ev-proc") {
		t.Errorf("truncated execve: expected match via process_observed sample, got %v", got)
	}
	if has("runtime_event/ev-other") {
		t.Errorf("unrelated process sample matched: %v", got)
	}
	if len(got) != 1 {
		t.Errorf("expected exactly one matched action (the setup.py process), got %v", got)
	}
}

func TestMaterializeLLMCalls(t *testing.T) {
	paths, err := store.Init(filepath.Join(t.TempDir(), ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := ObjectStore{DB: db, Paths: paths}
	const run = "run-llm"

	ins := func(id, etype, payload string) {
		if _, err := db.Exec(`INSERT INTO events (id, run_id, source, event_type, payload, created_at)
			VALUES (?, ?, 'agentprov_ebpf', ?, ?, '2026-01-01T00:00:01Z')`, id, run, etype, payload); err != nil {
			t.Fatal(err)
		}
	}
	ins("ev-req", "tls_write", `{"model":"claude-opus-4-8","content":"{\"model\":\"claude-opus-4-8\",\"messages\":[{\"role\":\"user\",\"content\":\"read creds\"}]}"}`)
	ins("ev-resp", "tls_read", `{"model":"claude-opus-4-8","content":"{\"model\":\"claude-opus-4-8\",\"content\":[{\"type\":\"tool_use\",\"name\":\"bash\"}]}"}`)
	// The ingest-time request->response pairing.
	if _, err := db.Exec(`INSERT INTO graph_edges (id, run_id, from_id, to_id, edge_type, created_at)
		VALUES ('e1', ?, 'runtime_event/ev-req', 'runtime_event/ev-resp', 'llm_call', '2026-01-01T00:00:02Z')`, run); err != nil {
		t.Fatal(err)
	}

	n, err := MaterializeLLMCalls(st, db, run)
	if err != nil {
		t.Fatalf("MaterializeLLMCalls: %v", err)
	}
	if n != 1 {
		t.Errorf("llm_call nodes = %d, want 1", n)
	}
	// Two bodies objectified as content-addressed evidence.
	var objs int
	db.QueryRow(`SELECT COUNT(*) FROM provenance_objects WHERE run_id=? AND object_type='llm_message'`, run).Scan(&objs)
	if objs != 2 {
		t.Errorf("llm_message objects = %d, want 2", objs)
	}
	// The llm_call node references both the request and the response body.
	var reqEdges, respEdges int
	db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id=? AND from_id='llm_call/ev-req' AND edge_type='llm_request'`, run).Scan(&reqEdges)
	db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id=? AND from_id='llm_call/ev-req' AND edge_type='llm_response'`, run).Scan(&respEdges)
	if reqEdges != 1 || respEdges != 1 {
		t.Errorf("llm_call edges: request=%d response=%d, want 1/1", reqEdges, respEdges)
	}
	// Each tls event links to its body object.
	var bodyEdges int
	db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id=? AND edge_type='llm_body'`, run).Scan(&bodyEdges)
	if bodyEdges != 2 {
		t.Errorf("llm_body edges = %d, want 2", bodyEdges)
	}

	// Direct link is exercised in TestMaterializeLLMCallsDirectLink.

	// Idempotent: a second pass must not duplicate objects or edges.
	if _, err := MaterializeLLMCalls(st, db, run); err != nil {
		t.Fatal(err)
	}
	db.QueryRow(`SELECT COUNT(*) FROM provenance_objects WHERE run_id=? AND object_type='llm_message'`, run).Scan(&objs)
	db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id=? AND edge_type='llm_body'`, run).Scan(&bodyEdges)
	if objs != 2 || bodyEdges != 2 {
		t.Errorf("after re-run: objects=%d body edges=%d, want 2/2 (idempotent)", objs, bodyEdges)
	}
}

func TestLLMMessageMeta(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "obj.json")
	if err := os.WriteFile(f, []byte(`{"type":"llm_message","payload":{"model":"claude-opus-4-8","semantics":{"tool_calls":["bash","read_file"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	meta := llmMessageMeta(f)
	if meta.Model != "claude-opus-4-8" || len(meta.ToolCalls) != 2 || meta.ToolCalls[0] != "bash" {
		t.Errorf("llmMessageMeta = %+v", meta)
	}
	// Missing file degrades quietly.
	if missing := llmMessageMeta(filepath.Join(dir, "nope.json")); missing.Model != "" || missing.ToolCalls != nil {
		t.Errorf("missing file should yield empty, got %+v", missing)
	}
}
