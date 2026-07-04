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
	ins("ev-resp", "tls_read", `{"content":"{\"model\":\"m\",\"stop_reason\":\"tool_use\",\"content\":[{\"type\":\"tool_use\",\"name\":\"bash\"}]}"}`)
	ins("ev-exec", "execve", `{"payload":{"raw":{"command":"cat creds"}}}`)
	edge := func(from, to, et string) {
		if _, err := db.Exec(`INSERT INTO graph_edges (id, run_id, from_id, to_id, edge_type, created_at)
			VALUES (?, ?, ?, ?, ?, '2026-01-01T00:00:02Z')`, ids.New("edge"), run, from, to, et); err != nil {
			t.Fatal(err)
		}
	}
	edge("runtime_event/ev-req", "runtime_event/ev-resp", "llm_call")
	edge("runtime_event/ev-resp", "runtime_event/ev-exec", "llm_intent_caused")

	if _, err := MaterializeLLMCalls(st, db, run); err != nil {
		t.Fatal(err)
	}
	var caused int
	db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id=? AND from_id='llm_call/ev-req' AND to_id='runtime_event/ev-exec' AND edge_type='llm_caused'`, run).Scan(&caused)
	if caused != 1 {
		t.Errorf("llm_caused edge llm_call -> execve = %d, want 1 (direct link)", caused)
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
	model, tools := llmMessageMeta(f)
	if model != "claude-opus-4-8" || len(tools) != 2 || tools[0] != "bash" {
		t.Errorf("llmMessageMeta = %q, %v", model, tools)
	}
	// Missing file degrades quietly.
	if m, tt := llmMessageMeta(filepath.Join(dir, "nope.json")); m != "" || tt != nil {
		t.Errorf("missing file should yield empty, got %q %v", m, tt)
	}
}
