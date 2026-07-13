package provenance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"
)

// A capture proxy dump (rustls agent, endpoint-captured): a chat turn whose
// response declares NO tool call, plus a blocked codebase upload. IngestEndpointDump
// must yield an llm_call node and a blocked network_connect egress event carrying the
// payload evidence -- so the intent diff can flag "effect with no declared intent".
func TestIngestEndpointDump(t *testing.T) {
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
	const run = "run-ep"

	dump := t.TempDir()
	write := func(name string, meta map[string]any, body []byte) {
		raw, _ := json.Marshal(meta)
		if err := os.WriteFile(filepath.Join(dump, name+".meta.json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dump, name+".body.bin"), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("001_req__v1_chat_completions",
		map[string]any{"seq": 1, "kind": "req", "method": "POST", "path": "/v1/chat/completions"},
		[]byte(`{"messages":[{"role":"user","content":"reply one word"}]}`))
	write("002_resp__v1_chat_completions",
		map[string]any{"seq": 2, "kind": "resp", "method": "POST", "path": "/v1/chat/completions"},
		[]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`)) // no tool_calls
	write("003_EXFIL-REQ__v1_upload_storage_v1",
		map[string]any{"seq": 3, "kind": "EXFIL-REQ", "method": "POST", "path": "/v1/upload/storage/v1"},
		[]byte("# v2 git bundle\nPACK...whole repo including SECRET_DO_NOT_READ..."))

	res, err := IngestEndpointDump(st, db, run, dump)
	if err != nil {
		t.Fatal(err)
	}
	if res.LLMCalls != 1 || res.Egress != 1 || res.BlockedEgress != 1 {
		t.Fatalf("result = %+v, want 1 llm_call / 1 egress / 1 blocked", res)
	}

	var reqE, respE int
	db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id=? AND from_id='llm_call/ep-1' AND edge_type='llm_request'`, run).Scan(&reqE)
	db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id=? AND from_id='llm_call/ep-1' AND edge_type='llm_response'`, run).Scan(&respE)
	if reqE != 1 || respE != 1 {
		t.Errorf("llm_call edges: request=%d response=%d, want 1/1", reqE, respE)
	}

	// The blocked egress is a network_connect event (a real effect) marked blocked/deny.
	var egN int
	var payload string
	db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id=? AND source='endpoint_capture' AND event_type='network_connect'`, run).Scan(&egN)
	if egN != 1 {
		t.Fatalf("egress network_connect events = %d, want 1", egN)
	}
	db.QueryRow(`SELECT payload FROM events WHERE run_id=? AND source='endpoint_capture'`, run).Scan(&payload)
	for _, want := range []string{`"blocked":true`, `"policy_decision":"deny"`, `"is_git_bundle":true`} {
		if !contains(payload, want) {
			t.Errorf("egress payload missing %s: %s", want, payload)
		}
	}

	// The payload evidence object was objectified.
	var objs int
	db.QueryRow(`SELECT COUNT(*) FROM provenance_objects WHERE run_id=? AND object_type='egress_payload'`, run).Scan(&objs)
	if objs != 1 {
		t.Errorf("egress_payload objects = %d, want 1", objs)
	}

	// Idempotent: a second pass must not duplicate.
	if _, err := IngestEndpointDump(st, db, run, dump); err != nil {
		t.Fatal(err)
	}
	db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id=? AND source='endpoint_capture'`, run).Scan(&egN)
	if egN != 1 {
		t.Errorf("after re-run: egress events = %d, want 1 (idempotent)", egN)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
