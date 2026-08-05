package provenance

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"
)

// A command decided by a sub-agent lives in the sub-agent's OWN transcript, not
// the main session transcript. HarvestTranscriptSet must harvest both, so the
// delegate's decided command becomes an llm_call and carries an llm_caused edge
// to the syscall that ran it -- the multi-agent half of the demo llm_caused=0 gap.
func TestHarvestTranscriptSetLinksSubAgentDecision(t *testing.T) {
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
	const run = "run-sub"

	ins := func(id, etype, payload string) {
		if _, err := db.Exec(`INSERT INTO events (id, run_id, source, event_type, payload, created_at)
			VALUES (?, ?, 'agentprov_ebpf', ?, ?, '2026-01-01T00:00:01Z')`, id, run, etype, payload); err != nil {
			t.Fatal(err)
		}
	}
	// The syscall the delegate's command actually ran, plus an unrelated one.
	ins("ev-setup", "execve", `{"payload":{"raw":{"command":"python3 ../pysnake-helper/setup.py install"}}}`)
	ins("ev-other", "execve", `{"payload":{"raw":{"command":"ls -la /tmp/build"}}}`)

	// Real Claude Code transcript shape. The MAIN agent only delegates (its Bash
	// does not match the setup execve); BOB, a sub-agent, decides the setup command.
	dir := t.TempDir()
	mainPath := filepath.Join(dir, "main.jsonl")
	subPath := filepath.Join(dir, "sub.jsonl")
	mustWrite(t, mainPath, `{"type":"user","message":{"role":"user","content":"Coordinate alice and bob to set the project up."}}
{"type":"assistant","message":{"role":"assistant","model":"deepseek-v4-pro","stop_reason":"tool_use","content":[{"type":"thinking","thinking":"Delegating to the team."},{"type":"tool_use","name":"Bash","input":{"command":"git status --short"}}]}}
`)
	mustWrite(t, subPath, `{"type":"user","message":{"role":"user","content":"Run the setup command alice relayed."}}
{"type":"assistant","message":{"role":"assistant","model":"deepseek-v4-pro","stop_reason":"tool_use","content":[{"type":"thinking","thinking":"Running the setup as instructed."},{"type":"tool_use","name":"Bash","input":{"command":"python3 ../pysnake-helper/setup.py install"}}]}}
`)

	subs := []AgentTranscript{{AgentID: "bob123abc", Path: subPath}}
	if _, err := HarvestTranscriptSet(st, db, run, mainPath, subs); err != nil {
		t.Fatal(err)
	}

	// The delegate's decided command links to the exact execve, and nothing links
	// to the unrelated one -- command-match stays precise.
	var subCaused, otherCaused int
	db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id=? AND edge_type='llm_caused'
		AND to_id='runtime_event/ev-setup' AND from_id LIKE 'llm_call/tr-bob123abc-%'`, run).Scan(&subCaused)
	db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id=? AND edge_type='llm_caused'
		AND to_id='runtime_event/ev-other'`, run).Scan(&otherCaused)
	if subCaused != 1 {
		t.Errorf("sub-agent decision -> setup execve llm_caused = %d, want 1", subCaused)
	}
	if otherCaused != 0 {
		t.Errorf("unrelated execve got %d llm_caused edges, want 0", otherCaused)
	}

	// The main transcript was still harvested (its own llm_call node exists) but
	// contributed no llm_caused edge -- its command matched nothing.
	var mainReq, totalCaused int
	db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id=? AND edge_type='llm_request' AND from_id='llm_call/tr-0'`, run).Scan(&mainReq)
	db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id=? AND edge_type='llm_caused'`, run).Scan(&totalCaused)
	if mainReq != 1 {
		t.Errorf("main transcript llm_call not harvested: llm_request from llm_call/tr-0 = %d, want 1", mainReq)
	}
	if totalCaused != 1 {
		t.Errorf("total llm_caused = %d, want 1 (only the sub-agent's command matched)", totalCaused)
	}

	// Idempotent: a second pass must not duplicate objects or edges.
	if _, err := HarvestTranscriptSet(st, db, run, mainPath, subs); err != nil {
		t.Fatal(err)
	}
	var objs, causedAfter int
	db.QueryRow(`SELECT COUNT(*) FROM provenance_objects WHERE run_id=? AND object_type='llm_message'`, run).Scan(&objs)
	db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id=? AND edge_type='llm_caused'`, run).Scan(&causedAfter)
	if objs != 4 || causedAfter != 1 {
		t.Errorf("after re-run: llm_message objects=%d (want 4) llm_caused=%d (want 1) -- not idempotent", objs, causedAfter)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
