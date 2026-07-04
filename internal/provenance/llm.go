package provenance

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/tlsintent"
)

// Graph edges wiring the model's actual traffic into the signed graph.
const (
	edgeLLMBody     = "llm_body"     // runtime_event(tls) -> the objectified body
	edgeLLMRequest  = "llm_request"  // llm_call -> request body object
	edgeLLMResponse = "llm_response" // llm_call -> response body object
	edgeLLMCaused   = "llm_caused"   // llm_call -> the syscall/action it caused
)

// MaterializeLLMCalls turns the captured LLM traffic into verifiable evidence:
// each reassembled tls_write/tls_read body (when full capture is on) is stored as
// a content-addressed `llm_message` object, and every paired request/response
// (from the ingest-time `llm_call` edge) becomes a first-class `llm_call` node
// that references the model's actual prompt and completion. Idempotent. Returns
// the number of llm_call nodes built.
func MaterializeLLMCalls(store ObjectStore, db *sql.DB, runID string) (int, error) {
	if runID == "" {
		return 0, fmt.Errorf("materialize llm calls: run id is required")
	}
	for _, q := range []string{
		`DELETE FROM graph_edges WHERE run_id = ? AND edge_type IN ('llm_body','llm_request','llm_response','llm_caused')`,
		`DELETE FROM provenance_objects WHERE run_id = ? AND object_type = 'llm_message'`,
	} {
		if _, err := db.Exec(q, runID); err != nil {
			return 0, fmt.Errorf("materialize llm calls: clear: %w", err)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)

	// Objectify each TLS body that carries full content.
	rows, err := db.Query(`SELECT id, event_type, COALESCE(payload,'')
		FROM events WHERE run_id = ? AND event_type IN ('tls_write','tls_read')`, runID)
	if err != nil {
		return 0, err
	}
	objByEvent := map[string]string{}
	type row struct{ id, etype, payload string }
	var evs []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.etype, &r.payload); err != nil {
			rows.Close()
			return 0, err
		}
		evs = append(evs, r)
	}
	rows.Close()
	for _, r := range evs {
		content, model := tlsBodyContent(r.payload)
		if content == "" {
			continue
		}
		dir, prefix := tlsintent.Request, "llm_request"
		if r.etype == "tls_read" {
			dir, prefix = tlsintent.Response, "llm_response"
		}
		sem := tlsintent.ParseSemantics(dir, []byte(content))
		if model == "" {
			model = sem.Model
		}
		res, err := store.PutExternalObject(ExternalObjectInput{
			Type:     "llm_message",
			SourceID: prefix + "/" + r.id,
			RunID:    runID,
			Payload:  map[string]any{"direction": dir, "model": model, "content": content, "semantics": sem},
		})
		if err != nil {
			return 0, fmt.Errorf("materialize llm calls: objectify %s: %w", r.id, err)
		}
		objByEvent[r.id] = res.Hash
		if err := insertLLMEdge(db, runID, "runtime_event/"+r.id, res.Hash, edgeLLMBody, r.id, now); err != nil {
			return 0, err
		}
	}

	// Build one llm_call node per paired request/response (the ingest-time pairing).
	pairs, err := db.Query(`SELECT from_id, to_id FROM graph_edges WHERE run_id = ? AND edge_type = 'llm_call'`, runID)
	if err != nil {
		return 0, err
	}
	type pair struct{ from, to string }
	var ps []pair
	for pairs.Next() {
		var p pair
		if err := pairs.Scan(&p.from, &p.to); err != nil {
			pairs.Close()
			return 0, err
		}
		ps = append(ps, p)
	}
	pairs.Close()
	n := 0
	for _, p := range ps {
		reqID := strings.TrimPrefix(p.from, "runtime_event/")
		respID := strings.TrimPrefix(p.to, "runtime_event/")
		reqObj, respObj := objByEvent[reqID], objByEvent[respID]
		if reqObj == "" && respObj == "" {
			continue
		}
		llmNode := "llm_call/" + reqID // deterministic: one llm_call per request
		if err := insertLLMEdge(db, runID, llmNode, reqObj, edgeLLMRequest, reqID, now); err != nil {
			return 0, err
		}
		if err := insertLLMEdge(db, runID, llmNode, respObj, edgeLLMResponse, respID, now); err != nil {
			return 0, err
		}
		// Direct link: connect the llm_call NODE to the syscalls/actions the
		// response caused (the ingest-time llm_intent_caused edges hang off the
		// tls_read event; lift them to the llm_call so the graph reads
		// "this model call decided -> caused this syscall").
		actions, err := causedActions(db, runID, respID)
		if err != nil {
			return 0, err
		}
		for _, actionNode := range actions {
			if err := insertLLMEdge(db, runID, llmNode, actionNode, edgeLLMCaused, respID, now); err != nil {
				return 0, err
			}
		}
		n++
	}
	return n, nil
}

// causedActions returns the action-event nodes that a response event's
// llm_intent_caused edges point to (collected before any write, to avoid the
// single-connection nested-cursor footgun).
func causedActions(db *sql.DB, runID, respEventID string) ([]string, error) {
	rows, err := db.Query(`SELECT to_id FROM graph_edges
		WHERE run_id = ? AND from_id = ? AND edge_type = 'llm_intent_caused'`,
		runID, "runtime_event/"+respEventID)
	if err != nil {
		return nil, fmt.Errorf("materialize llm calls: caused actions: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var to string
		if err := rows.Scan(&to); err != nil {
			return nil, err
		}
		out = append(out, to)
	}
	return out, rows.Err()
}

// insertLLMEdge writes one graph edge. An empty endpoint is a legitimate skip
// (e.g. a request with no captured response body) and returns nil; a real write
// failure is returned so MaterializeLLMCalls fails loudly rather than reporting
// success over a graph that is silently missing edges.
func insertLLMEdge(db *sql.DB, runID, from, to, edgeType, sourceEvent, now string) error {
	if from == "" || to == "" {
		return nil
	}
	if _, err := db.Exec(`INSERT INTO graph_edges (id, run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at)
		VALUES (?, ?, '', ?, ?, ?, ?, ?)`, ids.New("edge"), runID, from, to, edgeType, sourceEvent, now); err != nil {
		return fmt.Errorf("materialize llm calls: insert %s edge: %w", edgeType, err)
	}
	return nil
}

// tlsBodyContent extracts the full reassembled body + model from a tls event's
// payload. The body is present only when full TLS capture is enabled at ingest;
// otherwise the payload carries just a hash + preview and this returns "".
func tlsBodyContent(payload string) (content, model string) {
	var m map[string]any
	if json.Unmarshal([]byte(payload), &m) != nil {
		return "", ""
	}
	inner := m
	if p, ok := m["payload"].(map[string]any); ok { // envelope from the recorder
		inner = p
	}
	content, _ = inner["content"].(string)
	if content == "" {
		if raw, ok := inner["raw"].(map[string]any); ok {
			content, _ = raw["content"].(string)
		}
	}
	if s, ok := inner["model"].(string); ok {
		model = s
	}
	return content, model
}
