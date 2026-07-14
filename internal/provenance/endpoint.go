package provenance

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
)

// EndpointResult summarizes an endpoint-dump ingestion.
type EndpointResult struct {
	LLMCalls      int `json:"llm_calls"`
	Egress        int `json:"egress"`
	BlockedEgress int `json:"blocked_egress"`
}

// endpointMeta is one record the capture proxy wrote for a request or response.
// (proxy writes <seq>_<kind>_<path>.{meta.json,body.bin}; kind is req|resp|EXFIL-REQ.)
type endpointMeta struct {
	Seq         int      `json:"seq"`
	Kind        string   `json:"kind"`
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	Size        int      `json:"size"`
	CanaryHits  []string `json:"canary_hits"`   // canary strings the proxy matched in this body
	IsGitBundle bool     `json:"is_git_bundle"` // proxy-detected git-bundle marker
	base        string   // path without .meta.json (to find the sibling .body.bin)
}

// IngestEndpointDump folds a capture proxy's dump into the run graph for agents
// whose TLS the libssl uprobe can't read (e.g. rustls CLIs like Grok): the model
// traffic and the data egress are captured at the controlled endpoint instead.
//
//   - /chat/completions + /responses  -> an llm_call node (the model turn); the
//     response is inspected for tool_calls so the graph can assert the model
//     "declared" nothing but text.
//   - /v1/upload/storage + /v1/traces -> a network_connect egress EVENT (so the
//     intent diff sees an effect with no declared intent) plus a content-addressed
//     descriptor of the payload (a git bundle of the repo) as evidence. A blocked
//     upload is marked blocked/deny so the enforcement shows in the graph.
func IngestEndpointDump(store ObjectStore, db *sql.DB, runID, dumpDir string) (EndpointResult, error) {
	var res EndpointResult
	if runID == "" {
		return res, fmt.Errorf("ingest endpoint: run id is required")
	}
	metaPaths, err := filepath.Glob(filepath.Join(dumpDir, "*.meta.json"))
	if err != nil {
		return res, err
	}
	var metas []endpointMeta
	for _, mp := range metaPaths {
		raw, err := os.ReadFile(mp)
		if err != nil {
			return res, err
		}
		var m endpointMeta
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		m.base = strings.TrimSuffix(mp, ".meta.json")
		metas = append(metas, m)
	}
	sort.Slice(metas, func(i, j int) bool { return metas[i].Seq < metas[j].Seq })

	// Idempotent: clear prior endpoint-sourced objects/edges/events for the run.
	if _, err := db.Exec(`DELETE FROM provenance_objects WHERE run_id = ? AND source_id LIKE 'endpoint/%'`, runID); err != nil {
		return res, err
	}
	if _, err := db.Exec(`DELETE FROM graph_edges WHERE run_id = ? AND from_id LIKE 'llm_call/ep-%'`, runID); err != nil {
		return res, err
	}
	if _, err := db.Exec(`DELETE FROM events WHERE run_id = ? AND source = 'endpoint_capture'`, runID); err != nil {
		return res, err
	}

	// Index responses by path so a chat request can find its response body.
	respByPath := map[string]endpointMeta{}
	for _, m := range metas {
		if m.Kind == "resp" {
			respByPath[m.Path] = m
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)

	for _, m := range metas {
		body := readBody(m.base)
		switch {
		case m.Kind == "req" && isEndpointChat(m.Path):
			respBody := readBody(respByPath[m.Path].base)
			if err := ingestChatCall(store, db, runID, m, body, respBody, now); err != nil {
				return res, err
			}
			res.LLMCalls++
		case isEndpointEgress(m.Path) && m.Kind != "resp":
			blocked := m.Kind == "EXFIL-REQ" || m.Kind == "exfil-req"
			if err := ingestEgress(store, db, runID, m, body, blocked, now); err != nil {
				return res, err
			}
			res.Egress++
			if blocked {
				res.BlockedEgress++
			}
		}
	}
	return res, nil
}

func readBody(base string) []byte {
	b, err := os.ReadFile(base + ".body.bin")
	if err != nil {
		return nil
	}
	return b
}

func isEndpointChat(path string) bool {
	p := strings.ToLower(path)
	return strings.Contains(p, "chat/completions") || strings.Contains(p, "/responses") || strings.Contains(p, "/messages")
}

func isEndpointEgress(path string) bool {
	p := strings.ToLower(path)
	return strings.Contains(p, "/upload/storage") || strings.Contains(p, "/upload") || strings.Contains(p, "/traces")
}

// ingestChatCall objectifies the request + response bodies and builds an llm_call
// node, recording whether the model declared any tool call.
func ingestChatCall(store ObjectStore, db *sql.DB, runID string, m endpointMeta, reqBody, respBody []byte, now string) error {
	declaredTools := responseDeclaresToolCall(respBody)
	reqObj, err := store.PutExternalObject(ExternalObjectInput{
		Type: "llm_message", SourceID: fmt.Sprintf("endpoint/req-%d", m.Seq), RunID: runID,
		Payload: map[string]any{"direction": "request", "content": string(reqBody),
			"semantics": map[string]any{"path": m.Path, "source": "endpoint_capture"}},
	})
	if err != nil {
		return fmt.Errorf("ingest endpoint: request object: %w", err)
	}
	respObj, err := store.PutExternalObject(ExternalObjectInput{
		Type: "llm_message", SourceID: fmt.Sprintf("endpoint/resp-%d", m.Seq), RunID: runID,
		Payload: map[string]any{"direction": "response", "content": string(respBody),
			"semantics": map[string]any{"path": m.Path, "declared_tool_call": declaredTools, "source": "endpoint_capture"}},
	})
	if err != nil {
		return fmt.Errorf("ingest endpoint: response object: %w", err)
	}
	node := fmt.Sprintf("llm_call/ep-%d", m.Seq)
	if err := insertLLMEdge(db, runID, node, reqObj.Hash, edgeLLMRequest, "", now); err != nil {
		return err
	}
	return insertLLMEdge(db, runID, node, respObj.Hash, edgeLLMResponse, "", now)
}

// ingestEgress records a data-egress upload as a network_connect event (so the
// intent diff sees an effect) plus a content-addressed descriptor of the payload.
func ingestEgress(store ObjectStore, db *sql.DB, runID string, m endpointMeta, body []byte, blocked bool, now string) error {
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	// Prefer the proxy's own detection (it saw the whole body); fall back to
	// scanning the (possibly chunked) body here.
	isBundle := m.IsGitBundle || bytes.Contains(body, []byte("git bundle")) ||
		(len(body) >= 4 && bytes.HasPrefix(body, []byte("PACK")))
	// canary_hits is the proof of WHICH do-not-read files entered the (blocked)
	// upload -- the demo's smoking gun, now a first-class field on the egress node.
	canaries := m.CanaryHits
	fields := map[string]any{
		"kind": "egress_payload", "path": m.Path, "bytes": len(body),
		"payload_sha256": digest, "is_git_bundle": isBundle, "canary_hits": canaries,
		"blocked": blocked, "policy_decision": ternary(blocked, "deny", "observe"),
	}
	obj, err := store.PutExternalObject(ExternalObjectInput{
		Type: "egress_payload", SourceID: fmt.Sprintf("endpoint/egress-%d", m.Seq), RunID: runID,
		Payload: fields,
	})
	if err != nil {
		return fmt.Errorf("ingest endpoint: egress object: %w", err)
	}
	// A network_connect event so intent.classifyEvent sees a real network effect
	// with no declared intent (the codebase left the box, or was blocked leaving).
	eventID := ids.New("evt")
	payload, _ := json.Marshal(map[string]any{
		"dst_host": "grok-code-session-traces", "path": m.Path, "bytes": len(body),
		"payload_sha256": digest, "is_git_bundle": isBundle, "canary_hits": canaries,
		"blocked": blocked, "policy_decision": ternary(blocked, "deny", "observe"),
	})
	if _, err := db.Exec(`INSERT INTO events (id, run_id, source, event_type, payload, created_at)
		VALUES (?, ?, 'endpoint_capture', 'network_connect', ?, ?)`, eventID, runID, string(payload), now); err != nil {
		return err
	}
	// Link the egress event node to the payload evidence object.
	return insertLLMEdge(db, runID, "runtime_event/"+eventID, obj.Hash, "endpoint_egress_payload", eventID, now)
}

// responseDeclaresToolCall reports whether the model's response (JSON or SSE)
// contains any tool call. Absence is the point: the model "declared" only text.
func responseDeclaresToolCall(body []byte) bool {
	s := string(body)
	return strings.Contains(s, "\"tool_calls\"") || strings.Contains(s, "\"tool_use\"") ||
		strings.Contains(s, "\"function_call\"") || strings.Contains(s, "\"tool_call\"")
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
