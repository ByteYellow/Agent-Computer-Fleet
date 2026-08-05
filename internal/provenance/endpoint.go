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
	"github.com/byteyellow/agentprovenance/internal/security"
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
	Host        string   `json:"host"` // upstream host the proxy forwarded this request to
	Size        int      `json:"size"`
	CanaryHits  []string `json:"canary_hits"`   // canary strings the proxy matched in this body
	IsGitBundle bool     `json:"is_git_bundle"` // proxy-detected git-bundle marker
	base        string   // path without .meta.json (to find the sibling .body.bin)
}

// endpointDstHost is the destination the capture recorded for a request. It comes
// from the proxy (which knows the upstream it forwarded to) — never hardcoded per
// demo — and falls back to "unknown-endpoint" only when an older dump omitted it.
func endpointDstHost(m endpointMeta) string {
	if h := strings.TrimSpace(m.Host); h != "" {
		return h
	}
	return "unknown-endpoint"
}

type endpointPayloadClass struct {
	Kind          string
	Sensitive     bool
	Codebase      bool
	CanaryPaths   []string
	UploadFailure string
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
	// Clear the deny chain (policy_decision -> risk_signal -> response_action ->
	// unified signal + edges) a prior ingest attached to the endpoint egress
	// events, keyed on those events so only THIS layer is removed (not the gate's).
	// Runs before the events are deleted so the subqueries can still see them.
	const epEvents = `(SELECT id FROM events WHERE run_id = ? AND source = 'endpoint_capture')`
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`DELETE FROM graph_edges WHERE run_id = ? AND edge_type IN ('runtime_event_policy_decision','policy_decision_risk_signal','risk_signal_response_action','policy_decision_session') AND source_event_id IN ` + epEvents, []any{runID, runID}},
		{`DELETE FROM signals WHERE run_id = ? AND source_table = 'risk_signals' AND event_id IN ` + epEvents, []any{runID, runID}},
		{`DELETE FROM response_actions WHERE run_id = ? AND policy_decision_id IN (SELECT id FROM policy_decisions WHERE run_id = ? AND event_id IN ` + epEvents + `)`, []any{runID, runID, runID}},
		{`DELETE FROM risk_signals WHERE run_id = ? AND event_id IN ` + epEvents, []any{runID, runID}},
		{`DELETE FROM policy_decisions WHERE run_id = ? AND event_id IN ` + epEvents, []any{runID, runID}},
	} {
		if _, err := db.Exec(stmt.sql, stmt.args...); err != nil {
			return res, err
		}
	}
	if _, err := db.Exec(`DELETE FROM graph_edges WHERE run_id = ? AND source_event_id IN `+epEvents, runID, runID); err != nil {
		return res, err
	}
	if _, err := db.Exec(`DELETE FROM events WHERE run_id = ? AND source = 'endpoint_capture'`, runID); err != nil {
		return res, err
	}

	chatResponses := pairEndpointChatResponses(metas)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	// Attribute the egress to the SAME session/process the kernel saw reading the
	// files, so the exfil renders as one chain with the rest of the run's activity.
	sessionID, processID := runSessionProcess(db, runID)
	toolCallID := runToolCall(db, runID, processID)
	chatCalls := endpointChatCalls(metas)

	for _, m := range metas {
		body := readBody(m.base)
		switch {
		case m.Kind == "req" && isEndpointChat(m.Path):
			respBody := readBody(chatResponses[m.Seq].base)
			if err := ingestChatCall(store, db, runID, m, body, respBody, !isAuxiliaryChat(body), now); err != nil {
				return res, err
			}
			res.LLMCalls++
		case isEndpointEgress(m.Path) && m.Kind != "resp":
			transportBlocked := m.Kind == "EXFIL-REQ" || m.Kind == "exfil-req"
			class := classifyEndpointPayload(m.Path, body, m.CanaryHits, m.IsGitBundle)
			blocked := transportBlocked && class.Sensitive
			if err := ingestEgress(store, db, runID, m, body, blocked, sessionID, processID, toolCallID, nearestChatCall(m.Seq, chatCalls), now); err != nil {
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

func pairEndpointChatResponses(metas []endpointMeta) map[int]endpointMeta {
	requests := map[string][]endpointMeta{}
	responses := map[string][]endpointMeta{}
	for _, m := range metas {
		if !isEndpointChat(m.Path) {
			continue
		}
		if m.Kind == "req" {
			requests[m.Path] = append(requests[m.Path], m)
		} else if m.Kind == "resp" {
			responses[m.Path] = append(responses[m.Path], m)
		}
	}
	out := map[int]endpointMeta{}
	for path, reqs := range requests {
		resps := responses[path]
		for i, req := range reqs {
			if i < len(resps) {
				out[req.Seq] = resps[i]
			}
		}
	}
	return out
}

func isAuxiliaryChat(body []byte) bool {
	s := strings.ToLower(string(body))
	return strings.Contains(s, "generating the session title") || strings.Contains(s, `"name":"session_title"`)
}

func endpointChatCalls(metas []endpointMeta) map[int]string {
	out := map[int]string{}
	for _, m := range metas {
		if m.Kind == "req" && isEndpointChat(m.Path) {
			out[m.Seq] = fmt.Sprintf("llm_call/ep-%d", m.Seq)
		}
	}
	return out
}

func nearestChatCall(seq int, calls map[int]string) string {
	bestSeq, bestDist := 0, int(^uint(0)>>1)
	for candidate := range calls {
		d := candidate - seq
		if d < 0 {
			d = -d
		}
		if d < bestDist || (d == bestDist && candidate < bestSeq) {
			bestSeq, bestDist = candidate, d
		}
	}
	return calls[bestSeq]
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
	p := strings.ToLower(strings.Split(path, "?")[0])
	if strings.HasSuffix(p, "/storage/batch_exists") {
		return false
	}
	return p == "/storage" || p == "/traces" || strings.Contains(p, "/upload/storage") || strings.Contains(p, "/upload")
}

func classifyEndpointPayload(path string, body []byte, canaries []string, isBundle bool) endpointPayloadClass {
	p := strings.ToLower(strings.Split(path, "?")[0])
	c := endpointPayloadClass{Kind: "vendor_storage"}
	if strings.Contains(p, "/traces") {
		c.Kind = "trace"
	}
	if isBundle {
		c.Kind, c.Sensitive, c.Codebase = "codebase_archive", true, true
	}
	var value any
	if json.Unmarshal(body, &value) != nil {
		if len(canaries) > 0 {
			c.Kind, c.Sensitive = "sensitive_payload", true
		}
		return c
	}
	if obj, ok := value.(map[string]any); ok {
		switch {
		case obj["artifacts"] != nil && obj["upload_method"] != nil:
			c.Kind = "upload_manifest"
			if artifacts, ok := obj["artifacts"].(map[string]any); ok {
				if state, ok := artifacts["after_codebase.tar.gz"].(string); ok {
					if state == "enqueued" || state == "uploaded" || state == "complete" {
						c.Codebase, c.Sensitive = true, true
					} else if state != "" {
						c.UploadFailure = state
					}
				}
			}
		case obj["files"] != nil:
			c.Kind = "config_files"
			c.CanaryPaths = pathsContainingCanaries(obj["files"], canaries)
		case obj["messages"] != nil:
			c.Kind = "turn_messages"
		case obj["request_id"] != nil && obj["stop_reason"] != nil:
			c.Kind = "turn_result"
		case obj["repo_root"] != nil && obj["prompt"] != nil:
			c.Kind = "turn_metadata"
		case obj["features"] != nil && obj["toolset"] != nil:
			c.Kind = "runtime_config"
		}
	} else if list, ok := value.([]any); ok && len(list) > 0 {
		if first, ok := list[0].(map[string]any); ok && first["function"] != nil {
			c.Kind = "tool_definitions"
		}
	}
	if len(canaries) > 0 {
		c.Sensitive = true
		if c.Kind == "vendor_storage" {
			c.Kind = "sensitive_payload"
		}
	}
	return c
}

func pathsContainingCanaries(files any, canaries []string) []string {
	if len(canaries) == 0 {
		return nil
	}
	rows, ok := files.([]any)
	if !ok {
		return nil
	}
	var paths []string
	for _, row := range rows {
		obj, ok := row.(map[string]any)
		if !ok {
			continue
		}
		raw, _ := json.Marshal(obj["content"])
		for _, canary := range canaries {
			if canary != "" && bytes.Contains(raw, []byte(canary)) {
				if path, _ := obj["path"].(string); path != "" {
					paths = append(paths, path)
				}
				break
			}
		}
	}
	sort.Strings(paths)
	return paths
}

// ingestChatCall objectifies the request + response bodies and builds an llm_call
// node, recording whether the model declared any tool call.
func ingestChatCall(store ObjectStore, db *sql.DB, runID string, m endpointMeta, reqBody, respBody []byte, primary bool, now string) error {
	declaredTools := responseDeclaresToolCall(respBody)
	host := strings.TrimSpace(m.Host)
	// Sensitive markers the capture layer matched in the request body (the demo's
	// canaries stand in for a secret scanner): their presence means secrets reached
	// the model's context — the model_context_egress surface.
	reqObj, err := store.PutExternalObject(ExternalObjectInput{
		Type: "llm_message", SourceID: fmt.Sprintf("endpoint/req-%d", m.Seq), RunID: runID,
		Payload: map[string]any{"direction": "request", "content": string(reqBody),
			"semantics": map[string]any{"path": m.Path, "host": host, "source": "endpoint_capture", "intent_role": ternary(primary, "primary", "auxiliary"), "canary_hits": m.CanaryHits}},
	})
	if err != nil {
		return fmt.Errorf("ingest endpoint: request object: %w", err)
	}
	respObj, err := store.PutExternalObject(ExternalObjectInput{
		Type: "llm_message", SourceID: fmt.Sprintf("endpoint/resp-%d", m.Seq), RunID: runID,
		Payload: map[string]any{"direction": "response", "content": string(respBody),
			"semantics": map[string]any{"path": m.Path, "host": host, "declared_tool_call": declaredTools, "source": "endpoint_capture", "intent_role": ternary(primary, "primary", "auxiliary")}},
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
func ingestEgress(store ObjectStore, db *sql.DB, runID string, m endpointMeta, body []byte, blocked bool, sessionID, processID, toolCallID, llmCallID, now string) error {
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	// Prefer the proxy's own detection (it saw the whole body); fall back to
	// scanning the (possibly chunked) body here.
	isBundle := m.IsGitBundle || bytes.Contains(body, []byte("git bundle")) ||
		(len(body) >= 4 && bytes.HasPrefix(body, []byte("PACK")))
	// canary_hits is the proof of WHICH do-not-read files entered the (blocked)
	// upload -- the demo's smoking gun, now a first-class field on the egress node.
	canaries := m.CanaryHits
	class := classifyEndpointPayload(m.Path, body, canaries, isBundle)
	fields := map[string]any{
		"kind": "egress_payload", "egress_kind": class.Kind, "path": m.Path, "bytes": len(body),
		"payload_sha256": digest, "is_git_bundle": isBundle, "canary_hits": canaries,
		"canary_paths": class.CanaryPaths, "codebase_payload": class.Codebase,
		"upload_failure": class.UploadFailure, "blocked": blocked,
		"policy_decision": ternary(blocked && class.Sensitive, "deny", "observe"),
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
		"dst_host": endpointDstHost(m), "path": m.Path, "bytes": len(body),
		"payload_sha256": digest, "is_git_bundle": isBundle, "canary_hits": canaries,
		"canary_paths": class.CanaryPaths, "egress_kind": class.Kind, "codebase_payload": class.Codebase,
		"upload_failure": class.UploadFailure, "blocked": blocked,
		"policy_decision": ternary(blocked && class.Sensitive, "deny", "observe"),
	})
	// Attribute the egress to grok's session/process so it joins the same chain as
	// the kernel's reads of those files.
	if _, err := db.Exec(`INSERT INTO events (id, run_id, session_id, process_id, tool_call_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, ?, ?, 'endpoint_capture', 'network_connect', ?, ?)`, eventID, runID, sessionID, processID, toolCallID, string(payload), now); err != nil {
		return err
	}
	// Link the egress event node to the payload evidence object.
	if err := insertLLMEdge(db, runID, "runtime_event/"+eventID, obj.Hash, "endpoint_egress_payload", eventID, now); err != nil {
		return err
	}
	if blocked && llmCallID != "" {
		if err := insertLLMEdge(db, runID, llmCallID, "runtime_event/"+eventID, "llm_caused", eventID, now); err != nil {
			return err
		}
	}
	if err := linkCanarySources(db, runID, eventID, obj.Hash, class.CanaryPaths, now); err != nil {
		return err
	}
	// A blocked codebase upload becomes a first-class deny in the risk -> response
	// chain (the same one the gate uses), so the dashboard headlines "codebase
	// exfiltration -> BLOCKED" alongside the secret-read signals -- one chain.
	if blocked && class.Sensitive {
		ruleID := "sensitive_context_egress_block"
		what := class.Kind
		if class.Codebase {
			ruleID, what = "codebase_egress_block", "codebase payload"
		}
		reason := fmt.Sprintf("BLOCKED: agent attempted to upload %d bytes of %s to %s (%s)", len(body), what, endpointDstHost(m), m.Path)
		if _, err := security.PersistDenyForEvent(db, eventID, ruleID, reason); err != nil {
			return fmt.Errorf("ingest endpoint: egress deny chain: %w", err)
		}
	}
	return nil
}

func linkCanarySources(db *sql.DB, runID, sinkEventID, objectHash string, paths []string, now string) error {
	for _, path := range paths {
		fileNode := "workspace_file/" + path
		for _, edge := range []struct{ from, to, kind string }{
			{fileNode, objectHash, "sensitive_source_payload"},
			{objectHash, "runtime_event/" + sinkEventID, "payload_egress_attempt"},
		} {
			if err := insertLLMEdge(db, runID, edge.from, edge.to, edge.kind, sinkEventID, now); err != nil {
				return err
			}
		}
		var sourceEventID string
		like := "%" + path + "%"
		_ = db.QueryRow(`SELECT id FROM events WHERE run_id = ? AND event_type IN ('secret_path','file_open','openat')
			AND payload LIKE ? ORDER BY created_at DESC LIMIT 1`, runID, like).Scan(&sourceEventID)
		if sourceEventID != "" {
			for _, edge := range []struct{ from, to, kind string }{
				{"runtime_event/" + sourceEventID, objectHash, "sensitive_source_payload"},
				{"runtime_event/" + sourceEventID, "runtime_event/" + sinkEventID, "confirmed_sensitive_data_flow"},
			} {
				if err := insertLLMEdge(db, runID, edge.from, edge.to, edge.kind, sinkEventID, now); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// runSessionProcess returns the session and process the run's activity is under,
// preferring the process the kernel saw reading a secret path (so the egress
// attaches to the same node as the reads), falling back to any of the run's.
func runSessionProcess(db *sql.DB, runID string) (sessionID, processID string) {
	_ = db.QueryRow(`SELECT COALESCE(process_id,''), COALESCE(session_id,'') FROM events
		WHERE run_id = ? AND event_type = 'secret_path' AND COALESCE(process_id,'') != '' LIMIT 1`, runID).Scan(&processID, &sessionID)
	if sessionID == "" {
		_ = db.QueryRow(`SELECT p.id, p.session_id FROM processes p JOIN sessions s ON p.session_id = s.id
			WHERE s.run_id = ? ORDER BY p.started_at LIMIT 1`, runID).Scan(&processID, &sessionID)
	}
	if sessionID == "" {
		_ = db.QueryRow(`SELECT id FROM sessions WHERE run_id = ? LIMIT 1`, runID).Scan(&sessionID)
	}
	return sessionID, processID
}

func runToolCall(db *sql.DB, runID, processID string) string {
	var toolCallID string
	if processID != "" {
		_ = db.QueryRow(`SELECT tool_call_id FROM processes WHERE id = ?`, processID).Scan(&toolCallID)
	}
	if toolCallID == "" {
		_ = db.QueryRow(`SELECT id FROM tool_calls WHERE run_id = ? ORDER BY started_at LIMIT 1`, runID).Scan(&toolCallID)
	}
	return toolCallID
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
