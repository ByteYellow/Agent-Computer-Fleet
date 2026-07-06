package provenance

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

func graphLensNodes(db *sql.DB, runID string) (map[string]GraphLensNode, map[string]lensEvent, error) {
	nodes := map[string]GraphLensNode{}
	events := map[string]lensEvent{}
	add := func(node GraphLensNode) {
		if node.ID != "" {
			nodes[node.ID] = node
		}
	}
	rows, err := db.Query(`SELECT id, COALESCE(session_id,''), COALESCE(tool_call_id,''), COALESCE(process_id,''), COALESCE(snapshot_id,''), COALESCE(pid,0), COALESCE(ppid,0), COALESCE(tgid,0), source, event_type, payload, created_at
		FROM events WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ev lensEvent
		if err := rows.Scan(&ev.ID, &ev.SessionID, &ev.ToolCallID, &ev.ProcessID, &ev.SnapshotID, &ev.PID, &ev.PPID, &ev.TGID, &ev.Source, &ev.Type, &ev.Payload, &ev.CreatedAt); err != nil {
			return nil, nil, err
		}
		ev.NodeID = "runtime_event/" + ev.ID
		ev.Path = payloadString(ev.Payload, "path", "file")
		ev.Destination = payloadString(ev.Payload, "host", "dst_ip", "dst", "destination")
		events[ev.NodeID] = ev
		add(GraphLensNode{
			ID:      ev.NodeID,
			Kind:    "runtime_event",
			Subtype: ev.Type,
			Label:   lensEventLabel(ev),
			Risk:    riskForLensEvent(ev),
			Data: map[string]any{
				"event_id": ev.ID, "source": ev.Source, "pid": ev.PID, "ppid": ev.PPID,
				"process_id": ev.ProcessID, "tool_call_id": ev.ToolCallID, "path": ev.Path, "destination": ev.Destination,
				"created_at": ev.CreatedAt,
			},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	if err := addToolCallNodes(db, runID, add); err != nil {
		return nil, nil, err
	}
	if err := addAgentNodes(db, runID, add); err != nil {
		return nil, nil, err
	}
	if err := addIntentDiffNodes(db, runID, add); err != nil {
		return nil, nil, err
	}
	if err := addProcessNodes(db, runID, add); err != nil {
		return nil, nil, err
	}
	if err := addPolicyNodes(db, runID, add); err != nil {
		return nil, nil, err
	}
	if err := addSnapshotAttemptNodes(db, runID, add); err != nil {
		return nil, nil, err
	}
	if err := addProvenanceObjectNodes(db, runID, add); err != nil {
		return nil, nil, err
	}
	// runtime_process/pid/<pid> nodes are referenced by edges but otherwise carry
	// only the bare pid. Enrich them with the command from the matching execve
	// event so the graph shows the process NAME and the pid together (label =
	// command, subtitle = pid) instead of an opaque number.
	pidCommand := map[int64]string{}
	// execve is authoritative (the real exec). Then process_observed (the record
	// ps-sampler) fills in pids whose execve wasn't captured — e.g. processes that
	// were already running when the sensor attached — so the graph shows a name
	// instead of a bare pid.
	for _, ev := range events {
		if ev.Type == "execve" && ev.PID > 0 {
			if cmd := payloadString(ev.Payload, "command", "cmdline", "comm"); cmd != "" {
				pidCommand[ev.PID] = cmd
			}
		}
	}
	for _, ev := range events {
		if ev.Type == "process_observed" && ev.PID > 0 {
			if _, named := pidCommand[ev.PID]; named {
				continue
			}
			if cmd := payloadString(ev.Payload, "command", "cmdline", "comm"); cmd != "" {
				pidCommand[ev.PID] = cmd
			}
		}
	}
	// Final fallback: a pid still unnamed but seen in ANY other event (connect,
	// file, exit, ...) carries the comm the sensor stamps on every event. A real
	// agent spawns many short-lived children whose execve is missed (exec'd
	// before the sensor attached, or dropped under load) yet still do I/O — use
	// their comm so the graph shows "bash"/"claude"/"git" instead of a bare pid.
	// tgidName maps a thread-group id to a process name, so runtime_process/tgid/N
	// nodes (created from runtime_process_thread edges) show a name instead of a
	// bare number. Prefer the leader thread (pid==tgid); otherwise any thread's
	// comm/command.
	tgidName := map[int64]string{}
	for _, ev := range events {
		if ev.PID <= 0 {
			continue
		}
		name := payloadString(ev.Payload, "command", "cmdline", "comm")
		if name == "" {
			continue
		}
		if _, named := pidCommand[ev.PID]; !named {
			pidCommand[ev.PID] = name
		}
		if ev.TGID > 0 {
			if _, ok := tgidName[ev.TGID]; !ok || ev.PID == ev.TGID {
				tgidName[ev.TGID] = name
			}
		}
	}
	for pid, cmd := range pidCommand {
		id := fmt.Sprintf("runtime_process/pid/%d", pid)
		add(GraphLensNode{
			ID:          id,
			Kind:        "runtime_process",
			Subtype:     fmt.Sprintf("pid %d", pid),
			Label:       cmd,
			TrustOrigin: "runtime_observed",
			Data:        map[string]any{"pid": pid, "command": cmd},
		})
	}
	for tgid, name := range tgidName {
		id := fmt.Sprintf("runtime_process/tgid/%d", tgid)
		add(GraphLensNode{
			ID:          id,
			Kind:        "runtime_process",
			Subtype:     fmt.Sprintf("tgid %d (thread group)", tgid),
			Label:       name,
			TrustOrigin: "runtime_observed",
			Data:        map[string]any{"tgid": tgid, "command": name},
		})
	}
	return nodes, events, nil
}

func addToolCallNodes(db *sql.DB, runID string, add func(GraphLensNode)) error {
	rows, err := db.Query(`SELECT id, COALESCE(attempt_id,''), COALESCE(command,''), COALESCE(status,''), COALESCE(result_ref,''), COALESCE(policy_decision,''), COALESCE(agent_id,'')
		FROM tool_calls WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, attempt, command, status, result, policy, agentID string
		if err := rows.Scan(&id, &attempt, &command, &status, &result, &policy, &agentID); err != nil {
			return err
		}
		// A gate-denied proposal (Attempt A) or a model refusal is the app-side
		// half of the blame chain -- surface it as a risk so the orchestration
		// lens renders it distinctly from an ordinary tool call.
		risk := ""
		if status == "denied" || status == "refused" {
			risk = "refused"
		}
		add(GraphLensNode{ID: id, Kind: "tool_call", Subtype: status, Label: shortLabel(command, id), Risk: risk, TrustOrigin: "agent_asserted", Data: map[string]any{
			"attempt_id": attempt, "command": command, "status": status, "result_ref": result, "policy_decision": policy, "agent_id": agentID,
		}})
		if result != "" {
			add(GraphLensNode{ID: result, Kind: "artifact", Label: lensShortRef(result), TrustOrigin: "agent_generated", Data: map[string]any{"result_ref": result, "tool_call_id": id}})
		}
	}
	return rows.Err()
}

func addProcessNodes(db *sql.DB, runID string, add func(GraphLensNode)) error {
	rows, err := db.Query(`SELECT p.id, COALESCE(p.tool_call_id,''), COALESCE(p.command,''), COALESCE(p.status,''), COALESCE(p.exit_code,0)
		FROM processes p JOIN sessions s ON s.id = p.session_id WHERE s.run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, toolCall, command, status string
		var exitCode int
		if err := rows.Scan(&id, &toolCall, &command, &status, &exitCode); err != nil {
			return err
		}
		add(GraphLensNode{ID: id, Kind: "process", Subtype: status, Label: shortLabel(command, id), TrustOrigin: "runtime_observed", Data: map[string]any{
			"tool_call_id": toolCall, "command": command, "status": status, "exit_code": exitCode,
		}})
	}
	return rows.Err()
}

func addPolicyNodes(db *sql.DB, runID string, add func(GraphLensNode)) error {
	policies, err := db.Query(`SELECT id, COALESCE(event_id,''), COALESCE(rule_id,''), decision, COALESCE(reason,'') FROM policy_decisions WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer policies.Close()
	for policies.Next() {
		var id, eventID, rule, decision, reason string
		if err := policies.Scan(&id, &eventID, &rule, &decision, &reason); err != nil {
			return err
		}
		add(GraphLensNode{ID: "policy_decision/" + id, Kind: "policy_decision", Subtype: decision, Label: "policy: " + decision, Risk: riskForDecision(decision), Data: map[string]any{
			"policy_decision_id": id, "event_id": eventID, "rule_id": rule, "decision": decision, "reason": reason,
		}})
	}
	risks, err := db.Query(`SELECT id, COALESCE(event_id,''), signal_type, severity, COALESCE(reason,''), COALESCE(recommended_action,'') FROM risk_signals WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer risks.Close()
	for risks.Next() {
		var id, eventID, stype, severity, reason, action string
		if err := risks.Scan(&id, &eventID, &stype, &severity, &reason, &action); err != nil {
			return err
		}
		add(GraphLensNode{ID: "risk_signal/" + id, Kind: "risk_signal", Subtype: severity, Label: stype, Risk: severity, Data: map[string]any{
			"risk_signal_id": id, "event_id": eventID, "signal_type": stype, "severity": severity, "reason": reason, "recommended_action": action,
		}})
	}
	responses, err := db.Query(`SELECT id, action_type, COALESCE(status,''), COALESCE(target_type,''), COALESCE(target_id,'') FROM response_actions WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer responses.Close()
	for responses.Next() {
		var id, action, status, targetType, targetID string
		if err := responses.Scan(&id, &action, &status, &targetType, &targetID); err != nil {
			return err
		}
		add(GraphLensNode{ID: "response_action/" + id, Kind: "response_action", Subtype: status, Label: "response: " + action, Data: map[string]any{
			"response_action_id": id, "action_type": action, "status": status, "target_type": targetType, "target_id": targetID,
		}})
	}
	return nil
}

func addSnapshotAttemptNodes(db *sql.DB, runID string, add func(GraphLensNode)) error {
	rows, err := db.Query(`SELECT a.id, COALESCE(a.snapshot_id,''), COALESCE(a.status,''), COALESCE(a.strategy,''), COALESCE(a.artifact_result,''), COALESCE(a.risk_status,'')
		FROM fork_attempts a JOIN rollouts r ON r.id = a.rollout_id WHERE r.run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, snapshot, status, strategy, artifact, risk string
		if err := rows.Scan(&id, &snapshot, &status, &strategy, &artifact, &risk); err != nil {
			return err
		}
		add(GraphLensNode{ID: id, Kind: "attempt", Subtype: status, Label: id, Risk: risk, Data: map[string]any{
			"snapshot_id": snapshot, "strategy": strategy, "artifact_result": artifact, "risk_status": risk,
		}})
		if artifact != "" {
			add(GraphLensNode{ID: artifact, Kind: "artifact", Label: lensShortRef(artifact), TrustOrigin: "agent_generated", Data: map[string]any{"attempt_id": id, "result_ref": artifact}})
		}
	}
	snaps, err := db.Query(`SELECT id, COALESCE(name,''), COALESCE(kind,''), COALESCE(status,''), COALESCE(tainted,0) FROM snapshots`)
	if err != nil {
		return err
	}
	defer snaps.Close()
	for snaps.Next() {
		var id, name, kind, status string
		var tainted int
		if err := snaps.Scan(&id, &name, &kind, &status, &tainted); err != nil {
			return err
		}
		risk := ""
		if tainted != 0 {
			risk = "tainted"
		}
		add(GraphLensNode{ID: id, Kind: "snapshot", Subtype: kind, Label: fallback(name, id), Risk: risk, Data: map[string]any{"status": status, "tainted": tainted != 0}})
	}
	return nil
}

// addAgentNodes renders the multi-agent orchestration actors (from the hooks
// bridge): the main orchestrator and each sub-agent / teammate, keyed by the
// "agent/<id>" node id the agent_spawn / agent_message / agent_tool_call edges
// point at. Label is the resolved name (alice/bob) falling back to the agent id.
func addAgentNodes(db *sql.DB, runID string, add func(GraphLensNode)) error {
	rows, err := db.Query(`SELECT id, COALESCE(name,''), COALESCE(agent_type,''), COALESCE(parent_agent_id,''), COALESCE(started_at,''), COALESCE(ended_at,'')
		FROM agents WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, name, agentType, parent, startedAt, endedAt string
		if err := rows.Scan(&id, &name, &agentType, &parent, &startedAt, &endedAt); err != nil {
			return err
		}
		add(GraphLensNode{
			ID:          "agent/" + id,
			Kind:        "agent",
			Subtype:     agentType,
			Label:       fallback(name, id),
			TrustOrigin: "agent_asserted",
			Data: map[string]any{
				"agent_id": id, "name": name, "agent_type": agentType,
				"parent_agent_id": parent, "started_at": startedAt, "ended_at": endedAt,
			},
		})
	}
	return rows.Err()
}

// addIntentDiffNodes renders the Intent-Runtime Diff results (internal/intent):
// each row is a node keyed by its "diff/<id>" id, which the intent_contract edge
// (scope -> diff) and intent_diff_effect edge (diff -> observed event) point at.
// Colored by status via Risk so the lens reads at a glance: a red mismatch, a
// refusal bypass, a healthy green match, or a muted coverage gap.
func addIntentDiffNodes(db *sql.DB, runID string, add func(GraphLensNode)) error {
	rows, err := db.Query(`SELECT id, COALESCE(agent_id,''), COALESCE(contract_kind,''), COALESCE(operation,''),
		COALESCE(status,''), COALESCE(finding,''), COALESCE(confidence,0), COALESCE(observed_effects,'[]'), COALESCE(mismatch_reason,'')
		FROM intent_diffs WHERE run_id = ?`, runID)
	if err != nil {
		// Table may not exist on an older imported store: degrade to no nodes.
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var id, agentID, kind, operation, status, finding, observed, reason string
		var confidence float64
		if err := rows.Scan(&id, &agentID, &kind, &operation, &status, &finding, &confidence, &observed, &reason); err != nil {
			return err
		}
		label := intentDiffLabel(status, finding, operation)
		add(GraphLensNode{
			ID:      id,
			Kind:    "intent_diff",
			Subtype: status,
			Label:   label,
			Risk:    intentDiffRisk(status),
			Data: map[string]any{
				"status": status, "finding": finding, "operation": operation, "contract_kind": kind,
				"agent_id": agentID, "confidence": confidence, "observed_effects": observed, "reason": reason,
			},
		})
	}
	return rows.Err()
}

func intentDiffLabel(status, finding, operation string) string {
	head := finding
	if head == "" {
		head = status
	}
	switch status {
	case "declared_vs_effect_mismatch":
		return "⚠ " + operation + ": declared≠actual"
	case "refused_but_runtime_happened":
		return "⊘ refusal bypassed"
	case "decided_and_executed":
		return "✓ " + operation + " as declared"
	case "intent_coverage_gap":
		return "? uncaptured intent"
	default:
		return head
	}
}

// intentDiffRisk maps a diff status to a lens risk tier so the dashboard's
// existing risk coloring highlights divergence without new plumbing.
func intentDiffRisk(status string) string {
	switch status {
	case "refused_but_runtime_happened":
		return "critical"
	case "declared_vs_effect_mismatch":
		return "high"
	case "intent_coverage_gap":
		return "info"
	default:
		return ""
	}
}

// llmMetaCache memoizes parsed llm_message metadata by object-file path. Object
// files are content-addressed and immutable, so a path always maps to the same
// content -- caching avoids re-reading every object on every lens refresh.
var llmMetaCache sync.Map // path -> llmMessageSummary

type llmMessageSummary struct {
	Model        string
	ToolCalls    []string
	ToolsOffered []string
	MessageCount int
	StopReason   string
	Command      string
	Prompt       string
}

// llmMessageMeta reads a stored llm_message object file and pulls out the model,
// prompt/tool summary, and the model's decided command. Best-effort: any
// read/parse failure degrades to a bare label.
func llmMessageMeta(path string) llmMessageSummary {
	if path == "" {
		return llmMessageSummary{}
	}
	if v, ok := llmMetaCache.Load(path); ok {
		return v.(llmMessageSummary)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return llmMessageSummary{}
	}
	var obj struct {
		Payload struct {
			Content   string `json:"content"`
			Model     string `json:"model"`
			Semantics struct {
				Model        string   `json:"model"`
				ToolCalls    []string `json:"tool_calls"`
				ToolsOffered []string `json:"tools_offered"`
				MessageCount int      `json:"message_count"`
				StopReason   string   `json:"stop_reason"`
			} `json:"semantics"`
		} `json:"payload"`
	}
	if json.Unmarshal(raw, &obj) != nil {
		return llmMessageSummary{}
	}
	prompt, command := llmContentSummary(obj.Payload.Content)
	out := llmMessageSummary{
		Model:        firstString([]string{obj.Payload.Model, obj.Payload.Semantics.Model}),
		ToolCalls:    obj.Payload.Semantics.ToolCalls,
		ToolsOffered: obj.Payload.Semantics.ToolsOffered,
		MessageCount: obj.Payload.Semantics.MessageCount,
		StopReason:   obj.Payload.Semantics.StopReason,
		Command:      command,
		Prompt:       prompt,
	}
	llmMetaCache.Store(path, out)
	return out
}

func llmContentSummary(content string) (prompt string, command string) {
	if content == "" {
		return "", ""
	}
	var body map[string]any
	if json.Unmarshal([]byte(content), &body) != nil {
		return "", ""
	}
	if msgs, ok := body["messages"].([]any); ok && len(msgs) > 0 {
		if msg, ok := msgs[0].(map[string]any); ok {
			if s, ok := msg["content"].(string); ok {
				prompt = conciseCommandLabel(s)
			}
		}
	}
	if items, ok := body["content"].([]any); ok {
		for _, item := range items {
			m, ok := item.(map[string]any)
			if !ok || m["type"] != "tool_use" {
				continue
			}
			if input, ok := m["input"].(map[string]any); ok {
				if s, ok := input["command"].(string); ok {
					command = s
					break
				}
			}
		}
	}
	return prompt, command
}

func addProvenanceObjectNodes(db *sql.DB, runID string, add func(GraphLensNode)) error {
	agentNames := agentNameMap(db, runID)
	rows, err := db.Query(`SELECT hash, object_type, COALESCE(source_id,''), COALESCE(path,''), COALESCE(size_bytes,0)
		FROM provenance_objects WHERE run_id = ? AND object_type IN ('artifact','llm_message')`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var hash, objectType, sourceID, path string
		var sizeBytes int64
		if err := rows.Scan(&hash, &objectType, &sourceID, &path, &sizeBytes); err != nil {
			return err
		}
		// The model's actual prompt/completion, captured at the TLS boundary and
		// stored as content-addressed evidence. Label so the graph reads as a plain
		// narrative: "LLM request" -> "LLM response" (carrying the tool the model
		// decided) -> the syscall it caused.
		if objectType == "llm_message" {
			meta := llmMessageMeta(path)
			kind, label := "llm_prompt", "request"
			if strings.HasPrefix(sourceID, "llm_response/") {
				kind, label = "llm_completion", "response"
				if len(meta.ToolCalls) > 0 {
					label += ": " + strings.Join(meta.ToolCalls, ", ")
				}
			}
			if meta.Model != "" {
				if kind == "llm_prompt" {
					label += ": " + meta.Model
				} else {
					label += " [" + meta.Model + "]"
				}
			}
			add(GraphLensNode{
				ID: hash, Kind: kind, Subtype: "llm_message", Label: label,
				TrustOrigin: "content_addressed",
				Data: map[string]any{
					"hash": hash, "source_id": sourceID, "path": path, "model": meta.Model,
					"tool_decision": meta.ToolCalls, "tools_offered": meta.ToolsOffered,
					"message_count": meta.MessageCount, "stop_reason": meta.StopReason,
					"prompt": meta.Prompt, "command": meta.Command,
				},
			})
			continue
		}
		// A SendMessage body is objectified for verifiability, but it should read
		// as an agent-to-agent message, not a generic file artifact. Both messages
		// here carry the SAME instruction; distinguish them only by TOPOLOGY, never
		// by a benign/malicious verdict: peer (对等, sub-agent -> sub-agent) vs
		// delegation (主从, orchestrator -> sub-agent). The graph shows every path
		// the instruction reached the recipient; deciding which path is "the attack"
		// is a separate analysis layer, not something this lens pre-judges.
		if from, to, ok := parseAgentMessageSource(sourceID); ok {
			fromName, toName := agentLabel(agentNames, from), agentLabel(agentNames, to)
			kind, subtype, label := "message", "peer", "peer "+fromName+" -> "+toName
			if from == "main" { // main/orchestrator -> sub-agent = delegation (主从), not a peer edge
				kind, subtype, label = "relay", "delegation", "delegate "+fromName+" -> "+toName
			}
			add(GraphLensNode{
				ID:          hash,
				Kind:        kind,
				Subtype:     subtype,
				Label:       label,
				TrustOrigin: "content_addressed",
				Data: map[string]any{
					"hash": hash, "kind": "agent_message", "topology": subtype, "from": from, "to": to,
					"from_name": fromName, "to_name": toName,
					"source_id": sourceID, "path": path,
				},
			})
			continue
		}
		add(GraphLensNode{
			ID:          hash,
			Kind:        "artifact",
			Subtype:     objectType,
			Label:       lensShortRef(sourceID),
			TrustOrigin: "content_addressed",
			Data: map[string]any{
				"hash": hash, "object_type": objectType, "source_id": sourceID, "path": path, "size_bytes": sizeBytes,
			},
		})
	}
	return rows.Err()
}

// parseAgentMessageSource splits an objectified peer-message source id
// ("agent_message/<from>-><to>/<seq>") into the sender and recipient agent ids.
func parseAgentMessageSource(sourceID string) (from, to string, ok bool) {
	rest, found := strings.CutPrefix(sourceID, "agent_message/")
	if !found {
		return "", "", false
	}
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		rest = rest[:i] // drop the trailing /<seq>
	}
	from, to, ok = strings.Cut(rest, "->")
	return from, to, ok
}

// agentNameMap resolves agent id -> display name for the run.
func agentNameMap(db *sql.DB, runID string) map[string]string {
	m := map[string]string{}
	rows, err := db.Query(`SELECT id, COALESCE(name,'') FROM agents WHERE run_id = ?`, runID)
	if err != nil {
		return m
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err == nil {
			m[id] = name
		}
	}
	return m
}

func agentLabel(names map[string]string, id string) string {
	if n := names[id]; n != "" {
		return n
	}
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
