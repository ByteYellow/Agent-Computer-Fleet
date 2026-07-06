package provenance

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

func graphLensEdges(db *sql.DB, runID string) ([]GraphLensEdge, error) {
	rows, err := db.Query(`SELECT id, from_id, to_id, edge_type, COALESCE(source_event_id,''), created_at FROM graph_edges WHERE run_id = ? ORDER BY created_at ASC, id ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var edges []GraphLensEdge
	for rows.Next() {
		var edge GraphLensEdge
		if err := rows.Scan(&edge.ID, &edge.FromID, &edge.ToID, &edge.EdgeType, &edge.SourceEventID, &edge.CreatedAt); err != nil {
			return nil, err
		}
		edges = append(edges, edge)
	}
	return edges, rows.Err()
}

func filterGraphLensEdges(lens, focus, detail string, nodes map[string]GraphLensNode, events map[string]lensEvent, edges []GraphLensEdge) []GraphLensEdge {
	var out []GraphLensEdge
	focus = strings.TrimSpace(focus)
	focusIDs := map[string]bool{}
	if focus != "" {
		focusIDs[focus] = true
	}
	for _, edge := range edges {
		if !edgeMatchesLens(lens, detail, edge, nodes, events) {
			continue
		}
		if focus != "" && !edgeTouchesFocus(edge, focusIDs, focus) {
			continue
		}
		if focus != "" {
			focusIDs[edge.FromID] = true
			focusIDs[edge.ToID] = true
		}
		out = append(out, edge)
	}
	return out
}

func edgeTouchesFocus(edge GraphLensEdge, focusIDs map[string]bool, focus string) bool {
	if edge.FromID == focus || edge.ToID == focus || strings.Contains(edge.FromID, focus) || strings.Contains(edge.ToID, focus) {
		return true
	}
	if (focusIDs[edge.FromID] || focusIDs[edge.ToID]) && isSecurityChainEdge(edge.EdgeType) {
		return true
	}
	return false
}

func isSecurityChainEdge(edgeType string) bool {
	switch edgeType {
	case "runtime_event_policy_decision", "policy_decision_risk_signal", "risk_signal_response_action":
		return true
	default:
		return false
	}
}

func edgeMatchesLens(lens, detail string, edge GraphLensEdge, nodes map[string]GraphLensNode, events map[string]lensEvent) bool {
	from := nodes[edge.FromID]
	to := nodes[edge.ToID]
	fromEvent := events[edge.FromID]
	toEvent := events[edge.ToID]
	if detail != "raw" && !edgeIsMaterializedSignal(edge, from, to, fromEvent, toEvent) {
		return false
	}
	switch lens {
	case "security":
		return strings.Contains(edge.EdgeType, "policy") || strings.Contains(edge.EdgeType, "risk") || strings.Contains(edge.EdgeType, "response") ||
			isSecurityKind(from.Kind) || isSecurityKind(to.Kind) || riskForLensEvent(fromEvent) != "" || riskForLensEvent(toEvent) != ""
	case "process":
		return strings.Contains(edge.EdgeType, "process") || from.Kind == "process" || to.Kind == "process" || strings.HasPrefix(edge.FromID, "runtime_process/") || strings.HasPrefix(edge.ToID, "runtime_process/")
	case "file-artifact":
		return strings.Contains(edge.EdgeType, "file") || strings.Contains(edge.EdgeType, "artifact") || from.Kind == "file" || to.Kind == "file" || from.Kind == "artifact" || to.Kind == "artifact" ||
			strings.HasPrefix(edge.FromID, "workspace_file/") || strings.HasPrefix(edge.ToID, "workspace_file/")
	case "network-egress":
		return isNetworkEvent(fromEvent.Type) || isNetworkEvent(toEvent.Type) || strings.Contains(edge.EdgeType, "network") || strings.Contains(edge.EdgeType, "egress") || strings.Contains(edge.EdgeType, "llm_call")
	case "data-flow-taint":
		return edge.Derived || isSourceEvent(fromEvent.Type, fromEvent.Path) || isSourceEvent(toEvent.Type, toEvent.Path) || isTaintSinkEvent(fromEvent) || isTaintSinkEvent(toEvent)
	case "agent-intent":
		// The LLM-story lens: the llm_call chain (request/response/decided/caused)
		// and each agent's tool calls. Excludes (a) the broad ingest-time
		// llm_intent_caused, which links the response to every action in the window,
		// and (b) the runtime_* event/process plumbing -- both drown the story and
		// both stay in the DB + default/raw lens for full observability.
		if strings.HasPrefix(edge.EdgeType, "runtime_") {
			return false
		}
		return (strings.Contains(edge.EdgeType, "llm_") && edge.EdgeType != "llm_intent_caused") ||
			strings.HasPrefix(edge.EdgeType, "agent_") ||
			from.Kind == "tool_call" || to.Kind == "tool_call"
	case "orchestration":
		// Multi-agent structure: delegation (agent_spawn), peer influence
		// (agent_message + the objectified body), and each agent's tool calls
		// (incl. the refused Attempt-A node).
		return strings.HasPrefix(edge.EdgeType, "agent_") || from.Kind == "agent" || to.Kind == "agent" ||
			strings.HasPrefix(edge.FromID, "agent/") || strings.HasPrefix(edge.ToID, "agent/") ||
			from.Risk == "refused" || to.Risk == "refused"
	case "intent":
		// The declared-vs-actual story: each contract's scope (its tool call /
		// agent) -> the diff verdict -> the observed effects that back it, plus
		// the agent tool-call/message edges that give the diff its intent origin.
		return strings.HasPrefix(edge.EdgeType, "intent_") ||
			from.Kind == "intent_diff" || to.Kind == "intent_diff" ||
			edge.EdgeType == "agent_tool_call" || edge.EdgeType == "agent_message"
	case "trust-origin":
		return from.TrustOrigin != "" || to.TrustOrigin != "" || from.Kind == "artifact" || to.Kind == "artifact" || from.Kind == "tool_call" || to.Kind == "tool_call"
	case "sandbox-boundary":
		return isBoundaryEvent(fromEvent.Type) || isBoundaryEvent(toEvent.Type) || strings.Contains(edge.EdgeType, "snapshot") || strings.Contains(edge.EdgeType, "attempt")
	default:
		return true
	}
}

func edgeIsMaterializedSignal(edge GraphLensEdge, from, to GraphLensNode, fromEvent, toEvent lensEvent) bool {
	if edge.Derived {
		return true
	}
	if isStructuralEdge(edge.EdgeType) {
		return true
	}
	if fromEvent.ID != "" || toEvent.ID != "" {
		return eventIsGraphSignal(fromEvent) || eventIsGraphSignal(toEvent)
	}
	if isGraphValueNode(from) || isGraphValueNode(to) {
		return true
	}
	return eventIsGraphSignal(fromEvent) || eventIsGraphSignal(toEvent)
}

func isStructuralEdge(edgeType string) bool {
	switch edgeType {
	case "runtime_tool_call_process", "runtime_tool_call_file",
		"runtime_process_file", "runtime_attempt_file",
		"runtime_event_policy_decision", "policy_decision_risk_signal", "risk_signal_response_action",
		// llm_intent_caused (tls_read event -> syscall) is deliberately NOT rendered:
		// once materialized, MaterializeLLMCalls lifts the same link onto the
		// llm_call node as llm_caused, so rendering both would double every
		// intent->action edge.
		"llm_call", "llm_request", "llm_response", "llm_caused",
		"attempt_snapshot", "snapshot_parent", "promotion_winner",
		"agent_spawn", "agent_message", "agent_tool_call", "agent_syscall",
		"intent_contract", "intent_diff_effect":
		return true
	default:
		return strings.Contains(edgeType, "policy") || strings.Contains(edgeType, "risk") ||
			strings.Contains(edgeType, "response") || strings.Contains(edgeType, "artifact")
	}
}

func isGraphValueNode(node GraphLensNode) bool {
	switch node.Kind {
	case "tool_call", "process", "artifact", "file", "policy_decision", "risk_signal", "response_action", "attempt", "snapshot", "agent", "message", "relay", "llm_call", "llm_prompt", "llm_completion", "intent_diff":
		return true
	default:
		return false
	}
}

func eventIsGraphSignal(ev lensEvent) bool {
	if ev.ID == "" {
		return false
	}
	if riskForLensEvent(ev) != "" || isNetworkEvent(ev.Type) || isSourceEvent(ev.Type, ev.Path) || isBoundaryEvent(ev.Type) {
		return true
	}
	switch ev.Type {
	case "execve", "file_write", "file_create", "file_modify", "artifact_export", "tool_call", "llm_call", "llm_intent", "process_start":
		return true
	default:
		return false
	}
}

func sortedLensNodes(nodes map[string]GraphLensNode, used map[string]bool) []GraphLensNode {
	out := make([]GraphLensNode, 0, len(used))
	for id := range used {
		node, ok := nodes[id]
		if !ok {
			node = inferLensNode(id)
		}
		out = append(out, node)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func egressGroupNode(edge GraphLensEdge) GraphLensNode {
	label := "risky egress group"
	destinations := stringsFromEdgeData(edge.Data, "destinations")
	if len(destinations) > 0 {
		label = "risky egress: " + destinations[0]
		if len(destinations) > 1 {
			label += fmt.Sprintf(" +%d", len(destinations)-1)
		}
	}
	return GraphLensNode{
		ID:          edge.ToID,
		Kind:        "egress_group",
		Subtype:     "risky_egress",
		Label:       label,
		Risk:        "high",
		TrustOrigin: "derived_summary",
		Data: map[string]any{
			"source_count":     valueFromMap(edge.Data, "source_count"),
			"sink_count":       valueFromMap(edge.Data, "sink_count"),
			"destinations":     destinations,
			"sensitive_paths":  stringsFromEdgeData(edge.Data, "sensitive_paths"),
			"derivation_rule":  edge.DerivationRule,
			"confidence":       edge.Confidence,
			"evidence_ref_cnt": len(edge.EvidenceRefs),
		},
	}
}

// prioritizeLensEdges stably reorders edges so that edges touching semantically
// important nodes come first and the runtime_event/runtime_process BULK comes
// last. When splitAndLimitLensEdges truncates to the budget, the important
// connections survive, so annotation nodes (policy/response/risk/file/artifact/
// tool_call/...) stay wired to their lineage instead of floating.
func prioritizeLensEdges(edges []GraphLensEdge, nodes map[string]GraphLensNode) {
	// The graph's edge population is dominated by the STRUCTURAL SKELETON
	// (runtime_process_event / runtime_tool_call_process / runtime_tool_call_event
	// / runtime_attempt_event ... -- hundreds of them, connecting one tool_call /
	// process to every event). The RARE, semantically critical edges are the
	// lineage of the annotation nodes: file/artifact production, policy, risk,
	// response, taint. Those must survive the edge-budget cut so the product and
	// the security verdicts stay on the graph. Note we key on the RARE kinds and
	// annotation edge_types only -- NOT "tool_call"/"process" substrings, which
	// would (wrongly) promote the whole skeleton.
	rare := map[string]bool{"file": true, "artifact": true, "policy_decision": true, "response_action": true, "risk_signal": true}
	tier := func(e GraphLensEdge) int {
		if e.Derived {
			return 0
		}
		et := e.EdgeType
		for _, s := range []string{"policy", "risk", "response", "artifact", "taint", "data_flow", "file", "llm_"} {
			if strings.Contains(et, s) {
				return 0
			}
		}
		for _, id := range []string{e.FromID, e.ToID} {
			if n, ok := nodes[id]; ok && rare[n.Kind] {
				return 0
			}
		}
		return 1
	}
	sort.SliceStable(edges, func(i, j int) bool { return tier(edges[i]) < tier(edges[j]) })
}

func splitAndLimitLensEdges(edges []GraphLensEdge, limit int) ([]GraphLensEdge, []GraphLensEdge, bool) {
	truncated := false
	if limit > 0 && len(edges) > limit {
		edges = edges[:limit]
		truncated = true
	}
	canonical := []GraphLensEdge{}
	derived := []GraphLensEdge{}
	for _, edge := range edges {
		if edge.Derived {
			derived = append(derived, edge)
		} else {
			canonical = append(canonical, edge)
		}
	}
	return canonical, derived, truncated
}

func buildGraphLensOverlays(nodes map[string]GraphLensNode, selected []GraphLensNode, overlays []string) []GraphLensOverlay {
	if len(overlays) == 0 {
		return nil
	}
	want := map[string]bool{}
	for _, overlay := range overlays {
		want[overlay] = true
	}
	var out []GraphLensOverlay
	for _, node := range selected {
		full := nodes[node.ID]
		if want["risk"] || want["security"] {
			if full.Risk != "" {
				out = append(out, GraphLensOverlay{TargetID: node.ID, Kind: "risk", Label: full.Risk, Severity: full.Risk})
			}
		}
		if want["trust"] && full.TrustOrigin != "" {
			out = append(out, GraphLensOverlay{TargetID: node.ID, Kind: "trust_origin", Label: full.TrustOrigin})
		}
	}
	return out
}

func cleanOverlays(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, raw := range values {
		for _, part := range strings.Split(raw, ",") {
			part = strings.ToLower(strings.TrimSpace(part))
			if part == "" || seen[part] {
				continue
			}
			seen[part] = true
			out = append(out, part)
		}
	}
	return out
}

func graphLensRules(lens string) []string {
	switch lens {
	case "security":
		return []string{"risk rule groups", "policy/risk/response path on focus", "high-risk runtime events"}
	case "process":
		return []string{"process groups by tool_call", "event bursts", "raw detail for full process tree"}
	case "file-artifact":
		return []string{"file path groups", "artifact lineage", "raw detail for individual files"}
	case "network-egress":
		return []string{"network_connect", "metadata_ip", "private_cidr", "dns_query", "tls_read/write"}
	case "data-flow-taint":
		return []string{"secret/file source events", "network sink events", "derived possible_sensitive_data_flow"}
	case "agent-intent":
		return []string{"causal DAG over real evidence: prompt → response → caused exec → send msg"}
	case "orchestration":
		return []string{"agent_spawn (delegation)", "agent_message (peer, body objectified)", "each agent's tool calls incl. refused proposals"}
	case "intent":
		return []string{"contract scope → diff verdict → observed effects", "declared_vs_effect_mismatch / refused_bypass / coverage_gap", "conditional on each action's declared contract, not a global rule"}
	case "trust-origin":
		return []string{"trust_origin annotations", "agent/tool/artifact nodes"}
	case "sandbox-boundary":
		return []string{"boundary/tamper/privilege events", "snapshot/attempt edges"}
	default:
		return []string{"run overview groups", "filtered high-value telemetry", "raw detail for full graph"}
	}
}

func graphLensLayout(lens string) string {
	switch lens {
	case "security":
		return "risk_overview"
	case "process":
		return "process_groups"
	case "file-artifact":
		return "file_groups"
	case "network-egress":
		return "egress_map"
	case "data-flow-taint":
		return "source_to_sink"
	case "agent-intent":
		return "intent_to_action"
	case "orchestration":
		return "agent_topology"
	case "intent":
		return "contract_vs_effect"
	case "trust-origin":
		return "origin_overlay"
	case "sandbox-boundary":
		return "boundary_map"
	default:
		return "run_overview"
	}
}

func inferLensNode(id string) GraphLensNode {
	switch {
	case strings.HasPrefix(id, "runtime_event/"):
		return GraphLensNode{ID: id, Kind: "runtime_event", Label: lensShortRef(id)}
	case strings.HasPrefix(id, "runtime_process/"):
		return GraphLensNode{ID: id, Kind: "runtime_process", Label: lensShortRef(id), TrustOrigin: "runtime_observed"}
	case strings.HasPrefix(id, "workspace_file/"):
		return GraphLensNode{ID: id, Kind: "file", Label: strings.TrimPrefix(id, "workspace_file/"), TrustOrigin: "workspace_state"}
	case strings.HasPrefix(id, "agent/"):
		return GraphLensNode{ID: id, Kind: "agent", Label: strings.TrimPrefix(id, "agent/"), TrustOrigin: "agent_asserted"}
	case strings.HasPrefix(id, "llm_call/"):
		return GraphLensNode{ID: id, Kind: "llm_call", Label: "LLM call", TrustOrigin: "content_addressed"}
	case strings.HasPrefix(id, "diff/"):
		return GraphLensNode{ID: id, Kind: "intent_diff", Label: "intent diff", TrustOrigin: "derived_summary"}
	case strings.HasPrefix(id, "egress_group/"):
		return GraphLensNode{ID: id, Kind: "egress_group", Subtype: "risky_egress", Label: "risky egress group", Risk: "high", TrustOrigin: "derived_summary"}
	case strings.HasPrefix(id, "policy_decision/"):
		return GraphLensNode{ID: id, Kind: "policy_decision", Label: lensShortRef(id)}
	case strings.HasPrefix(id, "risk_signal/"):
		return GraphLensNode{ID: id, Kind: "risk_signal", Label: lensShortRef(id)}
	case strings.HasPrefix(id, "response_action/"):
		return GraphLensNode{ID: id, Kind: "response_action", Label: lensShortRef(id)}
	// App-context entities referenced only as edge endpoints (no table-backed
	// typed node -- e.g. telemetry-ingested runs, or rollout/record-attempt ids
	// that aren't materialized as their own graph node). Type them by their
	// ids.New prefix so they render with a real kind and are counted, instead of
	// falling to a generic "unknown" gray node. This fallback only runs for
	// endpoints not already created from a table, so it never double-counts.
	case strings.HasPrefix(id, "tool-") || strings.HasPrefix(id, "tool_call/"):
		return GraphLensNode{ID: id, Kind: "tool_call", Label: lensShortRef(id)}
	case strings.HasPrefix(id, "record-attempt-") || strings.HasPrefix(id, "attempt-"):
		return GraphLensNode{ID: id, Kind: "attempt", Label: lensShortRef(id)}
	case strings.HasPrefix(id, "rollout-"):
		return GraphLensNode{ID: id, Kind: "rollout", Label: lensShortRef(id)}
	case strings.HasPrefix(id, "session-"):
		return GraphLensNode{ID: id, Kind: "session", Label: lensShortRef(id)}
	case strings.HasPrefix(id, "proc-") || strings.HasPrefix(id, "process-"):
		return GraphLensNode{ID: id, Kind: "process", Label: lensShortRef(id)}
	default:
		return GraphLensNode{ID: id, Kind: "unknown", Label: lensShortRef(id)}
	}
}
