package provenance

import (
	"fmt"
	"sort"
	"strings"
)

func summaryLensEdges(runID, lens, focus, detail string, nodes map[string]GraphLensNode, events map[string]lensEvent, edges []GraphLensEdge) ([]GraphLensEdge, bool) {
	if detail != "summary" || strings.TrimSpace(focus) != "" {
		return nil, false
	}
	switch lens {
	case "default":
		return buildRunOverviewEdges(runID, nodes, events, edges), true
	case "process":
		return buildProcessGroupEdges(nodes, events), true
	case "file-artifact":
		return buildFileGroupEdges(runID, nodes, edges), true
	case "security":
		return buildSecurityRuleEdges(runID, nodes, events), true
	case "network-egress":
		return buildNetworkGroupEdges(runID, nodes, events), true
	case "data-flow-taint":
		return buildDataFlowSummaryEdges(events), true
	case "agent-intent":
		return buildIntentDAGEdges(runID, nodes, events, edges), true
	case "trust-origin":
		return buildTrustOriginGroupEdges(runID, nodes), true
	case "sandbox-boundary":
		return buildSandboxBoundaryGroupEdges(runID, nodes, events), true
	default:
		return nil, false
	}
}

func buildRunOverviewEdges(runID string, nodes map[string]GraphLensNode, events map[string]lensEvent, edges []GraphLensEdge) []GraphLensEdge {
	runNode := GraphLensNode{ID: "run/" + runID, Kind: "run", Label: runID, Data: map[string]any{"run_id": runID}}
	nodes[runNode.ID] = runNode
	counts := overviewCounts(nodes, events, edges)
	groups := []struct {
		ID      string
		Label   string
		Subtype string
		Risk    string
		Data    map[string]any
	}{
		{"overview/tool_calls", fmt.Sprintf("Tool calls: %d", counts.ToolCalls), "tool_calls", "", map[string]any{"count": counts.ToolCalls, "drilldown_lens": "intent", "drilldown_detail": "summary"}},
		{"overview/processes", fmt.Sprintf("Process groups: %d pids", counts.RuntimeProcesses), "processes", "", map[string]any{"runtime_processes": counts.RuntimeProcesses, "logical_processes": counts.Processes, "drilldown_lens": "process", "drilldown_detail": "summary"}},
		{"overview/files", fmt.Sprintf("File changes: %d", counts.Files), "files", "", map[string]any{"count": counts.Files, "drilldown_lens": "file-artifact", "drilldown_detail": "summary"}},
		{"overview/egress", fmt.Sprintf("Egress: %d risky / %d total", counts.RiskyEgress, counts.Egress), "egress", riskIf(counts.RiskyEgress > 0), map[string]any{"total": counts.Egress, "risky": counts.RiskyEgress, "drilldown_lens": "network-egress", "drilldown_detail": "summary"}},
		{"overview/risks", fmt.Sprintf("Risks: %d high / %d total", counts.HighRisks, counts.Risks), "risks", riskIf(counts.HighRisks > 0), map[string]any{"total": counts.Risks, "high": counts.HighRisks, "drilldown_lens": "security", "drilldown_detail": "summary"}},
		{"overview/agent_network", fmt.Sprintf("Agent network: %d agents / %d peer msgs", counts.Agents, counts.AgentMessages), "agent_network", "", map[string]any{"agents": counts.Agents, "messages": counts.AgentMessages, "drilldown_lens": "orchestration", "drilldown_detail": "summary"}},
		{"overview/llm_intent", fmt.Sprintf("LLM intent: %d evidence nodes", counts.LLMIntents), "llm_intent", "", map[string]any{"count": counts.LLMIntents, "drilldown_lens": "agent-intent", "drilldown_detail": "summary"}},
		{"overview/artifacts", fmt.Sprintf("Artifacts: %d", counts.Artifacts), "artifacts", "", map[string]any{"count": counts.Artifacts, "drilldown_lens": "file-artifact", "drilldown_detail": "summary"}},
	}
	out := make([]GraphLensEdge, 0, len(groups))
	for i, group := range groups {
		nodes[group.ID] = GraphLensNode{ID: group.ID, Kind: "overview_group", Subtype: group.Subtype, Label: group.Label, Risk: group.Risk, TrustOrigin: "summary", Data: group.Data}
		out = append(out, GraphLensEdge{
			ID:        fmt.Sprintf("summary-overview-%d", i),
			FromID:    runNode.ID,
			ToID:      group.ID,
			EdgeType:  "overview_contains",
			CreatedAt: "",
			Data:      group.Data,
		})
	}
	return out
}

type overviewMetricCounts struct {
	ToolCalls        int
	Processes        int
	RuntimeProcesses int
	Files            int
	Egress           int
	RiskyEgress      int
	Risks            int
	HighRisks        int
	Artifacts        int
	Agents           int
	AgentMessages    int
	LLMIntents       int
}

func overviewCounts(nodes map[string]GraphLensNode, events map[string]lensEvent, edges []GraphLensEdge) overviewMetricCounts {
	var counts overviewMetricCounts
	hasRiskSignals := false
	fileIDs := map[string]bool{}
	for _, node := range nodes {
		switch node.Kind {
		case "tool_call":
			counts.ToolCalls++
		case "agent":
			counts.Agents++
		case "llm_call":
			counts.LLMIntents++
		case "process":
			counts.Processes++
		case "runtime_process":
			counts.RuntimeProcesses++
		case "file":
			fileIDs[node.ID] = true
		case "artifact", "llm_prompt", "llm_completion", "message":
			counts.Artifacts++
			if node.Kind == "message" {
				counts.AgentMessages++
			}
			if node.Kind == "llm_prompt" || node.Kind == "llm_completion" {
				counts.LLMIntents++
			}
		case "risk_signal":
			if isLoopbackPrivateRiskNode(node, events) {
				continue
			}
			hasRiskSignals = true
			counts.Risks++
			if isHighRisk(node.Risk) || isHighRisk(node.Subtype) {
				counts.HighRisks++
			}
		}
	}
	for _, edge := range edges {
		for _, id := range []string{edge.FromID, edge.ToID} {
			if strings.HasPrefix(id, "workspace_file/") {
				fileIDs[id] = true
			}
		}
	}
	counts.Files = len(fileIDs)
	for _, ev := range events {
		if isNetworkEvent(ev.Type) {
			counts.Egress++
		}
		if isRiskyNetworkSummaryEvent(ev) {
			counts.RiskyEgress++
		}
		if hasRiskSignals {
			continue
		}
		if risk := riskForLensEvent(ev); risk != "" {
			counts.Risks++
			if isHighRisk(risk) {
				counts.HighRisks++
			}
		}
	}
	return counts
}

func buildProcessGroupEdges(nodes map[string]GraphLensNode, events map[string]lensEvent) []GraphLensEdge {
	rootID := "process_overview"
	nodes[rootID] = GraphLensNode{ID: rootID, Kind: "overview_group", Subtype: "processes", Label: "Process overview", TrustOrigin: "summary"}
	groups := map[string]*processGroup{}
	for _, ev := range events {
		key := fallback(ev.ToolCallID, "unscoped")
		group := groups[key]
		if group == nil {
			group = &processGroup{toolCall: ev.ToolCallID, pids: map[int64]bool{}, events: map[string]int{}}
			groups[key] = group
		}
		if ev.PID > 0 {
			group.pids[ev.PID] = true
		}
		group.events[ev.Type]++
		if riskForLensEvent(ev) != "" || isTaintSinkEvent(ev) {
			group.risky++
		}
		if isNetworkEvent(ev.Type) {
			group.egress++
		}
		if ev.Type == "file_write" || ev.Type == "file_create" || ev.Type == "file_modify" {
			group.writes++
		}
		cmd := strings.ToLower(payloadString(ev.Payload, "command", "cmdline", "comm", "proc"))
		switch {
		case strings.Contains(cmd, "python"):
			group.python++
		case strings.Contains(cmd, "git"):
			group.git++
		case strings.Contains(cmd, "npm") || strings.Contains(cmd, "pip") || strings.Contains(cmd, "setup.py"):
			group.packageM++
		case strings.Contains(cmd, "sh") || strings.Contains(cmd, "bash") || strings.Contains(cmd, "zsh"):
			group.shells++
		}
	}
	keys := sortedProcessGroupKeys(groups)
	out := []GraphLensEdge{}
	for _, key := range keys {
		group := groups[key]
		groupID := "process_group/" + safeGraphID(key)
		label := fmt.Sprintf("process group: %d pids", len(group.pids))
		nodes[groupID] = GraphLensNode{ID: groupID, Kind: "process_group", Subtype: "summary", Label: label, Risk: riskIf(group.risky > 0), TrustOrigin: "summary", Data: map[string]any{
			"tool_call_id": group.toolCall, "pid_count": len(group.pids), "event_count": sumIntMap(group.events),
			"shells": group.shells, "python": group.python, "git": group.git, "package_managers": group.packageM,
			"risky": group.risky, "workspace_writes": group.writes, "egress": group.egress,
			"drilldown_lens": "process", "drilldown_detail": "raw", "drilldown_focus": group.toolCall,
		}}
		fromID := groupID
		if group.toolCall != "" {
			fromID = group.toolCall
		} else {
			fromID = rootID
		}
		out = append(out, GraphLensEdge{ID: "summary-process-" + safeGraphID(key), FromID: fromID, ToID: groupID, EdgeType: "tool_call_process_group"})
		for _, eventType := range topEventTypes(group.events, 4) {
			burstID := groupID + "/event_burst/" + safeGraphID(eventType)
			count := group.events[eventType]
			nodes[burstID] = GraphLensNode{ID: burstID, Kind: "event_burst", Subtype: eventType, Label: fmt.Sprintf("%s: %d", eventType, count), Risk: riskForEventType(eventType), TrustOrigin: "summary", Data: map[string]any{"event_type": eventType, "count": count, "tool_call_id": group.toolCall, "drilldown_lens": "process", "drilldown_detail": "raw", "drilldown_focus": group.toolCall}}
			out = append(out, GraphLensEdge{ID: "summary-burst-" + safeGraphID(key+"-"+eventType), FromID: groupID, ToID: burstID, EdgeType: "process_event_burst", Data: map[string]any{"count": count, "event_type": eventType}})
		}
	}
	return out
}

func buildFileGroupEdges(runID string, nodes map[string]GraphLensNode, edges []GraphLensEdge) []GraphLensEdge {
	rootID := "run/" + runID
	nodes[rootID] = GraphLensNode{ID: rootID, Kind: "run", Label: runID, Data: map[string]any{"run_id": runID}}
	filesByCategory := map[string]map[string]bool{}
	addFile := func(id string) {
		if !strings.HasPrefix(id, "workspace_file/") {
			return
		}
		path := strings.TrimPrefix(id, "workspace_file/")
		category := filePathCategory(path)
		if filesByCategory[category] == nil {
			filesByCategory[category] = map[string]bool{}
		}
		filesByCategory[category][path] = true
	}
	for id, node := range nodes {
		if node.Kind != "file" {
			continue
		}
		addFile(id)
	}
	for _, edge := range edges {
		for _, id := range []string{edge.FromID, edge.ToID} {
			addFile(id)
		}
	}
	keys := []string{"source", "build_artifact", "dependency_cache", "secret_or_config", "other"}
	out := []GraphLensEdge{}
	for _, key := range keys {
		count := len(filesByCategory[key])
		if count == 0 {
			continue
		}
		id := "file_group/" + key
		label := fmt.Sprintf("%s: %d", strings.ReplaceAll(key, "_", " "), count)
		nodes[id] = GraphLensNode{ID: id, Kind: "file_group", Subtype: key, Label: label, Risk: riskIf(key == "secret_or_config"), TrustOrigin: "summary", Data: map[string]any{"category": key, "count": count, "drilldown_lens": "file-artifact", "drilldown_detail": "raw"}}
		out = append(out, GraphLensEdge{ID: "summary-file-" + key, FromID: rootID, ToID: id, EdgeType: "run_file_group", Data: map[string]any{"category": key, "count": count}})
	}
	return out
}

func buildSecurityRuleEdges(runID string, nodes map[string]GraphLensNode, events map[string]lensEvent) []GraphLensEdge {
	rootID := "run/" + runID
	nodes[rootID] = GraphLensNode{ID: rootID, Kind: "run", Label: runID, Data: map[string]any{"run_id": runID}}
	groups := map[string]*ruleGroup{}
	policyEventIDs := map[string]bool{}
	for _, node := range lensNodesInOrder(nodes) {
		if node.Kind != "policy_decision" {
			continue
		}
		if isLoopbackPrivateRiskNode(node, events) {
			continue
		}
		rule := stringFromAny(node.Data["rule_id"])
		if rule == "" {
			rule = stringFromAny(node.Data["reason"])
		}
		if rule == "" {
			rule = "policy"
		}
		group := groups[rule]
		if group == nil {
			group = &ruleGroup{}
			groups[rule] = group
		}
		group.count++
		group.decision = fallback(stringFromAny(node.Data["decision"]), group.decision)
		group.evidence = append(group.evidence, node.ID)
		if eventID := stringFromAny(node.Data["event_id"]); eventID != "" {
			policyEventIDs[eventID] = true
		}
	}
	for _, ev := range lensEventsInOrder(events) {
		if policyEventIDs[ev.ID] {
			continue
		}
		risk := riskForLensEvent(ev)
		if risk == "" {
			continue
		}
		group := groups[ev.Type]
		if group == nil {
			group = &ruleGroup{}
			groups[ev.Type] = group
		}
		group.count++
		group.severity = risk
		group.eventType = ev.Type
		group.evidence = append(group.evidence, ev.NodeID)
	}
	keys := sortedRuleGroupKeys(groups)
	out := []GraphLensEdge{}
	for _, key := range keys {
		group := groups[key]
		id := "risk_group/" + safeGraphID(key)
		label := fmt.Sprintf("%s: %d", key, group.count)
		decision := fallback(group.decision, group.action)
		if decision != "" {
			label += " -> " + decision
		}
		nodes[id] = GraphLensNode{ID: id, Kind: "risk_group", Subtype: key, Label: label, Risk: fallback(group.severity, riskForDecision(decision)), TrustOrigin: "summary", Data: map[string]any{
			"rule_id": key, "count": group.count, "decision": decision, "event_type": group.eventType, "evidence_refs": capStringSlice(group.evidence, 32), "omitted_evidence": maxInt(0, len(group.evidence)-32),
			"drilldown_lens": "security", "drilldown_detail": "raw", "drilldown_focus": firstString(group.evidence),
		}}
		out = append(out, GraphLensEdge{ID: "summary-risk-" + safeGraphID(key), FromID: rootID, ToID: id, EdgeType: "run_risk_group", EvidenceRefs: capStringSlice(group.evidence, 32)})
	}
	return out
}

func isLoopbackPrivateRiskNode(node GraphLensNode, events map[string]lensEvent) bool {
	eventID := stringFromAny(node.Data["event_id"])
	if eventID == "" {
		return false
	}
	ev, ok := events["runtime_event/"+eventID]
	return ok && ev.Type == "private_cidr" && isLoopbackDestination(ev.Destination)
}

func buildNetworkGroupEdges(runID string, nodes map[string]GraphLensNode, events map[string]lensEvent) []GraphLensEdge {
	rootID := "run/" + runID
	nodes[rootID] = GraphLensNode{ID: rootID, Kind: "run", Label: runID, Data: map[string]any{"run_id": runID}}
	type netGroup struct {
		count        int
		risky        int
		destinations map[string]bool
		evidence     []string
	}
	groups := map[string]*netGroup{}
	for _, ev := range lensEventsInOrder(events) {
		if !isNetworkEvent(ev.Type) {
			continue
		}
		key := networkGroupKey(ev)
		group := groups[key]
		if group == nil {
			group = &netGroup{destinations: map[string]bool{}}
			groups[key] = group
		}
		group.count++
		if isRiskyNetworkSummaryEvent(ev) {
			group.risky++
		}
		if ev.Destination != "" {
			group.destinations[ev.Destination] = true
		}
		group.evidence = append(group.evidence, ev.NodeID)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := []GraphLensEdge{}
	for _, key := range keys {
		group := groups[key]
		id := "egress_group/" + safeGraphID(key)
		destinations := capStringSlice(sortedBoolKeys(group.destinations), 12)
		label := fmt.Sprintf("%s: %d", strings.ReplaceAll(key, "_", " "), group.count)
		if len(destinations) > 0 {
			label += " -> " + destinations[0]
			if len(destinations) > 1 {
				label += fmt.Sprintf(" +%d", len(destinations)-1)
			}
		}
		nodes[id] = GraphLensNode{ID: id, Kind: "egress_group", Subtype: key, Label: label, Risk: riskIf(group.risky > 0), TrustOrigin: "summary", Data: map[string]any{
			"group": key, "count": group.count, "risky": group.risky, "destinations": destinations,
			"evidence_refs": capStringSlice(group.evidence, 32), "omitted_evidence": maxInt(0, len(group.evidence)-32),
			"drilldown_lens": "network-egress", "drilldown_detail": "raw", "drilldown_focus": firstString(group.evidence),
		}}
		out = append(out, GraphLensEdge{ID: "summary-egress-" + safeGraphID(key), FromID: rootID, ToID: id, EdgeType: "run_egress_group", EvidenceRefs: capStringSlice(group.evidence, 32)})
	}
	return out
}

func buildTrustOriginGroupEdges(runID string, nodes map[string]GraphLensNode) []GraphLensEdge {
	rootID := "run/" + runID
	nodes[rootID] = GraphLensNode{ID: rootID, Kind: "run", Label: runID, Data: map[string]any{"run_id": runID}}
	type originGroup struct {
		count    int
		kinds    map[string]int
		evidence []string
	}
	groups := map[string]*originGroup{}
	for _, node := range lensNodesInOrder(nodes) {
		if node.ID == rootID || node.TrustOrigin == "" || node.TrustOrigin == "summary" {
			continue
		}
		key := node.TrustOrigin
		group := groups[key]
		if group == nil {
			group = &originGroup{kinds: map[string]int{}}
			groups[key] = group
		}
		group.count++
		group.kinds[node.Kind]++
		group.evidence = append(group.evidence, node.ID)
	}
	keys := sortedStringKeys(groups)
	out := []GraphLensEdge{}
	for _, key := range keys {
		group := groups[key]
		id := "trust_group/" + safeGraphID(key)
		nodes[id] = GraphLensNode{ID: id, Kind: "trust_group", Subtype: key, Label: fmt.Sprintf("%s: %d", strings.ReplaceAll(key, "_", " "), group.count), TrustOrigin: "summary", Data: map[string]any{
			"origin": key, "count": group.count, "top_kinds": topEventTypes(group.kinds, 6),
			"evidence_refs": capStringSlice(group.evidence, 32), "omitted_evidence": maxInt(0, len(group.evidence)-32),
			"drilldown_lens": "trust-origin", "drilldown_detail": "raw", "drilldown_focus": firstString(group.evidence),
		}}
		out = append(out, GraphLensEdge{ID: "summary-trust-" + safeGraphID(key), FromID: rootID, ToID: id, EdgeType: "run_trust_group", EvidenceRefs: capStringSlice(group.evidence, 32)})
	}
	return out
}

func buildSandboxBoundaryGroupEdges(runID string, nodes map[string]GraphLensNode, events map[string]lensEvent) []GraphLensEdge {
	rootID := "run/" + runID
	nodes[rootID] = GraphLensNode{ID: rootID, Kind: "run", Label: runID, Data: map[string]any{"run_id": runID}}
	type boundaryGroup struct {
		count    int
		risky    int
		evidence []string
	}
	groups := map[string]*boundaryGroup{}
	for _, ev := range lensEventsInOrder(events) {
		if !isBoundaryEvent(ev.Type) || (ev.Type == "private_cidr" && isLoopbackDestination(ev.Destination)) {
			continue
		}
		group := groups[ev.Type]
		if group == nil {
			group = &boundaryGroup{}
			groups[ev.Type] = group
		}
		group.count++
		if riskForLensEvent(ev) != "" {
			group.risky++
		}
		group.evidence = append(group.evidence, ev.NodeID)
	}
	for _, node := range lensNodesInOrder(nodes) {
		if node.Kind != "snapshot" && node.Kind != "attempt" {
			continue
		}
		key := node.Kind
		group := groups[key]
		if group == nil {
			group = &boundaryGroup{}
			groups[key] = group
		}
		group.count++
		group.evidence = append(group.evidence, node.ID)
	}
	keys := sortedStringKeys(groups)
	out := []GraphLensEdge{}
	for _, key := range keys {
		group := groups[key]
		id := "boundary_group/" + safeGraphID(key)
		nodes[id] = GraphLensNode{ID: id, Kind: "boundary_group", Subtype: key, Label: fmt.Sprintf("%s: %d", key, group.count), Risk: riskIf(group.risky > 0), TrustOrigin: "summary", Data: map[string]any{
			"category": key, "count": group.count, "risky": group.risky,
			"evidence_refs": capStringSlice(group.evidence, 32), "omitted_evidence": maxInt(0, len(group.evidence)-32),
			"drilldown_lens": "sandbox-boundary", "drilldown_detail": "raw", "drilldown_focus": firstString(group.evidence),
		}}
		out = append(out, GraphLensEdge{ID: "summary-boundary-" + safeGraphID(key), FromID: rootID, ToID: id, EdgeType: "run_boundary_group", EvidenceRefs: capStringSlice(group.evidence, 32)})
	}
	return out
}

func networkGroupKey(ev lensEvent) string {
	switch {
	case isTaintSinkEvent(ev):
		return "risky_egress"
	case ev.Type == "dns_query":
		return "dns"
	case strings.HasPrefix(ev.Destination, "127.") || isLoopbackDestination(ev.Destination):
		return "loopback"
	case ev.Type == "tls_read" || ev.Type == "tls_write":
		return "tls"
	default:
		return "network"
	}
}
