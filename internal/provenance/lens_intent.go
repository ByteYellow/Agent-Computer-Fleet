package provenance

import (
	"fmt"
	"sort"
	"strings"
)

func buildIntentDAGEdges(runID string, nodes map[string]GraphLensNode, events map[string]lensEvent, edges []GraphLensEdge) []GraphLensEdge {
	rootID := "run/" + runID
	nodes[rootID] = GraphLensNode{ID: rootID, Kind: "run", Label: runID, Data: map[string]any{"run_id": runID}}
	var promptObj, respObj, llmCall string
	var caused, msgs []string
	for _, e := range edges {
		switch e.EdgeType {
		case "llm_request":
			promptObj, llmCall = e.ToID, e.FromID
		case "llm_response":
			respObj, llmCall = e.ToID, e.FromID
		case "llm_caused":
			caused = append(caused, e.ToID)
		case "agent_message":
			if n, ok := nodes[e.ToID]; ok && (n.Kind == "message" || n.Kind == "relay") {
				msgs = append(msgs, e.ToID)
			}
		}
	}
	if promptObj == "" && respObj == "" {
		// No captured LLM traffic to build a DAG from -> fall back to the
		// per-tool-call execution-scope aggregation so the view isn't empty.
		return buildAgentIntentGroupEdges(runID, nodes, events, edges)
	}
	caused = dedupStrings(caused)
	msgs = dedupStrings(msgs)
	relabel := func(id, prefix string) {
		if n, ok := nodes[id]; ok && !strings.HasPrefix(n.Label, prefix) {
			n.Label = prefix + n.Label
			nodes[id] = n
		}
	}
	relabel(promptObj, "① ")
	relabel(respObj, "② ")
	for _, c := range caused {
		relabel(c, "③ ")
	}
	out := []GraphLensEdge{}
	add := func(id, from, to, et string) {
		if from == "" || to == "" {
			return
		}
		out = append(out, GraphLensEdge{ID: id, FromID: from, ToID: to, EdgeType: et})
	}
	add("dag-run-prompt", rootID, promptObj, "prompt_check")
	add("dag-prompt-call", promptObj, llmCall, "sends")
	add("dag-call-resp", llmCall, respObj, "responds")
	for i, c := range caused {
		add(fmt.Sprintf("dag-caused-%d", i), respObj, c, "caused")
	}
	src := respObj
	if len(caused) > 0 {
		src = caused[0]
	}
	for i, m := range capStringSlice(msgs, 4) {
		add(fmt.Sprintf("dag-send-%d", i), src, m, "send_msg")
	}
	// Blocked intents: the gate-denied Attempt-A exfil and the model refusals.
	// Group each under the agent that proposed it (run → agent → ⊘ blocked …) so
	// the graph tells the whole story -- what was STOPPED at the intent layer, and
	// by which agent -- not only what ran.
	toolAgent := map[string]string{} // tool_call node -> its agent node
	for _, e := range edges {
		if e.EdgeType == "agent_tool_call" {
			toolAgent[e.ToID] = e.FromID
		}
	}
	var refused []string
	for id, n := range nodes {
		if n.Risk == "refused" {
			refused = append(refused, id)
		}
	}
	sort.Strings(refused)
	agentLinked := map[string]bool{}
	for _, id := range refused {
		if n := nodes[id]; !strings.HasPrefix(n.Label, "⊘") {
			n.Label = "⊘ blocked: " + n.Label
			nodes[id] = n
		}
		parent := rootID
		if a := toolAgent[id]; a != "" {
			parent = a
			if !agentLinked[a] {
				agentLinked[a] = true
				add("dag-run-agent-"+safeGraphID(a), rootID, a, "attempted")
			}
		}
		add("dag-refused-"+safeGraphID(id), parent, id, "refused_intent")
	}
	return out
}

func buildAgentIntentGroupEdges(runID string, nodes map[string]GraphLensNode, events map[string]lensEvent, edges []GraphLensEdge) []GraphLensEdge {
	rootID := "run/" + runID
	nodes[rootID] = GraphLensNode{ID: rootID, Kind: "run", Label: runID, Data: map[string]any{"run_id": runID}}
	out := []GraphLensEdge{}

	if hookEdges := buildStandardHookIntentEdges(rootID, nodes, events, edges); len(hookEdges) > 0 {
		return hookEdges
	}

	// Surface the model's action as a readable lifecycle spine (not aggregated),
	// so the summary reads as a plain sequence:
	//   ① prompt check → ② before tool call (decided) → ③ after tool call (caused
	//   syscall) → ④ send msg.
	var promptID, completionID string
	var causedIDs, msgIDs []string
	for _, e := range edges {
		switch e.EdgeType {
		case "llm_request":
			promptID = e.ToID
		case "llm_response":
			completionID = e.ToID
		case "llm_caused":
			causedIDs = append(causedIDs, e.ToID)
		case "agent_message":
			// ④ send msg = the SendMessage hook: peer (sub->sub, e.g. alice->bob)
			// and orchestrator delegation (relay).
			if n, ok := nodes[e.ToID]; ok && (n.Kind == "message" || n.Kind == "relay") {
				msgIDs = append(msgIDs, e.ToID)
			}
		}
	}
	causedIDs = dedupStrings(causedIDs)
	msgIDs = dedupStrings(msgIDs)
	addLC := func(from, to, stage string) {
		if from == "" || to == "" {
			return
		}
		out = append(out, GraphLensEdge{ID: "lc-" + stage + "-" + safeGraphID(to), FromID: from, ToID: to, EdgeType: stage})
	}
	if promptID != "" || completionID != "" {
		prev := rootID
		addLC(prev, promptID, "lc_prompt")
		if promptID != "" {
			prev = promptID
		}
		addLC(prev, completionID, "lc_before_tool")
		if completionID != "" {
			prev = completionID
		}
		for _, c := range causedIDs {
			addLC(prev, c, "lc_after_tool")
		}
		if len(causedIDs) > 0 {
			prev = causedIDs[0]
		}
		for _, m := range capStringSlice(msgIDs, 3) {
			addLC(prev, m, "lc_send_msg")
		}
		// With an explicit lifecycle spine, skip the per-tool-call "execution scope"
		// aggregation so the summary reads as the clean route -- not the old blob.
		return out
	}

	type intentGroup struct {
		toolCallID string
		events     map[string]int
		evidence   []string
	}
	groups := map[string]*intentGroup{}
	for _, ev := range lensEventsInOrder(events) {
		key := fallback(ev.ToolCallID, "unscoped")
		group := groups[key]
		if group == nil {
			group = &intentGroup{toolCallID: ev.ToolCallID, events: map[string]int{}}
			groups[key] = group
		}
		group.events[ev.Type]++
		group.evidence = append(group.evidence, ev.NodeID)
	}
	keys := sortedStringKeys(groups)
	for _, key := range keys {
		group := groups[key]
		if group.toolCallID != "" {
			out = append(out, GraphLensEdge{ID: "summary-intent-tool-" + safeGraphID(group.toolCallID), FromID: rootID, ToID: group.toolCallID, EdgeType: "run_tool_call"})
		}
		id := "intent_group/" + safeGraphID(key)
		label := fmt.Sprintf("execution scope: %d events", sumIntMap(group.events))
		nodes[id] = GraphLensNode{ID: id, Kind: "intent_group", Subtype: "execution_scope", Label: label, TrustOrigin: "summary", Data: map[string]any{
			"tool_call_id": group.toolCallID, "event_count": sumIntMap(group.events), "top_events": topEventTypes(group.events, 6),
			"evidence_refs": capStringSlice(group.evidence, 32), "omitted_evidence": maxInt(0, len(group.evidence)-32),
			"drilldown_lens": "agent-intent", "drilldown_detail": "raw", "drilldown_focus": group.toolCallID,
		}}
		fromID := rootID
		if group.toolCallID != "" {
			fromID = group.toolCallID
		}
		out = append(out, GraphLensEdge{ID: "summary-intent-" + safeGraphID(key), FromID: fromID, ToID: id, EdgeType: "tool_call_intent_group", EvidenceRefs: capStringSlice(group.evidence, 32)})
	}
	return out
}

func buildStandardHookIntentEdges(rootID string, nodes map[string]GraphLensNode, events map[string]lensEvent, edges []GraphLensEdge) []GraphLensEdge {
	var requestObj, responseObj, llmCall string
	caused := []string{}
	msgs := []string{}
	for _, e := range edges {
		switch e.EdgeType {
		case "llm_request":
			llmCall = e.FromID
			requestObj = e.ToID
		case "llm_response":
			if llmCall == "" {
				llmCall = e.FromID
			}
			responseObj = e.ToID
		case "llm_caused":
			caused = append(caused, e.ToID)
		case "agent_message":
			if n, ok := nodes[e.ToID]; ok && (n.Kind == "message" || n.Kind == "relay") {
				msgs = append(msgs, e.ToID)
			}
		}
	}
	if requestObj == "" && responseObj == "" && llmCall == "" {
		return nil
	}
	if llmCall == "" {
		llmCall = "llm_call/" + safeGraphID(firstString([]string{requestObj, responseObj}))
	}
	nodes[llmCall] = GraphLensNode{ID: llmCall, Kind: "llm_call", Label: "LLM call", TrustOrigin: "content_addressed"}
	requestNode := nodes[requestObj]
	responseNode := nodes[responseObj]
	reqPrompt, _ := requestNode.Data["prompt"].(string)
	reqModel, _ := requestNode.Data["model"].(string)
	respCommand, _ := responseNode.Data["command"].(string)
	respModel, _ := responseNode.Data["model"].(string)
	respTools := anyStringSlice(responseNode.Data["tool_decision"])

	stagePrompt := "intent_stage/prompt_check"
	stageBefore := "intent_stage/before_tool_call"
	stageAfter := "intent_stage/after_tool_call"
	stageSend := "intent_stage/send_msg"
	promptLabel := "① prompt check"
	if respCommand != "" {
		promptLabel = "① prompt: " + conciseIntentLabel(respCommand)
	}
	nodes[stagePrompt] = GraphLensNode{ID: stagePrompt, Kind: "intent_stage", Subtype: "prompt_check", Label: promptLabel, TrustOrigin: "summary", Data: map[string]any{"prompt": reqPrompt, "model": reqModel, "intended_command": respCommand}}
	beforeLabel := "② decide"
	if len(respTools) > 0 {
		beforeLabel += ": " + strings.Join(respTools, ", ")
	}
	nodes[stageBefore] = GraphLensNode{ID: stageBefore, Kind: "intent_stage", Subtype: "before_tool_call", Label: beforeLabel, TrustOrigin: "summary", Data: map[string]any{"tool_decision": respTools, "command": respCommand, "model": respModel}}
	nodes[stageAfter] = GraphLensNode{ID: stageAfter, Kind: "intent_stage", Subtype: "after_tool_call", Label: "③ observe runtime", TrustOrigin: "summary", Data: map[string]any{"command": respCommand}}
	nodes[stageSend] = GraphLensNode{ID: stageSend, Kind: "intent_stage", Subtype: "send_msg", Label: fmt.Sprintf("④ send msg: %d peer edges", len(dedupStrings(msgs))), TrustOrigin: "summary", Data: map[string]any{"message_edges": len(dedupStrings(msgs))}}

	if n, ok := nodes[requestObj]; ok {
		n.Label = "LLM request"
		if reqModel != "" {
			n.Label += " [" + reqModel + "]"
		}
		nodes[requestObj] = n
	}
	if n, ok := nodes[responseObj]; ok {
		n.Label = "LLM response"
		if len(respTools) > 0 {
			n.Label += " · " + strings.Join(respTools, ", ")
		}
		if respModel != "" {
			n.Label += " [" + respModel + "]"
		}
		nodes[responseObj] = n
	}

	out := []GraphLensEdge{}
	add := func(id, from, to, typ string) {
		if from == "" || to == "" {
			return
		}
		out = append(out, GraphLensEdge{ID: id, FromID: from, ToID: to, EdgeType: typ})
	}
	add("intent-root-prompt", rootID, stagePrompt, "intent_stage")
	add("intent-prompt-request", stagePrompt, requestObj, "prompt_check")
	add("intent-request-call", requestObj, llmCall, "llm_request")
	add("intent-call-before", llmCall, stageBefore, "intent_stage")
	add("intent-before-response", stageBefore, responseObj, "llm_response")
	add("intent-response-after", responseObj, stageAfter, "intent_stage")

	if groupID := addAfterToolAggregateNode(nodes, events); groupID != "" {
		add("intent-after-runtime-group", stageAfter, groupID, "after_tool_call_summary")
	}
	for i, id := range pickAfterToolActions(caused, events, 3) {
		if ev, ok := events[id]; ok {
			if n, ok := nodes[id]; ok {
				if cmd := payloadString(ev.Payload, "command", "cmdline", "comm"); cmd != "" {
					n.Label = conciseCommandLabel(cmd)
					nodes[id] = n
				}
			}
		}
		add(fmt.Sprintf("intent-after-exec-%d", i), stageAfter, id, "after_tool_call")
	}
	selectedMsgs := capStringSlice(dedupStrings(msgs), 3)
	if len(selectedMsgs) > 0 {
		add("intent-after-send", stageAfter, stageSend, "intent_stage")
		for i, id := range selectedMsgs {
			add(fmt.Sprintf("intent-send-msg-%d", i), stageSend, id, "send_msg")
		}
	}
	return out
}

func addAfterToolAggregateNode(nodes map[string]GraphLensNode, events map[string]lensEvent) string {
	counts := map[string]int{}
	evidence := []string{}
	for _, ev := range lensEventsInOrder(events) {
		switch ev.Type {
		case "execve":
			if !isObserverNoiseCommand(strings.ToLower(payloadString(ev.Payload, "command", "cmdline", "comm"))) {
				counts["execve"]++
				evidence = append(evidence, ev.NodeID)
			}
		case "process_observed":
			counts["process"]++
			evidence = append(evidence, ev.NodeID)
		case "secret_path", "metadata_ip", "private_cidr":
			counts["risk"]++
			evidence = append(evidence, ev.NodeID)
		}
	}
	total := counts["execve"] + counts["process"] + counts["risk"]
	if total == 0 {
		return ""
	}
	id := "event_burst/after_tool_runtime"
	label := fmt.Sprintf("%d exec / %d proc / %d risk", counts["execve"], counts["process"], counts["risk"])
	nodes[id] = GraphLensNode{
		ID:          id,
		Kind:        "event_burst",
		Subtype:     "after_tool_runtime",
		Label:       label,
		Risk:        riskIf(counts["risk"] > 0),
		TrustOrigin: "summary",
		Data: map[string]any{
			"execve": counts["execve"], "process": counts["process"], "risk": counts["risk"],
			"evidence_refs": capStringSlice(evidence, 32), "omitted_evidence": maxInt(0, len(evidence)-32),
			"drilldown_lens": "agent-intent", "drilldown_detail": "raw", "drilldown_focus": firstString(evidence),
		},
	}
	return id
}

func pickAfterToolActions(caused []string, events map[string]lensEvent, limit int) []string {
	setup := []string{}
	risks := []string{}
	preferred := []string{}
	fallbacks := []string{}
	seen := map[string]bool{}
	for _, ev := range lensEventsInOrder(events) {
		cmd := strings.ToLower(payloadString(ev.Payload, "command", "cmdline", "comm"))
		if (ev.Type == "execve" || ev.Type == "process_observed") && strings.Contains(cmd, "setup.py") {
			setup = append(setup, ev.NodeID)
		}
		if ev.Type == "secret_path" || ev.Type == "metadata_ip" {
			risks = append(risks, ev.NodeID)
		}
	}
	for _, id := range caused {
		if seen[id] {
			continue
		}
		seen[id] = true
		ev, ok := events[id]
		if !ok || ev.Type != "execve" {
			continue
		}
		cmd := strings.ToLower(payloadString(ev.Payload, "command", "cmdline", "comm"))
		if isObserverNoiseCommand(cmd) {
			continue
		}
		if strings.Contains(cmd, "setup.py") || strings.Contains(cmd, "install") || strings.Contains(cmd, "python3") || strings.Contains(cmd, "claude") {
			preferred = append(preferred, id)
		} else {
			fallbacks = append(fallbacks, id)
		}
	}
	out := append(dedupStrings(setup), dedupStrings(risks)...)
	out = append(out, preferred...)
	out = append(out, fallbacks...)
	return capStringSlice(out, limit)
}

func isObserverNoiseCommand(cmd string) bool {
	for _, noise := range []string{
		"ps -ao pid=,ppid=,command=",
		"ps aux",
		"grep -v grep",
		"agentprovenance/demo/shared/llm-intent-curl.sh",
		"head -c ",
		"/usr/bin/rm",
		"mktemp",
	} {
		if strings.Contains(cmd, noise) {
			return true
		}
	}
	return false
}

func ensurePrefix(label, prefix string) string {
	if strings.HasPrefix(label, prefix) {
		return label
	}
	if label == "" {
		return prefix
	}
	if strings.Contains(label, "[") {
		return prefix + " " + label[strings.Index(label, "["):]
	}
	return prefix + " · " + label
}

func conciseCommandLabel(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	cmd = strings.Join(strings.Fields(cmd), " ")
	if len(cmd) <= 56 {
		return cmd
	}
	return cmd[:53] + "..."
}

func conciseIntentLabel(cmd string) string {
	cmd = conciseCommandLabel(cmd)
	for _, prefix := range []string{"python3 ", "python ", "/bin/bash -c "} {
		cmd = strings.TrimPrefix(cmd, prefix)
	}
	return cmd
}

func anyStringSlice(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
