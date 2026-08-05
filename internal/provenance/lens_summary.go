package provenance

import (
	"encoding/json"
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
		return buildDataFlowSummaryEdges(events, edges), true
	case "agent-intent":
		return buildIntentDAGEdges(runID, nodes, events, edges), true
	case "substrate":
		return buildSubstrateEdges(runID, nodes, events), true
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

func buildSubstrateEdges(runID string, nodes map[string]GraphLensNode, events map[string]lensEvent) []GraphLensEdge {
	rootID := "run/" + runID
	nodes[rootID] = GraphLensNode{ID: rootID, Kind: "run", Label: runID, Data: map[string]any{"run_id": runID}}
	stats := substrateStats{
		sources: map[string]int{}, scopes: map[string]int{}, cgroups: map[string]int{},
		allCgroups: map[string]int{}, containers: map[string]int{}, allContainers: map[string]int{},
		events: map[string]int{}, pids: map[int64]bool{},
	}
	seenPods := map[string]bool{}
	for _, ev := range lensEventsInOrder(events) {
		if ev.Source == "k8s" && ev.Type == "pod_metadata" {
			// Context event from `sandbox bind-cgroup` enrichment, not runtime
			// telemetry: surfaced as pod nodes, excluded from event counts.
			var pod substratePod
			if err := json.Unmarshal([]byte(ev.Payload), &pod); err == nil && (pod.Name != "" || pod.UID != "") {
				key := pod.Namespace + "/" + pod.Name + "/" + pod.UID
				if !seenPods[key] {
					seenPods[key] = true
					stats.pods = append(stats.pods, pod)
				}
			}
			continue
		}
		if ev.Source != "" {
			stats.sources[ev.Source]++
		}
		if ev.BindingSource != "" {
			stats.scopes[ev.BindingSource]++
		}
		if ev.CgroupID != "" {
			stats.allCgroups[ev.CgroupID]++
			if ev.BindingSource != "" {
				stats.cgroups[ev.CgroupID]++
			}
		}
		if ev.ContainerID != "" {
			stats.allContainers[ev.ContainerID]++
			if ev.BindingSource != "" && !strings.HasPrefix(ev.ContainerID, "agentprov-record-") {
				stats.containers[ev.ContainerID]++
			}
		}
		if ev.Type != "" {
			stats.events[ev.Type]++
		}
		if ev.PID > 0 {
			stats.pids[ev.PID] = true
		}
	}
	profile, profileLabel := substrateProfile(stats)
	if len(stats.cgroups) == 0 {
		stats.cgroups = stats.allCgroups
	}
	if len(stats.containers) == 0 && profile != "k8s-daemonset" {
		stats.containers = stats.allContainers
	}
	scope := topStringKey(stats.scopes)
	if scope == "" {
		scope = "unbound"
	}
	cgroupSample := topStringKey(stats.cgroups)
	if cgroupSample == "" {
		cgroupSample = "none"
	}
	profileID := "substrate/profile/" + safeGraphID(profile)
	nodeID := "substrate/node_group"
	workloadID := "substrate/workload_group"
	cgroupID := "substrate/cgroup_group"
	scopeID := "substrate/scope/" + safeGraphID(scope)
	eventID := "substrate/runtime_event_group"
	nodes[profileID] = GraphLensNode{ID: profileID, Kind: "substrate_profile", Subtype: profile, Label: profileLabel, TrustOrigin: "producer_profile", Data: map[string]any{
		"profile": profile, "sources": summarizeStringCounts(stats.sources, 3), "source_counts": stats.sources,
	}}
	nodes[nodeID] = GraphLensNode{ID: nodeID, Kind: "substrate_node_group", Subtype: "node_sensor", Label: substrateNodeLabel(profile), TrustOrigin: "runtime_observed", Data: map[string]any{
		"producer_profile": profile, "sources": stats.sources,
	}}
	nodes[workloadID] = GraphLensNode{ID: workloadID, Kind: "substrate_workload_group", Subtype: workloadSubtype(profile), Label: substrateWorkloadLabel(profile, len(stats.containers), stats.pods), TrustOrigin: "runtime_observed", Data: map[string]any{
		"containers": len(stats.containers), "known_container_ids": sortedStringKeys(stats.containers), "pods": len(stats.pods), "metadata": workloadMetadataNote(stats.pods),
	}}
	nodes[cgroupID] = GraphLensNode{ID: cgroupID, Kind: "substrate_cgroup_group", Subtype: "cgroup", Label: fmt.Sprintf("cgroups: %d", len(stats.cgroups)), TrustOrigin: "kernel_observed", Data: map[string]any{
		"count": len(stats.cgroups), "sample": cgroupSample, "cgroups": sortedStringKeys(stats.cgroups),
	}}
	nodes[scopeID] = GraphLensNode{ID: scopeID, Kind: "substrate_scope", Subtype: scope, Label: substrateScopeLabel(scope), TrustOrigin: "correlation", Data: map[string]any{
		"binding_source": scope, "confidence": substrateScopeConfidence(scope), "scope_counts": stats.scopes,
	}}
	nodes[eventID] = GraphLensNode{ID: eventID, Kind: "substrate_event_group", Subtype: "runtime_events", Label: fmt.Sprintf("runtime events: %d", sumIntMap(stats.events)), TrustOrigin: "runtime_observed", Data: map[string]any{
		"event_count": sumIntMap(stats.events), "pid_count": len(stats.pids), "top_event_types": topEventTypes(stats.events, 6), "event_counts": stats.events,
		"drilldown_lens": "process", "drilldown_detail": "summary",
	}}
	out := []GraphLensEdge{
		{ID: "substrate-profile-node", FromID: profileID, ToID: nodeID, EdgeType: "producer_runs_on"},
		{ID: "substrate-node-workload", FromID: nodeID, ToID: workloadID, EdgeType: "sensor_observes_workload"},
		{ID: "substrate-workload-cgroup", FromID: workloadID, ToID: cgroupID, EdgeType: "workload_has_cgroup", Data: map[string]any{"cgroup_count": len(stats.cgroups)}},
		{ID: "substrate-cgroup-scope", FromID: cgroupID, ToID: scopeID, EdgeType: "cgroup_binds_scope", Confidence: substrateScopeConfidence(scope)},
		{ID: "substrate-scope-run", FromID: scopeID, ToID: rootID, EdgeType: "scope_binds_run", Confidence: substrateScopeConfidence(scope)},
		{ID: "substrate-cgroup-events", FromID: cgroupID, ToID: eventID, EdgeType: "cgroup_observed_events", Data: map[string]any{"event_count": sumIntMap(stats.events), "pid_count": len(stats.pids)}},
		{ID: "substrate-events-run", FromID: eventID, ToID: rootID, EdgeType: "events_materialize_run"},
	}
	// Per-pod cgroup nodes (so N pods don't collapse onto the single aggregate
	// cgroup node) + indexes for the cross-pod influence pass.
	podByCgroup := map[string]string{} // cgroup_id -> podID
	podByIP := map[string]string{}     // pod_ip    -> podID
	for i, pod := range stats.pods {
		podID := "substrate/pod/" + safeGraphID(podDisplayName(pod))
		nodes[podID] = GraphLensNode{ID: podID, Kind: "substrate_pod", Subtype: "pod", Label: "pod " + podDisplayName(pod), TrustOrigin: "k8s_api_asserted", Data: map[string]any{
			"cluster": pod.Cluster, "node": pod.Node, "pod_name": pod.Name, "namespace": pod.Namespace,
			"container": pod.Container, "image": pod.Image, "service_account": pod.ServiceAccount,
			"labels": pod.Labels, "pod_uid": pod.UID, "cgroup_id": pod.CgroupID, "pod_ip": pod.PodIP,
		}}
		out = append(out, GraphLensEdge{ID: fmt.Sprintf("substrate-workload-pod-%d", i), FromID: workloadID, ToID: podID, EdgeType: "workload_has_pod"})
		if pod.PodIP != "" {
			podByIP[pod.PodIP] = podID
		}
		if pod.CgroupID != "" {
			podByCgroup[pod.CgroupID] = podID
			pcg := "substrate/cgroup/" + safeGraphID(pod.CgroupID)
			nodes[pcg] = GraphLensNode{ID: pcg, Kind: "substrate_cgroup_group", Subtype: "cgroup", Label: "cgroup " + pod.CgroupID, TrustOrigin: "kernel_observed", Data: map[string]any{"cgroup_id": pod.CgroupID, "pod": podDisplayName(pod)}}
			out = append(out,
				GraphLensEdge{ID: fmt.Sprintf("substrate-pod-cgroup-%d", i), FromID: podID, ToID: pcg, EdgeType: "pod_bound_cgroup", Data: map[string]any{"cgroup_id": pod.CgroupID}},
				GraphLensEdge{ID: fmt.Sprintf("substrate-podcgroup-scope-%d", i), FromID: pcg, ToID: scopeID, EdgeType: "cgroup_binds_scope", Confidence: substrateScopeConfidence(scope)},
			)
		}
	}
	// Cross-pod influence: an egress from pod X's cgroup to pod Y's pod IP is a
	// real A2A network call between two pods on this node — kernel ground truth.
	seen := map[string]bool{}
	for _, ev := range lensEventsInOrder(events) {
		if ev.CgroupID == "" || ev.Destination == "" || !isSubstrateEgress(ev.Type) {
			continue
		}
		src, dst := podByCgroup[ev.CgroupID], podByIP[ev.Destination]
		if src == "" || dst == "" || src == dst || seen[src+"->"+dst] {
			continue
		}
		seen[src+"->"+dst] = true
		out = append(out, GraphLensEdge{ID: "substrate-influence-" + safeGraphID(src+"-"+dst), FromID: src, ToID: dst, EdgeType: "pod_influences_pod", Data: map[string]any{"via": ev.Type, "dst_ip": ev.Destination}})
	}
	return out
}

func isSubstrateEgress(t string) bool {
	switch t {
	case "network_connect", "net_connect", "private_cidr", "metadata_ip":
		return true
	}
	return false
}

type substratePod struct {
	Name           string `json:"pod_name"`
	Namespace      string `json:"namespace"`
	Labels         string `json:"labels"`
	UID            string `json:"pod_uid"`
	CgroupID       string `json:"cgroup_id"`
	Cluster        string `json:"cluster"`
	Node           string `json:"node"`
	Container      string `json:"container"`
	Image          string `json:"image"`
	ServiceAccount string `json:"service_account"`
	PodIP          string `json:"pod_ip"`
}

func podDisplayName(pod substratePod) string {
	name := pod.Name
	if name == "" {
		name = pod.UID
	}
	if pod.Namespace != "" {
		name = pod.Namespace + "/" + name
	}
	if pod.Cluster != "" {
		return pod.Cluster + "/" + name
	}
	return name
}

func workloadMetadataNote(pods []substratePod) string {
	if len(pods) > 0 {
		return "pod metadata from bind-cgroup enrichment (k8s api asserted)"
	}
	return "pod/container metadata pending informer enrichment"
}

type substrateStats struct {
	sources       map[string]int
	scopes        map[string]int
	cgroups       map[string]int
	allCgroups    map[string]int
	containers    map[string]int
	allContainers map[string]int
	events        map[string]int
	pids          map[int64]bool
	pods          []substratePod
}

func substrateProfile(stats substrateStats) (profile, label string) {
	if stats.scopes["k8s_cgroup"] > 0 || len(stats.pods) > 0 {
		return "k8s-daemonset", "k8s-daemonset"
	}
	if stats.sources["agentprov_ebpf"] > 0 {
		return "local-vm-sensor", "local/VM sensor"
	}
	if stats.sources["record"] > 0 || stats.sources["record_file_diff"] > 0 {
		return "local-record", "local-record"
	}
	return "evidence-import", "evidence import"
}

func substrateNodeLabel(profile string) string {
	if profile == "k8s-daemonset" {
		return "node sensor group"
	}
	if profile == "local-vm-sensor" {
		return "host sensor"
	}
	return "producer"
}

func workloadSubtype(profile string) string {
	if profile == "k8s-daemonset" {
		return "pod_group"
	}
	return "process_group"
}

func substrateWorkloadLabel(profile string, containers int, pods []substratePod) string {
	if profile == "k8s-daemonset" {
		if len(pods) == 1 {
			return "pod " + podDisplayName(pods[0])
		}
		if len(pods) > 1 {
			return fmt.Sprintf("pod group: %d pods", len(pods))
		}
		if containers > 0 {
			return fmt.Sprintf("pod/container group: %d containers", containers)
		}
		return "pod/container group: metadata pending"
	}
	return "local process workload"
}

func substrateScopeLabel(scope string) string {
	switch scope {
	case "k8s_cgroup":
		return "passive cgroup attribution"
	case "record":
		return "record cgroup leaf"
	case "ai_asserted":
		return "app asserted scope"
	case "unbound":
		return "no explicit scope"
	default:
		return scope
	}
}

func substrateScopeConfidence(scope string) float64 {
	switch scope {
	case "record":
		return 1.0
	case "k8s_cgroup":
		return 0.8
	case "ai_asserted":
		return 0.5
	default:
		return 0
	}
}

func topStringKey(values map[string]int) string {
	best := ""
	bestN := -1
	for _, key := range sortedStringKeys(values) {
		if values[key] > bestN {
			best, bestN = key, values[key]
		}
	}
	return best
}

func summarizeStringCounts(values map[string]int, limit int) []string {
	keys := sortedStringKeys(values)
	if limit > 0 && len(keys) > limit {
		keys = keys[:limit]
	}
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, fmt.Sprintf("%s:%d", key, values[key]))
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
		blocked      int
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
		if strings.Contains(ev.Payload, `"blocked":true`) || strings.Contains(ev.Payload, `"blocked": true`) {
			group.blocked++
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
			"group": key, "count": group.count, "risky": group.risky, "blocked": group.blocked, "destinations": destinations,
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
