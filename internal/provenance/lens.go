package provenance

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
)

const graphLensSchemaVersion = "agentprovenance.graph_lens/v1"

var availableGraphLenses = []string{
	"default",
	"security",
	"process",
	"file-artifact",
	"network-egress",
	"data-flow-taint",
	"agent-intent",
	"orchestration",
	"trust-origin",
	"sandbox-boundary",
}

type GraphLensOptions struct {
	RunID    string
	Lens     string
	Focus    string
	Overlays []string
	Limit    int
	Detail   string
}

type GraphLensManifest struct {
	SchemaVersion   string             `json:"schema_version"`
	RunID           string             `json:"run_id"`
	Lens            string             `json:"lens"`
	AvailableLenses []string           `json:"available_lenses"`
	Query           GraphLensQuery     `json:"query"`
	Summary         []string           `json:"summary"`
	Nodes           []GraphLensNode    `json:"nodes"`
	Edges           []GraphLensEdge    `json:"edges"`
	DerivedEdges    []GraphLensEdge    `json:"derived_edges,omitempty"`
	Overlays        []GraphLensOverlay `json:"overlays,omitempty"`
}

type GraphLensQuery struct {
	Focus         string   `json:"focus,omitempty"`
	Overlays      []string `json:"overlays,omitempty"`
	Limit         int      `json:"limit"`
	Detail        string   `json:"detail"`
	Truncated     bool     `json:"truncated"`
	NodeCount     int      `json:"node_count"`
	EdgeCount     int      `json:"edge_count"`
	Derived       int      `json:"derived_edge_count"`
	RawEventCount int      `json:"raw_event_count"`
	OmittedNodes  int      `json:"omitted_nodes,omitempty"`
	OmittedEdges  int      `json:"omitted_edges,omitempty"`
	LensRules     []string `json:"lens_rules"`
	LayoutHint    string   `json:"layout_hint"`
}

type GraphLensNode struct {
	ID          string         `json:"id"`
	Kind        string         `json:"kind"`
	Subtype     string         `json:"subtype,omitempty"`
	Label       string         `json:"label"`
	TrustOrigin string         `json:"trust_origin,omitempty"`
	Risk        string         `json:"risk,omitempty"`
	Data        map[string]any `json:"data,omitempty"`
}

type GraphLensEdge struct {
	ID             string         `json:"id,omitempty"`
	FromID         string         `json:"from_id"`
	ToID           string         `json:"to_id"`
	EdgeType       string         `json:"edge_type"`
	SourceEventID  string         `json:"source_event_id,omitempty"`
	CreatedAt      string         `json:"created_at,omitempty"`
	Derived        bool           `json:"derived"`
	DerivationRule string         `json:"derivation_rule,omitempty"`
	Confidence     float64        `json:"confidence,omitempty"`
	EvidenceRefs   []string       `json:"evidence_refs,omitempty"`
	Data           map[string]any `json:"data,omitempty"`
}

type GraphLensOverlay struct {
	TargetID string         `json:"target_id"`
	Kind     string         `json:"kind"`
	Label    string         `json:"label"`
	Severity string         `json:"severity,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
}

type lensEvent struct {
	ID          string
	NodeID      string
	Type        string
	ProcessID   string
	ToolCallID  string
	SessionID   string
	SnapshotID  string
	PID         int64
	PPID        int64
	Source      string
	Payload     string
	CreatedAt   string
	Path        string
	Destination string
	TGID        int64
}

type processGroup struct {
	toolCall string
	pids     map[int64]bool
	events   map[string]int
	shells   int
	python   int
	git      int
	packageM int
	risky    int
	writes   int
	egress   int
}

type ruleGroup struct {
	count     int
	decision  string
	severity  string
	action    string
	evidence  []string
	eventType string
}

func BuildGraphLens(db *sql.DB, opts GraphLensOptions) (GraphLensManifest, error) {
	opts.RunID = strings.TrimSpace(opts.RunID)
	if opts.RunID == "" {
		return GraphLensManifest{}, fmt.Errorf("--run is required")
	}
	lens := normalizeGraphLens(opts.Lens)
	detail := normalizeGraphLensDetail(opts.Detail)
	if opts.Limit <= 0 {
		// 350 keeps the graph light enough to lay out + render fast on a lens
		// switch while still fitting all the prioritized semantic edges (product
		// lineage + policy/risk/response); the runtime_event/process skeleton is
		// what gets trimmed, and it is the least informative part.
		opts.Limit = 350
	}
	nodes, events, err := graphLensNodes(db, opts.RunID)
	if err != nil {
		return GraphLensManifest{}, err
	}
	edges, err := graphLensEdges(db, opts.RunID)
	if err != nil {
		return GraphLensManifest{}, err
	}
	derived := deriveGraphLensEdges(lens, events, detail)
	allEdges := append(edges, derived...)
	filteredEdges, summarized := summaryLensEdges(opts.RunID, lens, opts.Focus, detail, nodes, events, allEdges)
	if !summarized {
		filteredEdges = filterGraphLensEdges(lens, opts.Focus, detail, nodes, events, allEdges)
	}
	manifest := GraphLensManifest{
		SchemaVersion:   graphLensSchemaVersion,
		RunID:           opts.RunID,
		Lens:            lens,
		AvailableLenses: append([]string{}, availableGraphLenses...),
		Query: GraphLensQuery{
			Focus:         opts.Focus,
			Overlays:      cleanOverlays(opts.Overlays),
			Limit:         opts.Limit,
			Detail:        detail,
			RawEventCount: len(events),
			LensRules:     graphLensRules(lens),
			LayoutHint:    graphLensLayout(lens),
		},
	}
	// Prioritize edges so that when the budget truncates the runtime_event/
	// runtime_process BULK, edges incident to semantically important nodes
	// (policy_decision / response_action / risk_signal / file / artifact /
	// tool_call / snapshot / attempt / rollout / process) survive. Without this
	// the bulk ate the whole edge budget and those nodes were returned but
	// ORPHANED -- appearing as disconnected, mis-positioned floaters.
	prioritizeLensEdges(filteredEdges, nodes)
	manifest.Edges, manifest.DerivedEdges, manifest.Query.Truncated = splitAndLimitLensEdges(filteredEdges, opts.Limit)
	// Build the visible node set from the RETURNED edges only, so no node is ever
	// shown without a connecting edge. (Previously `used` was built from every
	// pre-truncation edge, so a node whose only edge fell past the cut still
	// appeared -- floating.) Genuinely edgeless nodes are dropped rather than
	// left disconnected; drill/focus recovers detail for a specific node.
	used := map[string]bool{}
	for _, edge := range append(append([]GraphLensEdge{}, manifest.Edges...), manifest.DerivedEdges...) {
		if edge.EdgeType == "possible_sensitive_data_flow_summary" && edge.ToID != "" {
			nodes[edge.ToID] = egressGroupNode(edge)
		}
		used[edge.FromID] = true
		used[edge.ToID] = true
		// NOTE: the edge's SourceEventID is intentionally NOT added as a node --
		// it is reachable via the edge's source_event_id for drill-down, and
		// adding it as a bare node (with no edge of its own returned) reintroduces
		// a floating runtime_event. Only actual edge endpoints become nodes.
	}
	if opts.Focus != "" {
		used[opts.Focus] = true
	}
	manifest.Nodes = sortedLensNodes(nodes, used)
	manifest.Query.NodeCount = len(manifest.Nodes)
	manifest.Query.EdgeCount = len(manifest.Edges) + len(manifest.DerivedEdges)
	manifest.Query.Derived = len(manifest.DerivedEdges)
	manifest.Query.OmittedNodes = maxInt(0, len(nodes)-manifest.Query.NodeCount)
	manifest.Query.OmittedEdges = maxInt(0, len(allEdges)-manifest.Query.EdgeCount)
	manifest.Overlays = buildGraphLensOverlays(nodes, manifest.Nodes, manifest.Query.Overlays)
	manifest.Summary = []string{
		fmt.Sprintf("lens=%s layout=%s", manifest.Lens, manifest.Query.LayoutHint),
		fmt.Sprintf("detail=%s raw_events=%d nodes=%d edges=%d derived_edges=%d omitted_nodes=%d omitted_edges=%d",
			manifest.Query.Detail, manifest.Query.RawEventCount, manifest.Query.NodeCount, len(manifest.Edges), len(manifest.DerivedEdges),
			manifest.Query.OmittedNodes, manifest.Query.OmittedEdges),
	}
	return manifest, nil
}

func GraphLensJSON(db *sql.DB, opts GraphLensOptions, out io.Writer) error {
	manifest, err := BuildGraphLens(db, opts)
	if err != nil {
		return err
	}
	return PrintGraphLensManifestJSON(out, manifest)
}

func PrintGraphLensManifestJSON(out io.Writer, manifest GraphLensManifest) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(manifest)
}

func GraphLens(db *sql.DB, opts GraphLensOptions, out io.Writer) error {
	manifest, err := BuildGraphLens(db, opts)
	if err != nil {
		return err
	}
	return PrintGraphLensManifest(out, manifest)
}

func PrintGraphLensManifest(out io.Writer, manifest GraphLensManifest) error {
	fmt.Fprintf(out, "graph_lens run=%s lens=%s schema=%s nodes=%d edges=%d derived=%d layout=%s truncated=%t\n",
		manifest.RunID, manifest.Lens, manifest.SchemaVersion, manifest.Query.NodeCount,
		len(manifest.Edges), len(manifest.DerivedEdges), manifest.Query.LayoutHint, manifest.Query.Truncated)
	for _, line := range manifest.Summary {
		fmt.Fprintf(out, "  summary=%s\n", line)
	}
	for _, edge := range manifest.DerivedEdges {
		fmt.Fprintf(out, "  derived_edge=%s %s -> %s confidence=%.2f rule=%s evidence=%s\n",
			edge.EdgeType, edge.FromID, edge.ToID, edge.Confidence, edge.DerivationRule, strings.Join(edge.EvidenceRefs, ","))
	}
	for _, edge := range manifest.Edges {
		fmt.Fprintf(out, "  edge=%s %s -> %s source_event=%s\n", edge.EdgeType, edge.FromID, edge.ToID, edge.SourceEventID)
	}
	return nil
}

func normalizeGraphLens(lens string) string {
	lens = strings.ToLower(strings.TrimSpace(lens))
	if lens == "" {
		return "default"
	}
	for _, allowed := range availableGraphLenses {
		if lens == allowed {
			return lens
		}
	}
	return "default"
}

func normalizeGraphLensDetail(detail string) string {
	switch strings.ToLower(strings.TrimSpace(detail)) {
	case "raw", "expanded":
		return strings.ToLower(strings.TrimSpace(detail))
	default:
		return "summary"
	}
}

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

// llmMetaCache memoizes parsed llm_message metadata by object-file path. Object
// files are content-addressed and immutable, so a path always maps to the same
// content -- caching avoids re-reading every object on every lens refresh.
var llmMetaCache sync.Map // path -> [2]any{model string, tools []string}

// llmMessageMeta reads a stored llm_message object file and pulls out the model
// and the model's decided tool names. Best-effort: any read/parse failure (e.g. a
// bundle imported without its object files) degrades to a bare label.
func llmMessageMeta(path string) (model string, tools []string) {
	if path == "" {
		return "", nil
	}
	if v, ok := llmMetaCache.Load(path); ok {
		c := v.([2]any)
		m, _ := c[0].(string)
		t, _ := c[1].([]string)
		return m, t
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", nil
	}
	var obj struct {
		Payload struct {
			Model     string `json:"model"`
			Semantics struct {
				ToolCalls []string `json:"tool_calls"`
			} `json:"semantics"`
		} `json:"payload"`
	}
	if json.Unmarshal(raw, &obj) != nil {
		return "", nil
	}
	llmMetaCache.Store(path, [2]any{obj.Payload.Model, obj.Payload.Semantics.ToolCalls})
	return obj.Payload.Model, obj.Payload.Semantics.ToolCalls
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
			model, tools := llmMessageMeta(path)
			kind, label := "llm_prompt", "LLM request"
			if strings.HasPrefix(sourceID, "llm_response/") {
				kind, label = "llm_completion", "LLM response"
				if len(tools) > 0 {
					label += " · decided: " + strings.Join(tools, ", ")
				}
			}
			if model != "" {
				label += "  [" + model + "]"
			}
			add(GraphLensNode{
				ID: hash, Kind: kind, Subtype: "llm_message", Label: label,
				TrustOrigin: "content_addressed",
				Data:        map[string]any{"hash": hash, "source_id": sourceID, "path": path, "model": model, "tool_decision": tools},
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
		return buildAgentIntentGroupEdges(runID, nodes, events), true
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
		{"overview/tool_calls", fmt.Sprintf("Tool calls: %d", counts.ToolCalls), "tool_calls", "", map[string]any{"count": counts.ToolCalls, "drilldown_lens": "agent-intent", "drilldown_detail": "summary"}},
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
	for _, node := range nodes {
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
	for _, ev := range events {
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
	for _, ev := range events {
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

func buildDataFlowSummaryEdges(events map[string]lensEvent) []GraphLensEdge {
	sources := make([]lensEvent, 0)
	sinks := make([]lensEvent, 0)
	for _, ev := range events {
		if isSourceEvent(ev.Type, ev.Path) {
			sources = append(sources, ev)
		}
		if isTaintSinkEvent(ev) {
			sinks = append(sinks, ev)
		}
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].CreatedAt < sources[j].CreatedAt })
	sort.Slice(sinks, func(i, j int) bool { return sinks[i].CreatedAt < sinks[j].CreatedAt })
	return deriveAggregatedDataFlowEdges(sources, sinks)
}

func buildAgentIntentGroupEdges(runID string, nodes map[string]GraphLensNode, events map[string]lensEvent) []GraphLensEdge {
	rootID := "run/" + runID
	nodes[rootID] = GraphLensNode{ID: rootID, Kind: "run", Label: runID, Data: map[string]any{"run_id": runID}}
	type intentGroup struct {
		toolCallID string
		events     map[string]int
		evidence   []string
	}
	groups := map[string]*intentGroup{}
	for _, ev := range events {
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
	out := []GraphLensEdge{}
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

func buildTrustOriginGroupEdges(runID string, nodes map[string]GraphLensNode) []GraphLensEdge {
	rootID := "run/" + runID
	nodes[rootID] = GraphLensNode{ID: rootID, Kind: "run", Label: runID, Data: map[string]any{"run_id": runID}}
	type originGroup struct {
		count    int
		kinds    map[string]int
		evidence []string
	}
	groups := map[string]*originGroup{}
	for id, node := range nodes {
		if id == rootID || node.TrustOrigin == "" || node.TrustOrigin == "summary" {
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
		group.evidence = append(group.evidence, id)
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
	for _, ev := range events {
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
	for id, node := range nodes {
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
		group.evidence = append(group.evidence, id)
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
		"agent_spawn", "agent_message", "agent_tool_call", "agent_syscall":
		return true
	default:
		return strings.Contains(edgeType, "policy") || strings.Contains(edgeType, "risk") ||
			strings.Contains(edgeType, "response") || strings.Contains(edgeType, "artifact")
	}
}

func isGraphValueNode(node GraphLensNode) bool {
	switch node.Kind {
	case "tool_call", "process", "artifact", "file", "policy_decision", "risk_signal", "response_action", "attempt", "snapshot", "agent", "message", "relay", "llm_call", "llm_prompt", "llm_completion":
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

func deriveGraphLensEdges(lens string, events map[string]lensEvent, detail string) []GraphLensEdge {
	if lens != "data-flow-taint" && lens != "security" && lens != "default" {
		return nil
	}
	sources := make([]lensEvent, 0)
	sinks := make([]lensEvent, 0)
	for _, ev := range events {
		if isSourceEvent(ev.Type, ev.Path) {
			sources = append(sources, ev)
		}
		if isTaintSinkEvent(ev) {
			sinks = append(sinks, ev)
		}
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].CreatedAt < sources[j].CreatedAt })
	sort.Slice(sinks, func(i, j int) bool { return sinks[i].CreatedAt < sinks[j].CreatedAt })
	if detail == "summary" {
		return deriveAggregatedDataFlowEdges(sources, sinks)
	}
	var derived []GraphLensEdge
	seen := map[string]bool{}
	for _, src := range sources {
		for _, sink := range sinks {
			// A data flow can only run forward in time: the secret must be read
			// before it can leave over the network. Skip sinks that happened at
			// or before the source so we never draw a temporally impossible edge
			// (e.g. an egress that preceded the secret read).
			if src.CreatedAt != "" && sink.CreatedAt != "" && sink.CreatedAt <= src.CreatedAt {
				continue
			}
			_, _, rule, conf := taintFlowScope(src, sink, true)
			if conf == 0 {
				continue
			}
			key := src.NodeID + "|" + sink.NodeID + "|" + rule
			if seen[key] {
				continue
			}
			seen[key] = true
			derived = append(derived, GraphLensEdge{
				ID:       "derived/" + key,
				FromID:   src.NodeID,
				ToID:     sink.NodeID,
				EdgeType: "possible_sensitive_data_flow",
				// Stamp the inferred flow with the sink's time so a time-scrubbed
				// replay surfaces it at the moment the data actually left.
				CreatedAt:      sink.CreatedAt,
				Derived:        true,
				DerivationRule: rule,
				Confidence:     conf,
				EvidenceRefs:   []string{src.NodeID, sink.NodeID},
			})
		}
	}
	return derived
}

func deriveAggregatedDataFlowEdges(sources, sinks []lensEvent) []GraphLensEdge {
	type flowGroup struct {
		fromID       string
		toID         string
		rule         string
		confidence   float64
		createdAt    string
		sourceRefs   map[string]bool
		sinkRefs     map[string]bool
		paths        map[string]bool
		destinations map[string]bool
	}
	groups := map[string]*flowGroup{}
	for _, src := range sources {
		for _, sink := range sinks {
			if src.CreatedAt != "" && sink.CreatedAt != "" && sink.CreatedAt <= src.CreatedAt {
				continue
			}
			scopeID, scopeKey, baseRule, conf := taintFlowScope(src, sink, false)
			if scopeID == "" {
				continue
			}
			rule := strings.Replace(baseRule, ".v1", ".aggregate.v1", 1)
			toID := "egress_group/" + safeGraphID(scopeKey)
			key := scopeKey + "|" + rule
			group := groups[key]
			if group == nil {
				group = &flowGroup{
					fromID:       scopeID,
					toID:         toID,
					rule:         rule,
					confidence:   conf,
					sourceRefs:   map[string]bool{},
					sinkRefs:     map[string]bool{},
					paths:        map[string]bool{},
					destinations: map[string]bool{},
				}
				groups[key] = group
			}
			if group.createdAt == "" || (sink.CreatedAt != "" && sink.CreatedAt > group.createdAt) {
				group.createdAt = sink.CreatedAt
			}
			group.sourceRefs[src.NodeID] = true
			group.sinkRefs[sink.NodeID] = true
			if src.Path != "" {
				group.paths[src.Path] = true
			}
			if sink.Destination != "" {
				group.destinations[sink.Destination] = true
			}
		}
	}
	out := make([]GraphLensEdge, 0, len(groups))
	for key, group := range groups {
		refs := append(sortedBoolKeys(group.sourceRefs), sortedBoolKeys(group.sinkRefs)...)
		out = append(out, GraphLensEdge{
			ID:             "derived/" + safeGraphID(key),
			FromID:         group.fromID,
			ToID:           group.toID,
			EdgeType:       "possible_sensitive_data_flow_summary",
			CreatedAt:      group.createdAt,
			Derived:        true,
			DerivationRule: group.rule,
			Confidence:     group.confidence,
			EvidenceRefs:   capStringSlice(refs, 80),
			Data: map[string]any{
				"source_count":       len(group.sourceRefs),
				"sink_count":         len(group.sinkRefs),
				"omitted_evidence":   maxInt(0, len(refs)-80),
				"sensitive_paths":    capStringSlice(sortedBoolKeys(group.paths), 12),
				"destinations":       capStringSlice(sortedBoolKeys(group.destinations), 12),
				"source_event_count": len(group.sourceRefs),
				"sink_event_count":   len(group.sinkRefs),
			},
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt < out[j].CreatedAt
		}
		return out[i].ID < out[j].ID
	})
	return out
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
		return []string{"llm_call", "llm_intent_caused", "tool_call edges"}
	case "orchestration":
		return []string{"agent_spawn (delegation)", "agent_message (peer, body objectified)", "each agent's tool calls incl. refused proposals"}
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

func isSecurityKind(kind string) bool {
	return kind == "policy_decision" || kind == "risk_signal" || kind == "response_action"
}

func isNetworkEvent(eventType string) bool {
	switch eventType {
	case "network_connect", "metadata_ip", "private_cidr", "dns_query", "tls_write", "tls_read":
		return true
	default:
		return false
	}
}

func isSourceEvent(eventType, path string) bool {
	if eventType == "secret_path" {
		return true
	}
	if eventType != "file_open" {
		return false
	}
	path = strings.ToLower(path)
	return strings.Contains(path, ".ssh") || strings.Contains(path, ".aws") || strings.Contains(path, "credential") || strings.Contains(path, "secret") || strings.Contains(path, "token")
}

// taintFlowScope returns the scope a (source, sink) pair shares for a sensitive
// data-flow edge — the from-node, a grouping key, the rule and confidence. It
// prefers the OS pid (an exfiltration happens within ONE process, and the
// correlated process_id can be a single coarse id for a whole captured run), then
// falls back to process_id and tool_call for events without a pid. Returns conf=0
// when the pair shares no scope (so they are not a flow).
func taintFlowScope(src, sink lensEvent, allowFallback bool) (fromNode, scopeKey, rule string, conf float64) {
	switch {
	case src.PID > 0 && sink.PID > 0:
		if src.PID != sink.PID {
			return "", "", "", 0
		}
		return fmt.Sprintf("runtime_process/pid/%d", src.PID), fmt.Sprintf("pid:%d", src.PID),
			"dataflow.same_process.secret_to_network.v1", 0.82
	case allowFallback && src.ProcessID != "" && src.ProcessID == sink.ProcessID:
		return src.ProcessID, "process:" + src.ProcessID, "dataflow.same_process.secret_to_network.v1", 0.8
	case allowFallback && src.ToolCallID != "" && src.ToolCallID == sink.ToolCallID:
		return src.ToolCallID, "tool_call:" + src.ToolCallID, "dataflow.same_tool_call.risky_egress.v1", 0.52
	}
	return "", "", "", 0
}

// isLoopbackDestination reports whether a destination is the local host (e.g. the
// systemd-resolved DNS stub 127.0.0.53) — local traffic is not exfiltration.
func isLoopbackDestination(destination string) bool {
	host := strings.Trim(strings.TrimSpace(destination), "[]")
	if i := strings.LastIndex(host, ":"); i > 0 && strings.Count(host, ":") == 1 {
		host = host[:i]
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

func isTaintSinkEvent(ev lensEvent) bool {
	// A connection to localhost is not exfiltration, even if an upstream classifier
	// tagged it private_cidr (127.0.0.0/8 is loopback, not an RFC1918 private net).
	if isLoopbackDestination(ev.Destination) {
		return false
	}
	switch ev.Type {
	case "metadata_ip", "private_cidr", "network_deny", "egress_deny":
		return true
	case "network_connect", "tls_write":
		if isMetadataOrPrivateDestination(ev.Destination) {
			return true
		}
		decision := strings.ToLower(payloadString(ev.Payload, "decision", "policy_decision", "action"))
		severity := strings.ToLower(payloadString(ev.Payload, "severity", "risk", "level"))
		return decision == "deny" || decision == "quarantine" || decision == "kill" || severity == "high" || severity == "critical"
	default:
		return false
	}
}

func isMetadataOrPrivateDestination(destination string) bool {
	destination = strings.TrimSpace(destination)
	if destination == "" {
		return false
	}
	host := strings.Trim(destination, "[]")
	if i := strings.LastIndex(host, ":"); i > 0 && strings.Count(host, ":") == 1 {
		host = host[:i]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return strings.EqualFold(host, "169.254.169.254")
	}
	if addr.Is4() && addr.String() == "169.254.169.254" {
		return true
	}
	return addr.IsPrivate()
}

func isBoundaryEvent(eventType string) bool {
	switch eventType {
	case "setuid", "setgid", "ptrace", "abnormal_process_tree", "file_rename", "file_unlink", "metadata_ip", "private_cidr":
		return true
	default:
		return false
	}
}

func riskForEventType(eventType string) string {
	switch eventType {
	case "metadata_ip", "private_cidr", "secret_path", "abnormal_process_tree", "setuid", "setgid", "ptrace":
		return "high"
	case "file_rename", "file_unlink":
		return "medium"
	default:
		return ""
	}
}

func riskForLensEvent(ev lensEvent) string {
	if ev.Type == "private_cidr" && isLoopbackDestination(ev.Destination) {
		return ""
	}
	return riskForEventType(ev.Type)
}

func isRiskyNetworkSummaryEvent(ev lensEvent) bool {
	if !isNetworkEvent(ev.Type) {
		return false
	}
	if isLoopbackDestination(ev.Destination) {
		return false
	}
	return isTaintSinkEvent(ev) || riskForLensEvent(ev) != ""
}

func riskForDecision(decision string) string {
	switch strings.ToLower(decision) {
	case "deny", "kill", "quarantine", "taint_snapshot":
		return "high"
	case "audit":
		return "medium"
	default:
		return ""
	}
}

// lensEventLabel makes a runtime event self-explanatory: instead of a bare event
// type ("secret_path", "metadata_ip"), show WHAT it touched, so the exfil reads at
// a glance -- "secret_path .aws/credentials", "metadata_ip 169.254.169.254".
func lensEventLabel(ev lensEvent) string {
	switch ev.Type {
	case "secret_path", "file_open", "file_write":
		if p := shortPathTail(ev.Path); p != "" {
			return ev.Type + " " + p
		}
	case "metadata_ip", "private_cidr", "network_connect", "dns_query":
		if ev.Destination != "" {
			return ev.Type + " " + ev.Destination
		}
	case "execve":
		if c := payloadString(ev.Payload, "command", "cmdline", "comm"); c != "" {
			return shortLabel(c, ev.Type)
		}
	}
	return ev.Type
}

// shortPathTail returns the last two path segments (".aws/credentials"), enough to
// identify the file without the noisy absolute prefix.
func shortPathTail(p string) string {
	p = strings.TrimRight(p, "/")
	if p == "" {
		return ""
	}
	segs := strings.Split(p, "/")
	if len(segs) >= 2 {
		return segs[len(segs)-2] + "/" + segs[len(segs)-1]
	}
	return segs[len(segs)-1]
}

func payloadString(payload string, keys ...string) string {
	var top map[string]any
	if json.Unmarshal([]byte(payload), &top) != nil {
		return ""
	}
	if inner, ok := top["payload"].(map[string]any); ok {
		top = inner
	}
	if raw, ok := top["raw"].(map[string]any); ok {
		top = raw
	}
	for _, key := range keys {
		if v, ok := top[key]; ok {
			switch typed := v.(type) {
			case string:
				return typed
			case float64:
				return fmt.Sprintf("%.0f", typed)
			}
		}
	}
	return ""
}

func sortedBoolKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func sortedStringKeys[T any](values map[string]T) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func capStringSlice(values []string, limit int) []string {
	if limit <= 0 || len(values) <= limit {
		return values
	}
	return append([]string{}, values[:limit]...)
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func stringsFromEdgeData(data map[string]any, key string) []string {
	if data == nil {
		return nil
	}
	value := data[key]
	switch v := value.(type) {
	case []string:
		return append([]string{}, v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func sortedProcessGroupKeys(groups map[string]*processGroup) []string {
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedRuleGroupKeys(groups map[string]*ruleGroup) []string {
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func topEventTypes(counts map[string]int, limit int) []string {
	type pair struct {
		key   string
		count int
	}
	pairs := make([]pair, 0, len(counts))
	for key, count := range counts {
		pairs = append(pairs, pair{key: key, count: count})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return pairs[i].key < pairs[j].key
	})
	if limit > 0 && len(pairs) > limit {
		pairs = pairs[:limit]
	}
	out := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		out = append(out, pair.key)
	}
	return out
}

func sumIntMap(values map[string]int) int {
	total := 0
	for _, value := range values {
		total += value
	}
	return total
}

func filePathCategory(path string) string {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "node_modules/"), strings.Contains(p, ".venv/"), strings.Contains(p, "site-packages/"), strings.Contains(p, "__pycache__/"), strings.Contains(p, ".cache/"):
		return "dependency_cache"
	case strings.HasPrefix(p, "dist/"), strings.HasPrefix(p, "build/"), strings.HasSuffix(p, ".pyc"), strings.HasSuffix(p, ".egg"), strings.HasSuffix(p, ".whl"), strings.HasSuffix(p, ".so"):
		return "build_artifact"
	case strings.Contains(p, ".ssh"), strings.Contains(p, ".aws"), strings.Contains(p, "credential"), strings.Contains(p, "secret"), strings.Contains(p, "token"), strings.HasSuffix(p, ".env"):
		return "secret_or_config"
	case strings.HasSuffix(p, ".py"), strings.HasSuffix(p, ".go"), strings.HasSuffix(p, ".js"), strings.HasSuffix(p, ".ts"), strings.HasSuffix(p, ".tsx"), strings.HasSuffix(p, ".java"), strings.HasSuffix(p, ".rs"), strings.HasSuffix(p, ".md"):
		return "source"
	default:
		return "other"
	}
}

func riskIf(ok bool) string {
	if ok {
		return "high"
	}
	return ""
}

func isHighRisk(risk string) bool {
	switch strings.ToLower(risk) {
	case "high", "critical", "tainted":
		return true
	default:
		return false
	}
}

func stringFromAny(value any) string {
	if value == nil {
		return ""
	}
	if s, ok := value.(string); ok {
		return s
	}
	return fmt.Sprint(value)
}

func valueFromMap(data map[string]any, key string) any {
	if data == nil {
		return nil
	}
	return data[key]
}

func safeGraphID(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.', r == ':':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "unknown"
	}
	if len(out) > 120 {
		return out[:120]
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func shortLabel(value, fallbackValue string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallbackValue
	}
	if len(value) > 48 {
		return value[:45] + "..."
	}
	return value
}

func lensShortRef(ref string) string {
	if idx := strings.LastIndex(ref, "/"); idx >= 0 && idx+1 < len(ref) {
		return ref[idx+1:]
	}
	return ref
}

func fallback(value, fallbackValue string) string {
	if strings.TrimSpace(value) == "" {
		return fallbackValue
	}
	return value
}
