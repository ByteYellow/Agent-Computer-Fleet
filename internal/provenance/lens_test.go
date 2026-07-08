package provenance

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestGraphLensDataFlowDerivesSecretToNetworkEdge(t *testing.T) {
	db := newLensTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertLensFixture(t, db, now)
	insertLensEvent(t, db, "evt-dns", "network_connect", `{"dst_ip":"127.0.0.53","comm":"systemd-resolved"}`, addSeconds(t, now, 2))
	insertLensEvent(t, db, "evt-public", "network_connect", `{"dst_ip":"150.138.1.1","comm":"model-client"}`, addSeconds(t, now, 3))
	// A loopback destination tagged private_cidr by an upstream classifier must NOT
	// count as exfiltration (the local DNS stub is not a private-network egress).
	insertLensEvent(t, db, "evt-dns-priv", "private_cidr", `{"dst_ip":"127.0.0.53","comm":"systemd-resolved"}`, addSeconds(t, now, 4))

	manifest, err := BuildGraphLens(db, GraphLensOptions{
		RunID:    "run-lens",
		Lens:     "data-flow-taint",
		Overlays: []string{"risk", "trust"},
		Limit:    100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != graphLensSchemaVersion {
		t.Fatalf("schema=%s", manifest.SchemaVersion)
	}
	if manifest.Lens != "data-flow-taint" {
		t.Fatalf("lens=%s", manifest.Lens)
	}
	if len(manifest.DerivedEdges) != 1 {
		t.Fatalf("derived edges=%d, want 1: %+v", len(manifest.DerivedEdges), manifest.DerivedEdges)
	}
	edge := manifest.DerivedEdges[0]
	if edge.EdgeType != "possible_sensitive_data_flow_summary" {
		t.Fatalf("derived edge type=%s", edge.EdgeType)
	}
	if edge.FromID != "runtime_process/pid/4242" || edge.ToID == "" {
		t.Fatalf("derived edge path=%s -> %s", edge.FromID, edge.ToID)
	}
	if edge.DerivationRule != "dataflow.same_process.secret_to_network.aggregate.v1" || edge.Confidence < 0.8 {
		t.Fatalf("derived metadata not strong enough: %+v", edge)
	}
	if got := intFromEdgeData(edge, "source_count"); got != 1 {
		t.Fatalf("source_count=%d, want 1: %+v", got, edge.Data)
	}
	if got := intFromEdgeData(edge, "sink_count"); got != 1 {
		t.Fatalf("sink_count=%d, want 1: %+v", got, edge.Data)
	}
	destinations, _ := edge.Data["destinations"].([]string)
	if len(destinations) != 1 || destinations[0] != "169.254.169.254" {
		t.Fatalf("destinations=%v, want metadata IP only", destinations)
	}
}

func TestGraphLensRawDetailKeepsIndividualDataFlowEdges(t *testing.T) {
	db := newLensTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertLensFixture(t, db, now)

	manifest, err := BuildGraphLens(db, GraphLensOptions{
		RunID:  "run-lens",
		Lens:   "data-flow-taint",
		Detail: "raw",
		Limit:  100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.DerivedEdges) != 1 {
		t.Fatalf("derived edges=%d, want 1: %+v", len(manifest.DerivedEdges), manifest.DerivedEdges)
	}
	edge := manifest.DerivedEdges[0]
	if edge.EdgeType != "possible_sensitive_data_flow" {
		t.Fatalf("derived edge type=%s", edge.EdgeType)
	}
	if edge.FromID != "runtime_event/evt-secret" || edge.ToID != "runtime_event/evt-egress" {
		t.Fatalf("raw derived edge path=%s -> %s", edge.FromID, edge.ToID)
	}
}

func TestGraphLensSummaryRequiresPIDScopeForTaintAggregation(t *testing.T) {
	db := newLensTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertLensFixture(t, db, now)
	if _, err := db.Exec(`UPDATE events SET pid = 0 WHERE run_id = 'run-lens'`); err != nil {
		t.Fatal(err)
	}

	summary, err := BuildGraphLens(db, GraphLensOptions{RunID: "run-lens", Lens: "data-flow-taint", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.DerivedEdges) != 0 {
		t.Fatalf("summary should not aggregate coarse process_id-only taint flows: %+v", summary.DerivedEdges)
	}

	raw, err := BuildGraphLens(db, GraphLensOptions{RunID: "run-lens", Lens: "data-flow-taint", Detail: "raw", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw.DerivedEdges) != 1 {
		t.Fatalf("raw detail should keep fallback evidence edge, got %d: %+v", len(raw.DerivedEdges), raw.DerivedEdges)
	}
}

func TestGraphLensDefaultSummaryUsesRunOverview(t *testing.T) {
	db := newLensTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertLensFixture(t, db, now)
	insertLensEvent(t, db, "evt-loopback-private", "private_cidr", `{"dst_ip":"127.0.0.53","comm":"systemd-resolved"}`, addSeconds(t, now, 2))
	if _, err := db.Exec(`INSERT INTO policy_decisions (id, event_id, run_id, session_id, rule_id, decision, reason, created_at)
		VALUES ('policy-loopback-private', 'evt-loopback-private', 'run-lens', 'session-lens', 'private_cidr_access', 'deny', 'private CIDR access', ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO risk_signals (id, run_id, session_id, tool_call_id, process_id, event_id, policy_decision_id, signal_type, severity, reason, recommended_action, created_at)
		VALUES ('risk-loopback-private', 'run-lens', 'session-lens', 'tool-lens', 'proc-lens', 'evt-loopback-private', 'policy-loopback-private', 'policy_violation', 'medium', 'private CIDR access', 'deny', ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO provenance_objects (hash, object_type, source_id, run_id, path, size_bytes, created_at)
		VALUES ('sha256:lens-artifact', 'artifact', 'workspace_file/app.py', 'run-lens', '/tmp/objects/artifact.json', 123, ?)`, now); err != nil {
		t.Fatal(err)
	}

	manifest, err := BuildGraphLens(db, GraphLensOptions{RunID: "run-lens", Lens: "default", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Query.LayoutHint != "run_overview" {
		t.Fatalf("layout=%s, want run_overview", manifest.Query.LayoutHint)
	}
	if !lensHasNode(manifest, "overview/processes", "overview_group") {
		t.Fatalf("overview process group missing: %+v", manifest.Nodes)
	}
	if lensHasNode(manifest, "runtime_event/evt-secret", "runtime_event") {
		t.Fatalf("default summary should not render raw runtime events: %+v", manifest.Nodes)
	}
	if got := lensNodeDataInt(manifest, "overview/artifacts", "count"); got != 1 {
		t.Fatalf("overview artifacts=%d, want 1: %+v", got, manifest.Nodes)
	}
	if got := lensNodeDataInt(manifest, "overview/risks", "total"); got != 1 {
		t.Fatalf("overview risks total=%d, want 1: %+v", got, manifest.Nodes)
	}
	if got := lensNodeDataInt(manifest, "overview/risks", "high"); got != 1 {
		t.Fatalf("overview high risks=%d, want 1: %+v", got, manifest.Nodes)
	}
}

func TestGraphLensSummaryGroupsWideLenses(t *testing.T) {
	db := newLensTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertLensFixture(t, db, now)
	insertLensEvent(t, db, "evt-write", "file_write", `{"path":"src/main.py","command":"python setup.py"}`, addSeconds(t, now, 2))
	insertLensEvent(t, db, "evt-loopback-private", "private_cidr", `{"dst_ip":"127.0.0.53","comm":"systemd-resolved"}`, addSeconds(t, now, 3))
	if _, err := db.Exec(`INSERT INTO graph_edges (id, run_id, from_id, to_id, edge_type, source_event_id, created_at)
		VALUES ('edge-write-file', 'run-lens', 'runtime_event/evt-write', 'workspace_file/src/main.py', 'runtime_event_file', 'evt-write', ?)`, addSeconds(t, now, 2)); err != nil {
		t.Fatal(err)
	}

	process, err := BuildGraphLens(db, GraphLensOptions{RunID: "run-lens", Lens: "process", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !lensHasKind(process, "process_group") || !lensHasKind(process, "event_burst") {
		t.Fatalf("process summary should use process_group + event_burst: %+v", process.Nodes)
	}

	security, err := BuildGraphLens(db, GraphLensOptions{RunID: "run-lens", Lens: "security", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !lensHasKind(security, "risk_group") {
		t.Fatalf("security summary should use risk_group: %+v", security.Nodes)
	}
	if lensHasGroupSubtype(security, "risk_group", "private_cidr_access") {
		t.Fatalf("security summary should exclude loopback private_cidr policy groups: %+v", security.Nodes)
	}
	if lensHasGroupSubtype(security, "risk_group", "metadata_ip") {
		t.Fatalf("security summary should not duplicate policy-covered raw event groups: %+v", security.Nodes)
	}

	files, err := BuildGraphLens(db, GraphLensOptions{RunID: "run-lens", Lens: "file-artifact", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !lensHasKind(files, "file_group") {
		t.Fatalf("file summary should use file_group: %+v", files.Nodes)
	}
	if got := lensGroupInt(files, "file_group", "source", "count"); got != 1 {
		t.Fatalf("source file group count=%d, want 1: %+v", got, files.Nodes)
	}

	network, err := BuildGraphLens(db, GraphLensOptions{RunID: "run-lens", Lens: "network-egress", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !lensHasKind(network, "egress_group") {
		t.Fatalf("network summary should use egress_group: %+v", network.Nodes)
	}
	if !lensHasDrilldown(network) {
		t.Fatalf("summary group should expose drilldown metadata: %+v", network.Nodes)
	}
	if got := lensGroupInt(network, "egress_group", "loopback", "risky"); got != 0 {
		t.Fatalf("loopback egress risky=%d, want 0", got)
	}

	taint, err := BuildGraphLens(db, GraphLensOptions{RunID: "run-lens", Lens: "data-flow-taint", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if lensHasKind(taint, "policy_decision") || lensHasKind(taint, "runtime_event") {
		t.Fatalf("taint summary should render derived summary path only: %+v", taint.Nodes)
	}
	if !lensHasKind(taint, "egress_group") {
		t.Fatalf("taint summary should include egress group: %+v", taint.Nodes)
	}

	intent, err := BuildGraphLens(db, GraphLensOptions{RunID: "run-lens", Lens: "agent-intent", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !lensHasKind(intent, "intent_group") || lensHasKind(intent, "runtime_event") {
		t.Fatalf("agent intent summary should use intent_group without raw events: %+v", intent.Nodes)
	}

	trust, err := BuildGraphLens(db, GraphLensOptions{RunID: "run-lens", Lens: "trust-origin", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !lensHasKind(trust, "trust_group") || lensHasKind(trust, "runtime_event") {
		t.Fatalf("trust summary should use trust_group without raw events: %+v", trust.Nodes)
	}

	boundary, err := BuildGraphLens(db, GraphLensOptions{RunID: "run-lens", Lens: "sandbox-boundary", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !lensHasKind(boundary, "boundary_group") || lensHasKind(boundary, "runtime_event") {
		t.Fatalf("boundary summary should use boundary_group without raw events: %+v", boundary.Nodes)
	}
}

func TestGraphLensSubstrateShowsK8sCgroupAttribution(t *testing.T) {
	db := newLensTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertLensFixture(t, db, now)
	if _, err := db.Exec(`UPDATE events SET binding_source = 'k8s_cgroup', cgroup_id = '334746', container_id = '', correlation_method = 'cgroup_time_window:run_id+cgroup_id+time', correlation_confidence = 0.8 WHERE run_id = 'run-lens'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, created_at)
		VALUES ('evt-podmeta', 'run-lens', 'session-lens', '', '', 'k8s', 'pod_metadata', ?, ?)`,
		`{"cluster":"local-k3s","node":"codex-kvm-k8s","pod_name":"agent-sandbox-0","namespace":"agentprov","container":"agent","image":"busybox","service_account":"default","labels":"app=agent","cgroup_id":"334746","pod_uid":"pod-uid-1"}`, now); err != nil {
		t.Fatal(err)
	}

	manifest, err := BuildGraphLens(db, GraphLensOptions{RunID: "run-lens", Lens: "substrate", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Query.LayoutHint != "substrate_topology" {
		t.Fatalf("layout=%s, want substrate_topology", manifest.Query.LayoutHint)
	}
	if !lensHasNode(manifest, "substrate/profile/k8s-daemonset", "substrate_profile") {
		t.Fatalf("substrate profile node missing: %+v", manifest.Nodes)
	}
	if !lensHasNode(manifest, "substrate/scope/k8s_cgroup", "substrate_scope") {
		t.Fatalf("k8s scope node missing: %+v", manifest.Nodes)
	}
	if got := lensNodeDataInt(manifest, "substrate/cgroup_group", "count"); got != 1 {
		t.Fatalf("cgroup group count=%d, want 1: %+v", got, manifest.Nodes)
	}
	if !lensHasNode(manifest, "substrate/pod/local-k3s_agentprov_agent-sandbox-0", "substrate_pod") {
		t.Fatalf("pod metadata node missing: %+v", manifest.Nodes)
	}
	var hasPodEdge, hasPodCgroupEdge bool
	for _, edge := range manifest.Edges {
		if edge.EdgeType == "workload_has_pod" && edge.ToID == "substrate/pod/local-k3s_agentprov_agent-sandbox-0" {
			hasPodEdge = true
		}
		if edge.EdgeType == "pod_bound_cgroup" && edge.FromID == "substrate/pod/local-k3s_agentprov_agent-sandbox-0" {
			hasPodCgroupEdge = true
		}
	}
	if !hasPodEdge || !hasPodCgroupEdge {
		t.Fatalf("pod edges missing (workload_has_pod=%v pod_bound_cgroup=%v): %+v", hasPodEdge, hasPodCgroupEdge, manifest.Edges)
	}
	if got := lensNodeDataInt(manifest, "substrate/workload_group", "pods"); got != 1 {
		t.Fatalf("workload pods=%d, want 1", got)
	}
}

func TestGraphLensSubstrateDrawsCrossPodInfluence(t *testing.T) {
	db := newLensTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertLensFixture(t, db, now)
	// Two pods on one node bound to one run; an egress from alice's cgroup targets
	// bob's pod IP — a real A2A network call the substrate lens must draw pod->pod.
	for _, p := range []struct{ name, cg, ip string }{{"bob", "100", "10.0.0.2"}, {"alice", "200", "10.0.0.1"}} {
		payload := `{"pod_name":"` + p.name + `","namespace":"team","cgroup_id":"` + p.cg + `","pod_uid":"uid-` + p.name + `","pod_ip":"` + p.ip + `"}`
		if _, err := db.Exec(`INSERT INTO events (id, run_id, session_id, source, event_type, payload, created_at)
			VALUES (?, 'run-lens', 'session-lens', 'k8s', 'pod_metadata', ?, ?)`, "evt-pod-"+p.name, payload, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO events (id, run_id, session_id, source, event_type, cgroup_id, binding_source, correlation_confidence, payload, created_at)
		VALUES ('evt-a2a', 'run-lens', 'session-lens', 'agentprov_ebpf', 'network_connect', '200', 'k8s_cgroup', 0.8, '{"dst_ip":"10.0.0.2","host":"10.0.0.2","port":"8080"}', ?)`, now); err != nil {
		t.Fatal(err)
	}

	manifest, err := BuildGraphLens(db, GraphLensOptions{RunID: "run-lens", Lens: "substrate", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !lensHasNode(manifest, "substrate/cgroup/100", "substrate_cgroup_group") || !lensHasNode(manifest, "substrate/cgroup/200", "substrate_cgroup_group") {
		t.Fatalf("per-pod cgroup nodes missing (pods must not collapse onto one cgroup): %+v", manifest.Nodes)
	}
	var influence *GraphLensEdge
	for i := range manifest.Edges {
		if manifest.Edges[i].EdgeType == "pod_influences_pod" {
			influence = &manifest.Edges[i]
		}
	}
	if influence == nil {
		t.Fatalf("cross-pod influence edge missing: %+v", manifest.Edges)
	}
	nodeName := func(id string) any {
		for _, n := range manifest.Nodes {
			if n.ID == id {
				return n.Data["pod_name"]
			}
		}
		return nil
	}
	if nodeName(influence.FromID) != "alice" || nodeName(influence.ToID) != "bob" {
		t.Fatalf("influence edge should be alice->bob, got %s->%s", influence.FromID, influence.ToID)
	}
}

func TestGraphLensFileArtifactMaterializesRawFileWrites(t *testing.T) {
	db := newLensTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertLensFixture(t, db, now)
	// A passive node-side capture has no record workspace diff; the file lens must
	// still surface a real file_write path, and filter pseudo-file noise.
	insertLensEvent(t, db, "evt-realfile", "file_write", `{"path":"/work/workspace/harvested_creds.bin"}`, addSeconds(t, now, 2))
	insertLensEvent(t, db, "evt-devnull", "file_write", `{"path":"/dev/null"}`, addSeconds(t, now, 3))

	manifest, err := BuildGraphLens(db, GraphLensOptions{RunID: "run-lens", Lens: "file-artifact", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !lensHasNode(manifest, "file_group/other", "file_group") {
		t.Fatalf("file_group/other missing: raw file_write not materialized: %+v", manifest.Nodes)
	}
	if got := lensNodeDataInt(manifest, "file_group/other", "count"); got != 1 {
		t.Fatalf("file_group other count=%d, want 1 (/dev/null must be filtered): %+v", got, manifest.Nodes)
	}
}

func TestGraphLensSummaryOmitsLowValueRuntimeNoise(t *testing.T) {
	db := newLensTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertLensFixture(t, db, now)
	insertLensEvent(t, db, "evt-exit", "process_exit", `{"exit_code":0}`, now)
	if _, err := db.Exec(`INSERT INTO graph_edges (id, run_id, from_id, to_id, edge_type, source_event_id, created_at)
		VALUES ('edge-proc-exit', 'run-lens', 'proc-lens', 'runtime_event/evt-exit', 'runtime_process_event', 'evt-exit', ?)`, now); err != nil {
		t.Fatal(err)
	}

	summary, err := BuildGraphLens(db, GraphLensOptions{RunID: "run-lens", Lens: "process", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if lensHasNode(summary, "runtime_event/evt-exit", "runtime_event") {
		t.Fatalf("summary lens should omit low-value process_exit: %+v", summary.Nodes)
	}

	raw, err := BuildGraphLens(db, GraphLensOptions{RunID: "run-lens", Lens: "process", Detail: "raw", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !lensHasNode(raw, "runtime_event/evt-exit", "runtime_event") {
		t.Fatalf("raw lens should keep process_exit for full observability: %+v", raw.Nodes)
	}
}

func TestGraphLensFocusAndJSON(t *testing.T) {
	db := newLensTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertLensFixture(t, db, now)

	var out bytes.Buffer
	if err := GraphLensJSON(db, GraphLensOptions{
		RunID: "run-lens",
		Lens:  "security",
		Focus: "runtime_event/evt-egress",
		Limit: 100,
	}, &out); err != nil {
		t.Fatal(err)
	}
	var manifest GraphLensManifest
	if err := json.Unmarshal(out.Bytes(), &manifest); err != nil {
		t.Fatalf("invalid lens json: %v\n%s", err, out.String())
	}
	if manifest.Query.Focus != "runtime_event/evt-egress" {
		t.Fatalf("focus=%s", manifest.Query.Focus)
	}
	if len(manifest.Edges) == 0 {
		t.Fatalf("expected focused security edges")
	}
	if !lensHasNode(manifest, "policy_decision/policy-lens", "policy_decision") {
		t.Fatalf("focused security lens should include policy node: %+v", manifest.Nodes)
	}
	if !lensHasNode(manifest, "risk_signal/risk-lens", "risk_signal") {
		t.Fatalf("focused security lens should include risk node: %+v", manifest.Nodes)
	}
	if !lensHasNode(manifest, "response_action/response-lens", "response_action") {
		t.Fatalf("focused security lens should include response node: %+v", manifest.Nodes)
	}
	for _, edge := range manifest.Edges {
		if edge.FromID != "runtime_event/evt-egress" && edge.ToID != "runtime_event/evt-egress" &&
			edge.FromID != "policy_decision/policy-lens" && edge.ToID != "policy_decision/policy-lens" &&
			edge.FromID != "risk_signal/risk-lens" && edge.ToID != "risk_signal/risk-lens" {
			t.Fatalf("edge escaped focus: %+v", edge)
		}
	}
}

func newLensTestDB(t *testing.T) *sql.DB {
	t.Helper()
	paths, err := store.Init(filepath.Join(t.TempDir(), ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func insertLensFixture(t *testing.T, db *sql.DB, now string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO leases (id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES ('lease-lens', 'run-lens', 'task.yaml', '{}', 'allocated', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sessions (id, lease_id, run_id, workspace_host_path, status, created_at, updated_at)
		VALUES ('session-lens', 'lease-lens', 'run-lens', '/tmp/work', 'running', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tool_calls (id, run_id, session_id, command, status, created_at, started_at)
		VALUES ('tool-lens', 'run-lens', 'session-lens', 'run setup', 'running', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO processes (id, session_id, tool_call_id, command, status, started_at)
		VALUES ('proc-lens', 'session-lens', 'tool-lens', 'sh -c setup', 'running', ?)`, now); err != nil {
		t.Fatal(err)
	}
	// The secret read must precede the egress for a real data flow; the taint
	// lens only derives an edge that runs forward in time.
	parsed, err := time.Parse(time.RFC3339Nano, now)
	if err != nil {
		t.Fatal(err)
	}
	egressTime := parsed.Add(time.Second).UTC().Format(time.RFC3339Nano)
	insertLensEvent(t, db, "evt-secret", "secret_path", `{"path":"/root/.aws/credentials"}`, now)
	insertLensEvent(t, db, "evt-egress", "metadata_ip", `{"dst_ip":"169.254.169.254","comm":"wget"}`, egressTime)
	if _, err := db.Exec(`INSERT INTO graph_edges (id, run_id, from_id, to_id, edge_type, source_event_id, created_at) VALUES
		('edge-tool-proc', 'run-lens', 'tool-lens', 'proc-lens', 'runtime_tool_call_process', '', ?),
		('edge-proc-secret', 'run-lens', 'proc-lens', 'runtime_event/evt-secret', 'runtime_process_event', 'evt-secret', ?),
		('edge-proc-egress', 'run-lens', 'proc-lens', 'runtime_event/evt-egress', 'runtime_process_event', 'evt-egress', ?),
		('edge-event-policy', 'run-lens', 'runtime_event/evt-egress', 'policy_decision/policy-lens', 'runtime_event_policy_decision', 'evt-egress', ?)`,
		now, now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO policy_decisions (id, event_id, run_id, session_id, rule_id, decision, reason, created_at)
		VALUES ('policy-lens', 'evt-egress', 'run-lens', 'session-lens', 'metadata-ip', 'quarantine', 'metadata IP access', ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO risk_signals (id, run_id, session_id, tool_call_id, process_id, event_id, policy_decision_id, signal_type, severity, reason, recommended_action, created_at)
		VALUES ('risk-lens', 'run-lens', 'session-lens', 'tool-lens', 'proc-lens', 'evt-egress', 'policy-lens', 'policy_violation', 'high', 'metadata IP access', 'quarantine', ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO response_actions (id, run_id, session_id, process_id, risk_signal_id, policy_decision_id, action_type, target_type, target_id, status, created_at)
		VALUES ('response-lens', 'run-lens', 'session-lens', 'proc-lens', 'risk-lens', 'policy-lens', 'quarantine', 'session', 'session-lens', 'recorded', ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO graph_edges (id, run_id, from_id, to_id, edge_type, source_event_id, created_at) VALUES
		('edge-policy-risk', 'run-lens', 'policy_decision/policy-lens', 'risk_signal/risk-lens', 'policy_decision_risk_signal', 'evt-egress', ?),
		('edge-risk-response', 'run-lens', 'risk_signal/risk-lens', 'response_action/response-lens', 'risk_signal_response_action', 'evt-egress', ?)`,
		now, now); err != nil {
		t.Fatal(err)
	}
}

func intFromEdgeData(edge GraphLensEdge, key string) int {
	value, ok := edge.Data[key]
	if !ok {
		return 0
	}
	switch v := value.(type) {
	case int:
		return v
	case float64:
		return int(v)
	default:
		return 0
	}
}

func insertLensEvent(t *testing.T, db *sql.DB, id, eventType, payload, now string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO events
		(id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, correlation_method, correlation_confidence, pid, ppid, created_at)
		VALUES (?, 'run-lens', 'session-lens', 'tool-lens', 'proc-lens', 'agentprov_ebpf', ?, ?, 'container_time_window', 0.92, 4242, 4000, ?)`,
		id, eventType, payload, now); err != nil {
		t.Fatal(err)
	}
}

func addSeconds(t *testing.T, ts string, seconds int) string {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Add(time.Duration(seconds) * time.Second).UTC().Format(time.RFC3339Nano)
}

func lensHasNode(manifest GraphLensManifest, id, kind string) bool {
	for _, node := range manifest.Nodes {
		if node.ID == id && node.Kind == kind {
			return true
		}
	}
	return false
}

func lensHasKind(manifest GraphLensManifest, kind string) bool {
	for _, node := range manifest.Nodes {
		if node.Kind == kind {
			return true
		}
	}
	return false
}

func lensHasGroupSubtype(manifest GraphLensManifest, kind, subtype string) bool {
	for _, node := range manifest.Nodes {
		if node.Kind == kind && node.Subtype == subtype {
			return true
		}
	}
	return false
}

func lensHasDrilldown(manifest GraphLensManifest) bool {
	for _, node := range manifest.Nodes {
		if node.Data != nil && stringFromAny(node.Data["drilldown_lens"]) != "" {
			return true
		}
	}
	return false
}

func lensGroupInt(manifest GraphLensManifest, kind, subtype, key string) int {
	for _, node := range manifest.Nodes {
		if node.Kind == kind && node.Subtype == subtype {
			switch v := node.Data[key].(type) {
			case int:
				return v
			case int64:
				return int(v)
			case float64:
				return int(v)
			}
		}
	}
	return 0
}

func lensNodeDataInt(manifest GraphLensManifest, id, key string) int {
	for _, node := range manifest.Nodes {
		if node.ID != id {
			continue
		}
		switch v := node.Data[key].(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			return int(v)
		}
	}
	return 0
}
