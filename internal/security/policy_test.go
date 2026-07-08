package security

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/signals"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestEvaluateMetadataIPQuarantines(t *testing.T) {
	decision := DefaultEngine().Evaluate(Event{
		EventType: "network_connect",
		DstIP:     "169.254.169.254",
	})
	if decision.Decision != "quarantine" {
		t.Fatalf("decision = %s, want quarantine", decision.Decision)
	}
}

func TestEvaluatePrivateCIDRDenies(t *testing.T) {
	decision := DefaultEngine().Evaluate(Event{
		EventType: "network_connect",
		DstIP:     "10.0.0.5",
	})
	if decision.Decision != "deny" {
		t.Fatalf("decision = %s, want deny", decision.Decision)
	}
}

func TestEvaluateLoopbackDoesNotDenyAsPrivateCIDR(t *testing.T) {
	decision := DefaultEngine().Evaluate(Event{
		EventType: "network_connect",
		DstIP:     "127.0.0.53",
	})
	if decision.Decision != "allow" {
		t.Fatalf("decision = %s, want allow", decision.Decision)
	}
}

func TestRuleMatchesEitherPathOrArgsWhenBothSet(t *testing.T) {
	r := Rule{Match: RuleMatch{PathContains: []string{"id_rsa"}, ArgsContains: []string{"curl"}}}
	// args matches, path does not: must still match (regression - PathContains
	// used to short-circuit to false before ArgsContains was consulted).
	if !r.Matches(Event{Path: "/tmp/harmless.txt", Args: []string{"curl", "https://x"}}) {
		t.Error("path+args rule should match on args when path does not")
	}
	// path matches, args does not: match.
	if !r.Matches(Event{Path: "/home/u/.ssh/id_rsa"}) {
		t.Error("path+args rule should match on path")
	}
	// neither matches: no match.
	if r.Matches(Event{Path: "/tmp/x", Args: []string{"ls"}}) {
		t.Error("path+args rule should not match when neither matches")
	}
}

func TestEvaluateSecretPathKills(t *testing.T) {
	decision := DefaultEngine().Evaluate(Event{
		EventType: "file_open",
		Path:      "/workspace/.env",
	})
	if decision.Decision != "kill" {
		t.Fatalf("decision = %s, want kill", decision.Decision)
	}
}

// TestSelfCredentialAccessNotAlerted proves the default policy does not alert on
// the agent reading its OWN operational credentials (the recurring dashboard
// noise), while a real target-secret read still kills -- ranked before the
// secret_path kill rule, allow-decision so the event is still captured.
func TestSelfCredentialAccessNotAlerted(t *testing.T) {
	eng := DefaultEngine()
	selfPaths := []string{
		"/home/agent/.claude/.credentials.json",
		"/home/agent/.agentprov-demo/deepseek-claude.env",
	}
	for _, p := range selfPaths {
		d := eng.Evaluate(Event{EventType: "secret_path", Path: p})
		if d.Decision != "allow" {
			t.Errorf("self credential %q: decision = %s, want allow (no alert)", p, d.Decision)
		}
		if d.RuleID != "self_credential_access" {
			t.Errorf("self credential %q: rule = %s, want self_credential_access", p, d.RuleID)
		}
	}
	// Planted targets must STILL kill (the self allowlist must not shadow them).
	for _, p := range []string{"/home/agent/.aws/credentials", "/home/agent/.config/agentprov-demo-secrets/api_token"} {
		d := eng.Evaluate(Event{EventType: "secret_path", Path: p})
		if d.Decision != "kill" {
			t.Errorf("target secret %q: decision = %s, want kill", p, d.Decision)
		}
	}
}

func TestEvaluatePtraceQuarantines(t *testing.T) {
	if d := DefaultEngine().Evaluate(Event{EventType: "ptrace"}); d.Decision != "quarantine" {
		t.Fatalf("ptrace decision = %s, want quarantine", d.Decision)
	}
}

func TestEvaluatePrivilegeEscalation(t *testing.T) {
	// runtimeEventForPolicy injects setuid_root only when uid==0.
	if d := DefaultEngine().Evaluate(Event{EventType: "setuid", Args: []string{"setuid_root"}}); d.Decision != "quarantine" {
		t.Fatalf("setuid(0) decision = %s, want quarantine", d.Decision)
	}
	// A benign privilege drop (no root marker) must NOT be flagged.
	if d := DefaultEngine().Evaluate(Event{EventType: "setuid"}); d.Decision != "allow" {
		t.Fatalf("benign setuid decision = %s, want allow", d.Decision)
	}
}

// TestReevaluateRun proves the replay command: it recomputes the risk layer from
// the current policy (self credential -> no alert; targets -> alert), leaves the
// raw events intact, and is idempotent (no duplicate signals on re-run).
func TestReevaluateRun(t *testing.T) {
	paths, err := store.Init(filepath.Join(t.TempDir(), ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ins := func(id, etype, payload string) {
		if _, err := db.Exec(`INSERT INTO events (id, run_id, source, event_type, payload, created_at)
			VALUES (?, 'run-r', 'agentprov_ebpf', ?, ?, '2026-01-01T00:00:01Z')`, id, etype, payload); err != nil {
			t.Fatal(err)
		}
	}
	ins("e-self", "secret_path", `{"payload":{"raw":{"path":"/home/a/.claude/.credentials.json"}}}`)
	ins("e-aws", "secret_path", `{"payload":{"raw":{"path":"/home/a/.aws/credentials"}}}`)
	ins("e-meta", "metadata_ip", `{"payload":{"raw":{"dst_ip":"169.254.169.254"}}}`)
	ins("e-benign", "execve", `{"payload":{"raw":{"command":"ls -la"}}}`)

	evaluated, alerts, err := ReevaluateRun(db, "run-r", DefaultEngine())
	if err != nil {
		t.Fatal(err)
	}
	if evaluated != 4 {
		t.Errorf("evaluated = %d, want 4", evaluated)
	}
	if alerts != 2 {
		t.Errorf("alerts = %d, want 2 (aws kill + metadata quarantine; self credential is allow)", alerts)
	}
	var secretEvents int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id='run-r' AND event_type='secret_path'`).Scan(&secretEvents); err != nil {
		t.Fatal(err)
	}
	if secretEvents != 2 {
		t.Errorf("secret_path events = %d, want 2 (raw data must be preserved)", secretEvents)
	}
	var selfRisks int
	if err := db.QueryRow(`SELECT COUNT(*) FROM risk_signals WHERE run_id='run-r' AND payload LIKE '%.claude%'`).Scan(&selfRisks); err != nil {
		t.Fatal(err)
	}
	if selfRisks != 0 {
		t.Errorf("self credential produced %d risk signals, want 0 (observed, not alerted)", selfRisks)
	}
	// Idempotent: a second pass must not duplicate the signals.
	if _, alerts2, err := ReevaluateRun(db, "run-r", DefaultEngine()); err != nil || alerts2 != 2 {
		t.Errorf("re-run alerts = %d (err %v), want 2 idempotent", alerts2, err)
	}
	var riskTotal int
	if err := db.QueryRow(`SELECT COUNT(*) FROM risk_signals WHERE run_id='run-r'`).Scan(&riskTotal); err != nil {
		t.Fatal(err)
	}
	if riskTotal != 2 {
		t.Errorf("risk_signals = %d after re-run, want 2 (no duplicates)", riskTotal)
	}
}

func TestEvaluateJSONLWithStatePersistsAndQuarantines(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	insertPolicySession(t, db)

	eventsPath := filepath.Join(root, "events.jsonl")
	if err := os.WriteFile(eventsPath, []byte(`{"source":"telemetry_fixture","event_type":"network_connect","run_id":"run-test","session_id":"sbx-test","dst_ip":"169.254.169.254"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := EvaluateJSONLWithState(db, eventsPath, os.Stdout); err != nil {
		t.Fatal(err)
	}

	var sessionStatus string
	if err := db.QueryRow(`SELECT status FROM sessions WHERE id = 'sbx-test'`).Scan(&sessionStatus); err != nil {
		t.Fatal(err)
	}
	if sessionStatus != "quarantined" {
		t.Fatalf("session status = %s, want quarantined", sessionStatus)
	}
	var decisionCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_decisions WHERE run_id = 'run-test' AND decision = 'quarantine'`).Scan(&decisionCount); err != nil {
		t.Fatal(err)
	}
	if decisionCount != 1 {
		t.Fatalf("decision count = %d, want 1", decisionCount)
	}
	var eventID, decisionID string
	if err := db.QueryRow(`SELECT id, event_id FROM policy_decisions WHERE run_id = 'run-test' AND decision = 'quarantine'`).Scan(&decisionID, &eventID); err != nil {
		t.Fatal(err)
	}
	var policyEdgeCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM graph_edges
		WHERE run_id = 'run-test'
		  AND from_id = ?
		  AND to_id = ?
		  AND edge_type = 'runtime_event_policy_decision'`, "runtime_event/"+eventID, "policy_decision/"+decisionID).Scan(&policyEdgeCount); err != nil {
		t.Fatal(err)
	}
	if policyEdgeCount != 1 {
		t.Fatalf("policy edge count = %d, want 1", policyEdgeCount)
	}
	var sessionEdgeCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM graph_edges
		WHERE run_id = 'run-test'
		  AND from_id = ?
		  AND to_id = 'sbx-test'
		  AND edge_type = 'policy_decision_session'`, "policy_decision/"+decisionID).Scan(&sessionEdgeCount); err != nil {
		t.Fatal(err)
	}
	if sessionEdgeCount != 1 {
		t.Fatalf("policy session edge count = %d, want 1", sessionEdgeCount)
	}
	var quarantineCount int
	if err := db.QueryRow(`SELECT COALESCE(SUM(quarantine_count), 0) FROM cost_samples WHERE run_id = 'run-test'`).Scan(&quarantineCount); err != nil {
		t.Fatal(err)
	}
	if quarantineCount != 1 {
		t.Fatalf("quarantine count = %d, want 1", quarantineCount)
	}
	risks, err := ListRiskSignals(db, "run-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(risks) != 1 {
		t.Fatalf("risk signals = %d, want 1", len(risks))
	}
	if risks[0].PolicyDecisionID != decisionID || risks[0].SignalType != "policy_violation" || risks[0].Severity != "high" || risks[0].RecommendedAction != "quarantine" {
		t.Fatalf("unexpected risk signal: %+v", risks[0])
	}
	responses, err := ListResponseActions(db, "run-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(responses) != 1 {
		t.Fatalf("response actions = %d, want 1", len(responses))
	}
	if responses[0].RiskSignalID != risks[0].ID || responses[0].PolicyDecisionID != decisionID || responses[0].ActionType != "quarantine" || responses[0].TargetType != "session" || responses[0].TargetID != "sbx-test" {
		t.Fatalf("unexpected response action: %+v", responses[0])
	}
	riskReport, err := BuildRiskSignalsReport(db, "run-test")
	if err != nil {
		t.Fatal(err)
	}
	if riskReport.SchemaVersion != "agentprovenance.security_risks/v1" || riskReport.ResultSetID == "" || riskReport.PageHash == "" || riskReport.Count != 1 {
		t.Fatalf("unexpected risk report: %+v", riskReport)
	}
	if !containsCommand(riskReport.Risks[0].Query.Drilldowns, "graph explain --risk "+decisionID) {
		t.Fatalf("risk report missing graph explain drilldown: %+v", riskReport.Risks[0].Query.Drilldowns)
	}
	responseReport, err := BuildResponseActionsReport(db, "run-test")
	if err != nil {
		t.Fatal(err)
	}
	if responseReport.SchemaVersion != "agentprovenance.security_responses/v1" || responseReport.ResultSetID == "" || responseReport.PageHash == "" || responseReport.Count != 1 {
		t.Fatalf("unexpected response report: %+v", responseReport)
	}
	if !containsCommand(responseReport.Responses[0].Query.Drilldowns, "graph explain --risk "+decisionID) {
		t.Fatalf("response report missing graph explain drilldown: %+v", responseReport.Responses[0].Query.Drilldowns)
	}
}

func containsCommand(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func insertPolicySession(t *testing.T, db *sql.DB) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := db.Exec(`INSERT INTO leases (id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES ('lease-test', 'run-test', 'task.yaml', '{}', 'allocated', ?, ?)`, now, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO sessions (id, lease_id, run_id, container_id, workspace_host_path, status, created_at, updated_at)
		VALUES ('sbx-test', 'lease-test', 'run-test', 'container-test', '/tmp/workspace', 'running', ?, ?)`, now, now)
	if err != nil {
		t.Fatal(err)
	}
}

// TestPolicyViolationEmitsUnifiedSignal verifies the security pillar is a live
// producer on the unified signal model (not just an after-the-fact projection):
// a non-allow decision must land a Security-dimension signal keyed to the graph,
// carrying source provenance back to its risk_signals row.
func TestPolicyViolationEmitsUnifiedSignal(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	insertPolicySession(t, db)

	eventsPath := filepath.Join(root, "events.jsonl")
	if err := os.WriteFile(eventsPath, []byte(`{"source":"telemetry_fixture","event_type":"network_connect","run_id":"run-test","session_id":"sbx-test","process_id":"proc-1","dst_ip":"169.254.169.254"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := EvaluateJSONLWithState(db, eventsPath, os.Stdout); err != nil {
		t.Fatal(err)
	}

	got, err := signals.Query(db, signals.Filter{RunID: "run-test", Dimension: signals.Security})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("unified security signals = %d, want 1", len(got))
	}
	s := got[0]
	if s.Type != "policy_violation" {
		t.Fatalf("signal type = %q, want policy_violation", s.Type)
	}
	if s.GraphRefKind != "process" || s.GraphRefID != "proc-1" {
		t.Fatalf("graph ref = %s/%s, want process/proc-1", s.GraphRefKind, s.GraphRefID)
	}
	if s.SourceTable != "risk_signals" || s.SourceID == "" {
		t.Fatalf("missing source provenance: %+v", s)
	}
	if s.ProducedBy != "security.policy" {
		t.Fatalf("produced_by = %q, want security.policy", s.ProducedBy)
	}

	// Backfill must not duplicate the live-written security row (idempotent on
	// source_table+source_id). It may still project other dimensions that are
	// projection-only (e.g. the cost_samples row this quarantine also wrote), so
	// we assert on the security dimension specifically, not the total count.
	if _, err := signals.Backfill(db); err != nil {
		t.Fatal(err)
	}
	after, err := signals.Query(db, signals.Filter{RunID: "run-test", Dimension: signals.Security})
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 {
		t.Fatalf("security signals after backfill = %d, want 1 (no duplicate of the live row)", len(after))
	}
}

// TestPolicyWritebackFailureIsObservable verifies the unified-signal writeback
// does not fail silently: if it errors, the policy decision and risk signal
// still persist (not blocked), and an observable signal_writeback error event is
// emitted.
func TestPolicyWritebackFailureIsObservable(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	insertPolicySession(t, db)

	// Force the unified writeback to fail by removing the signals table.
	if _, err := db.Exec(`DROP TABLE signals`); err != nil {
		t.Fatal(err)
	}

	eventsPath := filepath.Join(root, "events.jsonl")
	if err := os.WriteFile(eventsPath, []byte(`{"source":"telemetry_fixture","event_type":"network_connect","run_id":"run-test","session_id":"sbx-test","process_id":"proc-1","dst_ip":"169.254.169.254"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := EvaluateJSONLWithState(db, eventsPath, os.Stdout); err != nil {
		t.Fatalf("policy evaluation must not fail when writeback fails: %v", err)
	}

	// The policy decision was NOT blocked: the risk signal still persisted.
	risks, err := ListRiskSignals(db, "run-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(risks) != 1 {
		t.Fatalf("risk signals = %d, want 1 (decision must not be blocked by writeback failure)", len(risks))
	}

	// The failure is observable as a signal_writeback error event.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE source = 'signal_writeback' AND event_type = 'unified_signal_write_failed'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatal("expected an observable signal_writeback error event, found none")
	}
}

func TestDetectModeDowngradesToAudit(t *testing.T) {
	// supply_chain_install is a detect-mode rule: it must fire (not "allow") but
	// downgrade to "audit" so no kill/quarantine side effect runs, while keeping
	// the intended action visible.
	d := DefaultEngine().Evaluate(Event{Args: []string{"pip install requests"}})
	if d.Decision != "audit" {
		t.Fatalf("detect-mode decision = %s, want audit", d.Decision)
	}
	if d.Mode != "detect" {
		t.Fatalf("detect-mode Mode = %q, want detect", d.Mode)
	}
	if d.Intended != "quarantine" {
		t.Fatalf("detect-mode Intended = %q, want quarantine", d.Intended)
	}
	if IsEnforcingDecision(d.Decision) {
		t.Fatalf("audit must not count as an enforcing decision")
	}
	// An enforce-mode rule keeps its blocking decision.
	if e := DefaultEngine().Evaluate(Event{EventType: "ptrace"}); e.Decision != "quarantine" || e.Mode != "enforce" {
		t.Fatalf("enforce rule = %+v, want quarantine/enforce", e)
	}
}
