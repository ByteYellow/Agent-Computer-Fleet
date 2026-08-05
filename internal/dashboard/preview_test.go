package dashboard

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestRedactSecretsMasksSecretShapes(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		leak    string // substring that must NOT survive
		wantRed bool
	}{
		{
			name:    "private key block",
			in:      "key:\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
			leak:    "b3BlbnNzaC1rZXktdjEAAAAA",
			wantRed: true,
		},
		{name: "aws access key", in: "id = AKIAIOSFODNN7EXAMPLE", leak: "AKIAIOSFODNN7EXAMPLE", wantRed: true},
		{name: "password assignment", in: `{"password":"hunter2supersecret"}`, leak: "hunter2supersecret", wantRed: true},
		{name: "token assignment", in: "ANTHROPIC_AUTH_TOKEN=sk-abc123def456", leak: "sk-abc123def456", wantRed: true},
		{name: "benign code", in: "def move(snake):\n    return snake.head + 1\n", leak: "", wantRed: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, red := redactSecrets(c.in)
			if red != c.wantRed {
				t.Fatalf("redacted=%v want %v (out=%q)", red, c.wantRed, out)
			}
			if c.leak != "" && contains(out, c.leak) {
				t.Fatalf("secret %q survived redaction: %q", c.leak, out)
			}
		})
	}
}

func TestIsBinaryContent(t *testing.T) {
	if !isBinaryContent([]byte{0x7f, 0x45, 0x4c, 0x46, 0x00, 0x01}) {
		t.Fatal("NUL-containing bytes should be binary")
	}
	if isBinaryContent([]byte("print('snake')\n")) {
		t.Fatal("utf-8 text should not be binary")
	}
}

func TestLooksLikeDiff(t *testing.T) {
	if !looksLikeDiff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n") {
		t.Fatal("git diff should be detected")
	}
	if looksLikeDiff(`{"schema":"object"}`) {
		t.Fatal("json should not be a diff")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestDashboardEventsDrilldownByRefs(t *testing.T) {
	db := newDashboardTestDB(t)
	insertDashboardEvent(t, db, "evt-secret", "secret_path", `{"path":"/workspace/.aws/credentials"}`)
	insertDashboardEvent(t, db, "evt-egress", "metadata_ip", `{"dst_ip":"169.254.169.254"}`)

	req := httptest.NewRequest("GET", "/api/events?run=run-dash&refs=runtime_event/evt-egress", nil)
	rec := httptest.NewRecorder()
	(Server{DB: db}).events(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Total  int `json:"total"`
		Events []struct {
			ID        string `json:"id"`
			EventType string `json:"event_type"`
		} `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 1 || len(out.Events) != 1 || out.Events[0].ID != "evt-egress" {
		t.Fatalf("unexpected drilldown result: %+v", out)
	}
}

func TestDashboardEventSelfLaunchedBadge(t *testing.T) {
	db := newDashboardTestDB(t)
	// A kernel sensor event that matched a record-launched binding: it is
	// independently witnessed (kernel_correlated) AND self_launched -- the two
	// dimensions are orthogonal, which is the whole point of option 2.
	if _, err := db.Exec(`INSERT INTO events
		(id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, correlation_method, correlation_confidence, binding_source, pid, ppid, created_at)
		VALUES ('evt-self', 'run-dash', 'session-dash', 'tool-dash', 'proc-dash', 'agentprov_ebpf', 'execve', '{"argv":["ls"]}', 'cgroup_time_window:cgroup_id+time', 0.98, 'zero_sdk_record', 4242, 4000, '2026-06-30T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/api/events?run=run-dash&focus=runtime_event/evt-self", nil)
	rec := httptest.NewRecorder()
	(Server{DB: db}).events(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Events []struct {
			ID               string `json:"id"`
			CorrelationClass string `json:"correlation_class"`
			SelfLaunched     bool   `json:"self_launched"`
		} `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Events) != 1 {
		t.Fatalf("want 1 event, got %+v", out)
	}
	if out.Events[0].CorrelationClass != "kernel_correlated" {
		t.Errorf("correlation_class = %q, want kernel_correlated", out.Events[0].CorrelationClass)
	}
	if !out.Events[0].SelfLaunched {
		t.Errorf("self_launched = false, want true (record-launched sensor event)")
	}
}

func TestDashboardEventsNetworkGroup(t *testing.T) {
	db := newDashboardTestDB(t)
	insertDashboardEvent(t, db, "evt-dns", "private_cidr", `{"dst_ip":"127.0.0.53"}`)
	insertDashboardEvent(t, db, "evt-egress", "metadata_ip", `{"dst_ip":"169.254.169.254"}`)

	req := httptest.NewRequest("GET", "/api/events?run=run-dash&lens=network-egress&group=risky_egress", nil)
	rec := httptest.NewRecorder()
	(Server{DB: db}).events(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Total  int `json:"total"`
		Events []struct {
			ID string `json:"id"`
		} `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 1 || out.Events[0].ID != "evt-egress" {
		t.Fatalf("risky egress should exclude loopback private_cidr: %+v", out)
	}
}

func TestDashboardEventsProcessBurstGroup(t *testing.T) {
	db := newDashboardTestDB(t)
	insertDashboardEvent(t, db, "evt-exec", "execve", `{"comm":"python3"}`)
	insertDashboardEvent(t, db, "evt-exit", "process_exit", `{"exit_code":0}`)

	req := httptest.NewRequest("GET", "/api/events?run=run-dash&lens=process&group=process_exit&focus=tool-dash", nil)
	rec := httptest.NewRecorder()
	(Server{DB: db}).events(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Total  int `json:"total"`
		Events []struct {
			ID        string `json:"id"`
			EventType string `json:"event_type"`
		} `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 1 || out.Events[0].ID != "evt-exit" || out.Events[0].EventType != "process_exit" {
		t.Fatalf("process burst should filter by tool_call + event_type: %+v", out)
	}
}

func TestDashboardFrameworks(t *testing.T) {
	db := newDashboardTestDB(t)
	req := httptest.NewRequest("GET", "/api/frameworks", nil)
	rec := httptest.NewRecorder()
	(Server{DB: db}).frameworks(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out []struct {
		ID       string `json:"id"`
		Title    string `json:"title"`
		Controls int    `json:"controls"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	// Both built-in frameworks must be advertised, each with controls.
	byID := map[string]int{}
	for _, f := range out {
		byID[f.ID] = f.Controls
	}
	if byID["owasp-asi"] == 0 {
		t.Fatalf("owasp-asi missing or has no controls: %+v", out)
	}
	if len(out) < 2 {
		t.Fatalf("expected at least 2 frameworks, got %d: %+v", len(out), out)
	}
}

func TestDashboardComplianceMapsRun(t *testing.T) {
	db := newDashboardTestDB(t)
	insertDashboardEvent(t, db, "evt-secret", "secret_path", `{"path":"/workspace/.aws/credentials"}`)

	req := httptest.NewRequest("GET", "/api/compliance?run=run-dash&framework=owasp-asi", nil)
	rec := httptest.NewRecorder()
	(Server{DB: db}).compliance(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var rep struct {
		Framework string `json:"framework"`
		Summary   struct {
			Total int `json:"total"`
		} `json:"summary"`
		Items []struct {
			Status string `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Framework != "owasp-asi" || rep.Summary.Total == 0 || len(rep.Items) == 0 {
		t.Fatalf("expected a populated owasp-asi report, got %+v", rep)
	}
}

func insertPolicyDecision(t *testing.T, db *sql.DB, id, rule, decision string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO policy_decisions (id, event_id, run_id, session_id, rule_id, decision, reason, created_at)
		VALUES (?, '', 'run-dash', 'session-dash', ?, ?, 'test', '2026-06-30T00:00:00Z')`, id, rule, decision); err != nil {
		t.Fatal(err)
	}
}

func TestDashboardComplianceRuleStates(t *testing.T) {
	db := newDashboardTestDB(t)
	// secret_path_access -> ASI03, enforce-mode rule, killed -> enforced.
	insertPolicyDecision(t, db, "dec-kill", "secret_path_access", "kill")
	// supply_chain_install -> ASI04, detect-mode rule fires as "audit"
	// (observed, not blocked) -> detected.
	insertPolicyDecision(t, db, "dec-audit", "supply_chain_install", "audit")

	req := httptest.NewRequest("GET", "/api/compliance?run=run-dash&framework=owasp-asi", nil)
	rec := httptest.NewRecorder()
	(Server{DB: db}).compliance(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var rep struct {
		Summary map[string]int `json:"summary"`
		Items   []struct {
			ControlID string `json:"control_id"`
			Status    string `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	st := map[string]string{}
	for _, it := range rep.Items {
		st[it.ControlID] = it.Status
	}
	// ASI03: enforce rule fired and blocked -> enforced.
	if st["ASI03"] != "enforced" {
		t.Fatalf("ASI03 want enforced (killed secret access), got %q", st["ASI03"])
	}
	// ASI04: detect-mode rule fired but did not block -> detected.
	if st["ASI04"] != "detected" {
		t.Fatalf("ASI04 want detected (detect-mode install), got %q", st["ASI04"])
	}
	// ASI05: ptrace_access maps here but did not fire -> not_triggered.
	if st["ASI05"] != "not_triggered" {
		t.Fatalf("ASI05 want not_triggered (rule mapped, not fired), got %q", st["ASI05"])
	}
	// ASI01: no rule maps to it -> no_rule (honest gap, NOT a clean pass).
	if st["ASI01"] != "no_rule" {
		t.Fatalf("ASI01 want no_rule (no detector), got %q", st["ASI01"])
	}
	if rep.Summary["enforced"] < 1 || rep.Summary["detected"] < 1 || rep.Summary["no_rule"] < 1 {
		t.Fatalf("summary should count enforced+detected+no_rule, got %+v", rep.Summary)
	}
}

func TestDashboardComplianceUnknownFramework(t *testing.T) {
	db := newDashboardTestDB(t)
	req := httptest.NewRequest("GET", "/api/compliance?run=run-dash&framework=does-not-exist", nil)
	rec := httptest.NewRecorder()
	(Server{DB: db}).compliance(rec, req)
	if rec.Code != 400 {
		t.Fatalf("unknown framework should be 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDashboardOutboundUsesHonestEvidenceClasses(t *testing.T) {
	db := newDashboardTestDB(t)
	if _, err := db.Exec(`INSERT INTO events
		(id, run_id, session_id, process_id, source, event_type, payload, pid, created_at)
		VALUES
		('evt-trace', 'run-dash', 'session-dash', 'proc-grok', 'endpoint_capture', 'network_connect',
		 '{"dst_host":"cli-chat-proxy.grok.com","path":"/traces","bytes":900,"egress_kind":"trace","blocked":false}', 100, '2026-06-30T00:00:00Z'),
		('evt-mixpanel-dns', 'run-dash', 'session-dash', 'proc-grok', 'agentprov_ebpf', 'dns_query',
		 '{"host":"api.mixpanel.com","comm":"grok"}', 100, '2026-06-30T00:00:01Z'),
		('evt-xai-dns', 'run-dash', 'session-dash', 'proc-grok', 'agentprov_ebpf', 'dns_query',
		 '{"host":"cli-chat-proxy.grok.com","comm":"grok"}', 100, '2026-06-30T00:00:02Z')`); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/outbound?run=run-dash", nil)
	rec := httptest.NewRecorder()
	(Server{DB: db}).outbound(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var surfaces []struct {
		ChannelClass  string `json:"channel_class"`
		DataClass     string `json:"data_class"`
		EvidenceLevel string `json:"evidence_level"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &surfaces); err != nil {
		t.Fatal(err)
	}
	if len(surfaces) != 2 {
		t.Fatalf("want telemetry + Mixpanel DNS surfaces, with duplicate xAI DNS suppressed: %+v", surfaces)
	}
	seen := map[string]struct {
		data, evidence string
	}{}
	for _, s := range surfaces {
		seen[s.ChannelClass] = struct{ data, evidence string }{s.DataClass, s.EvidenceLevel}
	}
	if got := seen["telemetry_service"]; got.data != "unknown" || got.evidence != "payload_observed" {
		t.Errorf("trace endpoint must be telemetry payload evidence, got %+v", got)
	}
	if got := seen["product_analytics"]; got.data != "unknown" || got.evidence != "dns_only" {
		t.Errorf("DNS-only analytics endpoint must not claim behavioral payload, got %+v", got)
	}
}

func TestDashboardEgressDoesNotCrossWireDNSAcrossProcesses(t *testing.T) {
	db := newDashboardTestDB(t)
	if _, err := db.Exec(`INSERT INTO events
		(id, run_id, session_id, process_id, source, event_type, payload, pid, created_at)
		VALUES
		('evt-dns-a', 'run-dash', 'session-dash', 'proc-a', 'agentprov_ebpf', 'dns_query',
		 '{"host":"api.example.com","comm":"python"}', 101, '2026-06-30T00:00:00Z'),
		('evt-connect-b', 'run-dash', 'session-dash', 'proc-a', 'agentprov_ebpf', 'network_connect',
		 '{"dst_ip":"203.0.113.8","dst_port":"443","comm":"python"}', 202, '2026-06-30T00:00:01Z')`); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/egress?run=run-dash", nil)
	rec := httptest.NewRecorder()
	(Server{DB: db}).egress(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var rows []struct {
		Type   string `json:"type"`
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("want one DNS observation and one connection: %+v", rows)
	}
	for _, row := range rows {
		if row.Type == "network_connect" && row.Domain != "" {
			t.Fatalf("another process's DNS must not name this connection: %+v", rows)
		}
	}
}

func TestDashboardEgressHidesProxyLoopbackAndShowsEndpointDestination(t *testing.T) {
	db := newDashboardTestDB(t)
	if _, err := db.Exec(`INSERT INTO events
		(id, run_id, session_id, process_id, source, event_type, payload, pid, created_at)
		VALUES
		('evt-loopback', 'run-dash', 'session-dash', 'proc-grok', 'agentprov_ebpf', 'network_connect',
		 '{"dst_ip":"127.0.0.1","dst_port":"8088","comm":"grok"}', 100, '2026-06-30T00:00:00Z'),
		('evt-endpoint', 'run-dash', 'session-dash', 'proc-grok', 'endpoint_capture', 'network_connect',
		 '{"dst_host":"cli-chat-proxy.grok.com","path":"/traces","bytes":900,"egress_kind":"trace","blocked":false,"policy_decision":"observe"}', 100, '2026-06-30T00:00:01Z')`); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/egress?run=run-dash", nil)
	rec := httptest.NewRecorder()
	(Server{DB: db}).egress(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var rows []struct {
		Type string `json:"type"`
		Dst  string `json:"dst"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Type != "endpoint_egress" || rows[0].Dst != "cli-chat-proxy.grok.com" || rows[0].Path != "/traces" {
		t.Fatalf("egress must show remote endpoint instead of local proxy: %+v", rows)
	}
}

func newDashboardTestDB(t *testing.T) *sql.DB {
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

func insertDashboardEvent(t *testing.T, db *sql.DB, id, eventType, payload string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO events
		(id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, correlation_method, correlation_confidence, pid, ppid, created_at)
		VALUES (?, 'run-dash', 'session-dash', 'tool-dash', 'proc-dash', 'agentprov_ebpf', ?, ?, 'container_time_window', 0.92, 4242, 4000, '2026-06-30T00:00:00Z')`,
		id, eventType, payload); err != nil {
		t.Fatal(err)
	}
}
