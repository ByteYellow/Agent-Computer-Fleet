package security

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/signals"
	"gopkg.in/yaml.v3"
)

type Event struct {
	Source     string   `json:"source"`
	EventType  string   `json:"event_type"`
	RunID      string   `json:"run_id"`
	SessionID  string   `json:"session_id"`
	ToolCallID string   `json:"tool_call_id"`
	ProcessID  string   `json:"process_id"`
	SnapshotID string   `json:"snapshot_id"`
	DstIP      string   `json:"dst_ip"`
	Path       string   `json:"path"`
	Args       []string `json:"args"`
}

type Decision struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	RuleID   string `json:"rule_id,omitempty"`
	// Mode records whether the matched rule enforces ("enforce") or only
	// observes ("detect"). Intended is the action the rule WOULD take when it
	// runs in enforce mode, preserved even when a detect-mode match downgrades
	// the effective Decision to "audit" -- the compliance view needs it to show
	// "detected, would have killed" vs "detected and killed".
	Mode     string `json:"mode,omitempty"`
	Intended string `json:"intended_decision,omitempty"`
}

type DecisionRecord struct {
	ID        string `json:"id"`
	EventID   string `json:"event_id"`
	RunID     string `json:"run_id"`
	SessionID string `json:"session_id"`
	RuleID    string `json:"rule_id"`
	Decision  string `json:"decision"`
	Reason    string `json:"reason"`
	CreatedAt string `json:"created_at"`
}

type RiskSignalRecord struct {
	ID                string `json:"id"`
	RunID             string `json:"run_id"`
	SessionID         string `json:"session_id"`
	ToolCallID        string `json:"tool_call_id"`
	ProcessID         string `json:"process_id"`
	SnapshotID        string `json:"snapshot_id"`
	EventID           string `json:"event_id"`
	PolicyDecisionID  string `json:"policy_decision_id"`
	SignalType        string `json:"signal_type"`
	Severity          string `json:"severity"`
	Reason            string `json:"reason"`
	RecommendedAction string `json:"recommended_action"`
	Payload           string `json:"payload"`
	CreatedAt         string `json:"created_at"`
}

type ResponseActionRecord struct {
	ID               string `json:"id"`
	RunID            string `json:"run_id"`
	SessionID        string `json:"session_id"`
	ProcessID        string `json:"process_id"`
	SnapshotID       string `json:"snapshot_id"`
	RiskSignalID     string `json:"risk_signal_id"`
	PolicyDecisionID string `json:"policy_decision_id"`
	ActionType       string `json:"action_type"`
	TargetType       string `json:"target_type"`
	TargetID         string `json:"target_id"`
	Status           string `json:"status"`
	ResultRef        string `json:"result_ref"`
	Payload          string `json:"payload"`
	CreatedAt        string `json:"created_at"`
}

type QueryRefs struct {
	Drilldowns []string `json:"drilldowns"`
}

type RiskSignalView struct {
	Risk  RiskSignalRecord `json:"risk"`
	Query QueryRefs        `json:"query"`
}

type ResponseActionView struct {
	Response ResponseActionRecord `json:"response"`
	Query    QueryRefs            `json:"query"`
}

type RiskSignalsReport struct {
	SchemaVersion string           `json:"schema_version"`
	RunID         string           `json:"run_id,omitempty"`
	ResultSetID   string           `json:"result_set_id"`
	PageHash      string           `json:"page_hash"`
	Count         int              `json:"count"`
	Risks         []RiskSignalView `json:"risks"`
}

type ResponseActionsReport struct {
	SchemaVersion string               `json:"schema_version"`
	RunID         string               `json:"run_id,omitempty"`
	ResultSetID   string               `json:"result_set_id"`
	PageHash      string               `json:"page_hash"`
	Count         int                  `json:"count"`
	Responses     []ResponseActionView `json:"responses"`
}

type Engine struct {
	SecretPathPatterns []string
	Rules              []Rule
}

func DefaultEngine() Engine {
	return Engine{SecretPathPatterns: []string{".env", "id_rsa", "secret", "credentials"}, Rules: DefaultRules()}
}

type Rule struct {
	ID       string    `yaml:"id" json:"id"`
	Match    RuleMatch `yaml:"match" json:"match"`
	Decision string    `yaml:"decision" json:"decision"`
	Reason   string    `yaml:"reason" json:"reason"`
	// Mode is "enforce" (default when empty) or "detect". A detect rule records
	// the would-be decision as an audit signal but takes no kill/quarantine
	// action -- the run is observed, not blocked. This is what makes the
	// compliance view's "detected, not enforced" state real rather than cosmetic.
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`
	// Controls are the compliance control IDs (e.g. ASI03, Q1) this rule maps
	// to. The detection engine treats them as opaque tags; the compliance layer
	// reads them to answer "which control is covered by which rule, and did it
	// fire". Custom YAML rules set this to map themselves onto a framework.
	Controls []string `yaml:"controls,omitempty" json:"controls,omitempty"`
}

func (r Rule) detectMode() bool { return strings.EqualFold(r.Mode, "detect") }

// IsEnforcingDecision reports whether a recorded decision actually blocked the
// action (as opposed to "allow" or a detect-mode "audit"). The compliance view
// uses it to split fired rules into enforced vs detected-only.
func IsEnforcingDecision(decision string) bool {
	switch decision {
	case "deny", "quarantine", "kill":
		return true
	}
	return false
}

type RuleMatch struct {
	Source       string   `yaml:"source"`
	EventType    string   `yaml:"event_type"`
	DstIP        string   `yaml:"dst_ip"`
	PrivateCIDR  bool     `yaml:"private_cidr"`
	PathContains []string `yaml:"path_contains"`
	ArgsContains []string `yaml:"args_contains"`
}

type RuleFile struct {
	Rules []Rule `yaml:"rules"`
}

func DefaultRules() []Rule {
	return []Rule{
		{
			ID:       "metadata_ip_dst",
			Match:    RuleMatch{DstIP: "169.254.169.254"},
			Decision: "quarantine",
			Reason:   "metadata IP access",
			Controls: []string{"ASI03", "Q1", "Q2"},
		},
		{
			ID:       "metadata_ip_args",
			Match:    RuleMatch{ArgsContains: []string{"169.254.169.254"}},
			Decision: "quarantine",
			Reason:   "metadata IP access",
			Controls: []string{"ASI03", "Q1", "Q2"},
		},
		{
			ID:       "private_cidr_access",
			Match:    RuleMatch{PrivateCIDR: true},
			Decision: "deny",
			Reason:   "private CIDR access",
			Controls: []string{"ASI02", "Q1", "Q2"},
		},
		{
			// The agent reading its OWN operational credentials (Claude Code's
			// creds, its LLM API env) is normal, not exfil. Ranked BEFORE
			// secret_path_access and set to allow so these reads are still
			// CAPTURED as events (full observability) but raise no alert. This is
			// a DEFAULT-policy convenience, not a security judgement: override the
			// list via a custom rules file (`agentprov policy rules` to get
			// an editable copy) to match your own infra secret paths.
			ID:       "self_credential_access",
			Match:    RuleMatch{PathContains: []string{".claude/", "deepseek-claude.env", ".agentprov-demo/", ".agentprov/"}},
			Decision: "allow",
			Reason:   "agent's own credential/config access (not an exfil target)",
			Controls: []string{"ASI03"},
		},
		{
			ID:       "secret_path_access",
			Match:    RuleMatch{PathContains: []string{".env", "id_rsa", "secret", "credentials"}},
			Decision: "kill",
			Reason:   "secret path access",
			Controls: []string{"ASI03", "Q1", "Q2"},
		},
		{
			// Synthetic marker injected by runtimeEventForPolicy only for a
			// setuid/setgid TO ROOT, so the benign privilege-drop the container
			// runtime does (setuid to an unprivileged id) is not flagged.
			ID:       "privilege_escalation",
			Match:    RuleMatch{ArgsContains: []string{"setuid_root", "setgid_root"}},
			Decision: "quarantine",
			Reason:   "privilege escalation to root",
			Controls: []string{"ASI03", "Q1", "Q2"},
		},
		{
			ID:       "ptrace_access",
			Match:    RuleMatch{EventType: "ptrace"},
			Decision: "quarantine",
			Reason:   "process injection (ptrace)",
			Controls: []string{"ASI05", "Q1", "Q2"},
		},
		// --- detect-mode rules (observe, do not block) -------------------------
		// These cover controls that have a real event source the sensor emits, so
		// they are NOT phantom rules: when the matching activity happens they
		// genuinely fire. They default to detect so the compliance view can show
		// "this threat was seen but not blocked" -- the honest default posture.
		{
			// Package-install commands captured from execve argv. Supply-chain
			// risk is real but blocking every install is too aggressive a default,
			// so this observes and surfaces it for review.
			ID:       "supply_chain_install",
			Match:    RuleMatch{ArgsContains: []string{"pip install", "pip3 install", "npm install", "npm i ", "poetry add", "uv pip install"}},
			Decision: "quarantine",
			Reason:   "dependency install (supply-chain surface)",
			Mode:     "detect",
			Controls: []string{"ASI04", "Q1", "Q3"},
		},
		{
			// Emitted by the eBPF sensor when a process tree looks anomalous.
			ID:       "anomalous_process_tree",
			Match:    RuleMatch{EventType: "abnormal_process_tree"},
			Decision: "quarantine",
			Reason:   "anomalous process tree (possible rogue behaviour)",
			Mode:     "detect",
			Controls: []string{"ASI10", "Q1", "Q3"},
		},
		{
			// Sensor ringbuf back-pressure / event-drop -- a cascade/resource
			// exhaustion indicator.
			ID:       "resource_pressure",
			Match:    RuleMatch{EventType: "resource_pressure"},
			Decision: "deny",
			Reason:   "resource pressure / event drop (cascade risk)",
			Mode:     "detect",
			Controls: []string{"ASI08", "Q3"},
		},
	}
}

// DefaultRulesYAML renders the built-in policy as an editable YAML rules file, so
// an operator can dump it, tune the allow/detect lists (e.g. which credential
// paths count as the agent's own infra vs an exfil target), and load it back via
// LoadEngine / `policy test --rules`.
func DefaultRulesYAML() ([]byte, error) {
	return yaml.Marshal(RuleFile{Rules: DefaultRules()})
}

func LoadEngine(path string) (Engine, error) {
	if path == "" {
		return DefaultEngine(), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Engine{}, err
	}
	var file RuleFile
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return Engine{}, err
	}
	engine := Engine{Rules: file.Rules}
	if len(engine.Rules) == 0 {
		return Engine{}, fmt.Errorf("policy rule file has no rules")
	}
	return engine, nil
}

func (e Engine) Evaluate(event Event) Decision {
	if len(e.Rules) > 0 {
		for _, rule := range e.Rules {
			if rule.Matches(event) {
				reason := rule.Reason
				if reason == "" {
					reason = rule.ID
				}
				if rule.detectMode() {
					// Observe-only: downgrade the effective action to "audit" so
					// persistDecision records the signal but skips the kill/
					// quarantine side effects. Keep the intended action visible.
					return Decision{
						Decision: "audit",
						Reason:   reason + " (detect-only; would " + rule.Decision + ")",
						RuleID:   rule.ID,
						Mode:     "detect",
						Intended: rule.Decision,
					}
				}
				return Decision{Decision: rule.Decision, Reason: reason, RuleID: rule.ID, Mode: "enforce", Intended: rule.Decision}
			}
		}
	}
	return Decision{Decision: "allow", Reason: "no policy matched"}
}

func (r Rule) Matches(event Event) bool {
	if r.Match.Source != "" && r.Match.Source != event.Source {
		return false
	}
	if r.Match.EventType != "" && r.Match.EventType != event.EventType {
		return false
	}
	if r.Match.DstIP != "" && event.DstIP != r.Match.DstIP && !strings.Contains(strings.Join(event.Args, " "), r.Match.DstIP) {
		return false
	}
	if r.Match.PrivateCIDR && !isPrivateIP(event.DstIP) {
		return false
	}
	// Content matchers: path_contains and args_contains. When either is set, at
	// least one specified pattern (across BOTH dimensions) must match. Evaluate
	// both before deciding, so a rule that sets both can still match on args when
	// the path does not -- previously PathContains short-circuited to false and
	// ArgsContains was never consulted for such a rule.
	if len(r.Match.PathContains) > 0 || len(r.Match.ArgsContains) > 0 {
		for _, pattern := range r.Match.PathContains {
			if pattern != "" && strings.Contains(event.Path, pattern) {
				return true
			}
		}
		joinedArgs := strings.Join(event.Args, " ")
		for _, pattern := range r.Match.ArgsContains {
			if pattern != "" && strings.Contains(joinedArgs, pattern) {
				return true
			}
		}
		return false
	}
	return r.Match.Source != "" || r.Match.EventType != "" || r.Match.DstIP != "" || r.Match.PrivateCIDR
}

func EvaluateJSONL(path string, out io.Writer) error {
	return EvaluateJSONLWithEngine(nil, path, out, DefaultEngine())
}

func EvaluateJSONLWithState(db *sql.DB, path string, out io.Writer) error {
	return EvaluateJSONLWithEngine(db, path, out, DefaultEngine())
}

func EvaluateJSONLWithEngine(db *sql.DB, path string, out io.Writer, engine Engine) error {
	return evaluateJSONL(path, out, db, engine)
}

func EvaluateAndPersist(db *sql.DB, event Event, rawPayload string) (DecisionRecord, error) {
	decision := DefaultEngine().Evaluate(event)
	return persistDecision(db, event, rawPayload, decision)
}

func EvaluateRuntimeEvent(db *sql.DB, eventID string) (DecisionRecord, bool, error) {
	return EvaluateRuntimeEventWithEngine(db, eventID, DefaultEngine())
}

func EvaluateRuntimeEventWithEngine(db *sql.DB, eventID string, engine Engine) (DecisionRecord, bool, error) {
	event, rawPayload, err := runtimeEventForPolicy(db, eventID)
	if err != nil {
		return DecisionRecord{}, false, err
	}
	decision := engine.Evaluate(event)
	if decision.Decision == "allow" {
		return DecisionRecord{}, false, nil
	}
	record, err := persistDecisionForEventID(db, eventID, event, rawPayload, decision)
	return record, true, err
}

func PersistDecision(db *sql.DB, event Event, rawPayload string, decision Decision) (DecisionRecord, error) {
	return persistDecision(db, event, rawPayload, decision)
}

// PersistDenyForEvent attaches a deny policy decision -- plus its risk signal,
// response action, unified security signal, and graph edges -- to an
// already-stored runtime event, in the exact same verifiable chain the rule
// engine writes. It is for out-of-band enforcers (e.g. the endpoint egress
// blocker that DENIED a codebase upload the rule engine never saw): the block
// becomes a first-class risk -> response node attributed to the event's
// session/process, so it renders as one chain with the rest of the run.
func PersistDenyForEvent(db *sql.DB, eventID, ruleID, reason string) (DecisionRecord, error) {
	event, rawPayload, err := runtimeEventForPolicy(db, eventID)
	if err != nil {
		return DecisionRecord{}, err
	}
	return persistDecisionForEventID(db, eventID, event, rawPayload,
		Decision{Decision: "deny", RuleID: ruleID, Reason: reason})
}

// ReevaluateRun re-runs the policy engine over a run's already-captured runtime
// events, replacing the derived security layer (policy_decisions -> risk_signals
// -> response_actions -> unified signals + their graph edges) with fresh verdicts
// from `engine`. The raw events are UNTOUCHED -- full observability is preserved;
// only the "what did policy conclude" layer is recomputed. Deterministic (no
// model, no sensor): same events + same rules = same result. Pairs with
// `policy rules` for an edit-rules -> replay-history workflow.
//
// It is idempotent (the clear step below fully removes the prior layer), so a
// re-run or a mid-way failure is safe to retry. It does NOT retroactively reset
// session/process status a prior enforce set -- those record what the earlier
// policy actually did.
func ReevaluateRun(db *sql.DB, runID string, engine Engine) (evaluated int, alerts int, err error) {
	if runID == "" {
		return 0, 0, fmt.Errorf("reevaluate: run id is required")
	}
	if len(engine.Rules) == 0 {
		engine = DefaultEngine()
	}
	clears := []struct {
		q string
		a []any
	}{
		{`DELETE FROM graph_edges WHERE run_id = ? AND edge_type IN ('policy_decision_risk_signal','runtime_event_policy_decision','policy_decision_session','risk_signal_response_action')`, []any{runID}},
		{`DELETE FROM signals WHERE run_id = ? AND source_table = 'risk_signals'`, []any{runID}},
		{`DELETE FROM response_actions WHERE run_id = ?`, []any{runID}},
		{`DELETE FROM risk_signals WHERE run_id = ?`, []any{runID}},
		{`DELETE FROM policy_decisions WHERE run_id = ?`, []any{runID}},
		// Only the policy-derived cost rows (block/quarantine counters); token-cost
		// samples have both counters zero and are left alone.
		{`DELETE FROM cost_samples WHERE run_id = ? AND (policy_block_count > 0 OR quarantine_count > 0)`, []any{runID}},
	}
	for _, c := range clears {
		if _, e := db.Exec(c.q, c.a...); e != nil {
			return 0, 0, fmt.Errorf("reevaluate clear: %w", e)
		}
	}
	// Collect event ids first (cursor closed before the re-eval writes, to avoid
	// the single-connection nested-cursor footgun).
	rows, e := db.Query(`SELECT id FROM events WHERE run_id = ? ORDER BY created_at ASC, id ASC`, runID)
	if e != nil {
		return 0, 0, e
	}
	var eventIDs []string
	for rows.Next() {
		var id string
		if e := rows.Scan(&id); e != nil {
			rows.Close()
			return 0, 0, e
		}
		eventIDs = append(eventIDs, id)
	}
	rows.Close()
	for _, id := range eventIDs {
		_, persisted, e := EvaluateRuntimeEventWithEngine(db, id, engine)
		if e != nil {
			return evaluated, alerts, fmt.Errorf("reevaluate event %s: %w", id, e)
		}
		evaluated++
		if persisted {
			alerts++
		}
	}
	return evaluated, alerts, nil
}

func ListDecisions(db *sql.DB, runID string) ([]DecisionRecord, error) {
	query := `SELECT id, COALESCE(event_id, ''), COALESCE(run_id, ''), COALESCE(session_id, ''), COALESCE(rule_id, ''), decision, reason, created_at
		FROM policy_decisions`
	args := []any{}
	if runID != "" {
		query += ` WHERE run_id = ?`
		args = append(args, runID)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []DecisionRecord
	for rows.Next() {
		var record DecisionRecord
		if err := rows.Scan(&record.ID, &record.EventID, &record.RunID, &record.SessionID, &record.RuleID, &record.Decision, &record.Reason, &record.CreatedAt); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func ListRiskSignals(db *sql.DB, runID string) ([]RiskSignalRecord, error) {
	query := `SELECT id, run_id, session_id, tool_call_id, process_id, snapshot_id, event_id, policy_decision_id,
		signal_type, severity, reason, recommended_action, payload, created_at FROM risk_signals`
	args := []any{}
	if runID != "" {
		query += ` WHERE run_id = ?`
		args = append(args, runID)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []RiskSignalRecord
	for rows.Next() {
		var record RiskSignalRecord
		if err := rows.Scan(&record.ID, &record.RunID, &record.SessionID, &record.ToolCallID, &record.ProcessID, &record.SnapshotID, &record.EventID, &record.PolicyDecisionID, &record.SignalType, &record.Severity, &record.Reason, &record.RecommendedAction, &record.Payload, &record.CreatedAt); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func BuildRiskSignalsReport(db *sql.DB, runID string) (RiskSignalsReport, error) {
	records, err := ListRiskSignals(db, runID)
	if err != nil {
		return RiskSignalsReport{}, err
	}
	views := make([]RiskSignalView, 0, len(records))
	for _, record := range records {
		views = append(views, RiskSignalView{Risk: record, Query: QueryRefs{Drilldowns: riskDrilldowns(record)}})
	}
	report := RiskSignalsReport{
		SchemaVersion: "agentprovenance.security_risks/v1",
		RunID:         runID,
		Count:         len(views),
		Risks:         views,
	}
	resultSetID, pageHash, err := securityReportIntegrity("security_risks", runID, views)
	if err == nil {
		report.ResultSetID = resultSetID
		report.PageHash = pageHash
	}
	return report, nil
}

func ListResponseActions(db *sql.DB, runID string) ([]ResponseActionRecord, error) {
	query := `SELECT id, run_id, session_id, process_id, snapshot_id, risk_signal_id, policy_decision_id,
		action_type, target_type, target_id, status, result_ref, payload, created_at FROM response_actions`
	args := []any{}
	if runID != "" {
		query += ` WHERE run_id = ?`
		args = append(args, runID)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []ResponseActionRecord
	for rows.Next() {
		var record ResponseActionRecord
		if err := rows.Scan(&record.ID, &record.RunID, &record.SessionID, &record.ProcessID, &record.SnapshotID, &record.RiskSignalID, &record.PolicyDecisionID, &record.ActionType, &record.TargetType, &record.TargetID, &record.Status, &record.ResultRef, &record.Payload, &record.CreatedAt); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func BuildResponseActionsReport(db *sql.DB, runID string) (ResponseActionsReport, error) {
	records, err := ListResponseActions(db, runID)
	if err != nil {
		return ResponseActionsReport{}, err
	}
	views := make([]ResponseActionView, 0, len(records))
	for _, record := range records {
		views = append(views, ResponseActionView{Response: record, Query: QueryRefs{Drilldowns: responseDrilldowns(record)}})
	}
	report := ResponseActionsReport{
		SchemaVersion: "agentprovenance.security_responses/v1",
		RunID:         runID,
		Count:         len(views),
		Responses:     views,
	}
	resultSetID, pageHash, err := securityReportIntegrity("security_responses", runID, views)
	if err == nil {
		report.ResultSetID = resultSetID
		report.PageHash = pageHash
	}
	return report, nil
}

func riskDrilldowns(record RiskSignalRecord) []string {
	return uniqueCommands([]string{
		command(record.EventID != "", "observe event --run "+record.RunID+" --event "+record.EventID),
		command(record.EventID != "", "graph explain --event "+record.EventID),
		command(record.ProcessID != "", "observe process --run "+record.RunID+" --process "+record.ProcessID),
		command(record.ToolCallID != "", "timeline --run "+record.RunID+" --tool-call "+record.ToolCallID+" --view causality"),
		command(record.PolicyDecisionID != "", "graph explain --risk "+record.PolicyDecisionID),
	})
}

func responseDrilldowns(record ResponseActionRecord) []string {
	return uniqueCommands([]string{
		command(record.ProcessID != "", "observe process --run "+record.RunID+" --process "+record.ProcessID),
		command(record.RiskSignalID != "", "security risks --run "+record.RunID+" --json"),
		command(record.PolicyDecisionID != "", "graph explain --risk "+record.PolicyDecisionID),
		command(record.TargetType == "session" && record.TargetID != "", "timeline --run "+record.RunID+" --view causality"),
	})
}

func command(ok bool, value string) string {
	if !ok {
		return ""
	}
	return value
}

func uniqueCommands(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func securityReportIntegrity(kind, runID string, items any) (string, string, error) {
	resultSetID, err := digestSecurity(map[string]any{
		"kind":   kind + "_result_set",
		"run_id": runID,
		"items":  items,
	})
	if err != nil {
		return "", "", err
	}
	pageHash, err := digestSecurity(map[string]any{
		"kind":          kind + "_page",
		"result_set_id": resultSetID,
		"items":         items,
	})
	if err != nil {
		return "", "", err
	}
	return resultSetID, pageHash, nil
}

func digestSecurity(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func evaluateJSONL(path string, out io.Writer, db *sql.DB, engine Engine) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return err
		}
		decision := engine.Evaluate(event)
		if db != nil {
			if _, err := persistDecision(db, event, line, decision); err != nil {
				return err
			}
		}
		row := map[string]any{"event": event, "rule_id": decision.RuleID, "decision": decision.Decision, "reason": decision.Reason}
		b, _ := json.Marshal(row)
		fmt.Fprintln(out, string(b))
	}
	return scanner.Err()
}

func persistDecision(db *sql.DB, event Event, rawPayload string, decision Decision) (DecisionRecord, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	eventID := ids.New("evt")
	_, err := db.Exec(`INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, snapshot_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, eventID, event.RunID, event.SessionID, event.ToolCallID, event.ProcessID, event.SnapshotID, event.Source, event.EventType, rawPayload, now)
	if err != nil {
		return DecisionRecord{}, err
	}
	return persistDecisionWithExistingEvent(db, eventID, event, rawPayload, decision, now)
}

func persistDecisionForEventID(db *sql.DB, eventID string, event Event, rawPayload string, decision Decision) (DecisionRecord, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return persistDecisionWithExistingEvent(db, eventID, event, rawPayload, decision, now)
}

func persistDecisionWithExistingEvent(db *sql.DB, eventID string, event Event, rawPayload string, decision Decision, now string) (DecisionRecord, error) {
	record := DecisionRecord{
		ID:        ids.New("dec"),
		EventID:   eventID,
		RunID:     event.RunID,
		SessionID: event.SessionID,
		RuleID:    decision.RuleID,
		Decision:  decision.Decision,
		Reason:    decision.Reason,
		CreatedAt: now,
	}
	_, err := db.Exec(`INSERT INTO policy_decisions (id, event_id, run_id, session_id, rule_id, decision, reason, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, record.ID, eventID, event.RunID, event.SessionID, decision.RuleID, decision.Decision, decision.Reason, now)
	if err != nil {
		return DecisionRecord{}, err
	}
	policyNodeID := "policy_decision/" + record.ID
	var riskSignalID string
	if decision.Decision != "allow" {
		riskSignalID = ids.New("risk")
		severity := severityForDecision(decision.Decision)
		recommendedAction := recommendedActionForDecision(decision.Decision)
		payload, _ := json.Marshal(map[string]any{
			"source":     event.Source,
			"event_type": event.EventType,
			"dst_ip":     event.DstIP,
			"path":       event.Path,
			"args":       event.Args,
			"rule_id":    decision.RuleID,
			"decision":   decision.Decision,
		})
		_, err = db.Exec(`INSERT INTO risk_signals
			(id, run_id, session_id, tool_call_id, process_id, snapshot_id, event_id, policy_decision_id,
			 signal_type, severity, reason, recommended_action, payload, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			riskSignalID, event.RunID, event.SessionID, event.ToolCallID, event.ProcessID, event.SnapshotID, eventID, record.ID,
			"policy_violation", severity, decision.Reason, recommendedAction, string(payload), now)
		if err != nil {
			return DecisionRecord{}, err
		}
		// Live-project into the unified signal model (the infra contract).
		// Best-effort and idempotent on (source_table, source_id): a later
		// signals.Backfill will not duplicate this row.
		sigKind, sigID := "run", event.RunID
		if event.ProcessID != "" {
			sigKind, sigID = "process", event.ProcessID
		} else if event.ToolCallID != "" {
			sigKind, sigID = "tool_call", event.ToolCallID
		}
		if _, sigErr := signals.Record(db, signals.Signal{
			Dimension: signals.Security, Type: "policy_violation",
			GraphRefKind: sigKind, GraphRefID: sigID,
			RunID: event.RunID, SessionID: event.SessionID, ToolCallID: event.ToolCallID,
			ProcessID: event.ProcessID, EventID: eventID,
			Severity: severity, Reference: decision.Reason, RecommendedAction: recommendedAction,
			ProducedBy: "security.policy", Payload: string(payload), CreatedAt: now,
			SourceTable: "risk_signals", SourceID: riskSignalID,
		}); sigErr != nil {
			// Unified-signal writeback must not fail silently: emit an observable
			// error event (does not block the policy decision).
			errPayload, _ := json.Marshal(map[string]any{
				"error":              sigErr.Error(),
				"risk_signal_id":     riskSignalID,
				"policy_decision_id": record.ID,
				"dimension":          "security",
			})
			_, _ = db.Exec(`INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, created_at)
				VALUES (?, ?, ?, ?, ?, 'signal_writeback', 'unified_signal_write_failed', ?, ?)`,
				ids.New("evt"), event.RunID, event.SessionID, event.ToolCallID, event.ProcessID, string(errPayload), now)
		}
		_, _ = db.Exec(`INSERT OR REPLACE INTO graph_edges (id, run_id, from_id, to_id, edge_type, source_event_id, created_at)
			VALUES (?, ?, ?, ?, 'policy_decision_risk_signal', ?, ?)`,
			ids.New("edge"), event.RunID, policyNodeID, "risk_signal/"+riskSignalID, eventID, now)
	}
	_, _ = db.Exec(`INSERT OR REPLACE INTO graph_edges (id, run_id, from_id, to_id, edge_type, source_event_id, created_at)
		VALUES (?, ?, ?, ?, 'runtime_event_policy_decision', ?, ?)`,
		ids.New("edge"), event.RunID, "runtime_event/"+eventID, policyNodeID, eventID, now)
	if event.SessionID != "" {
		_, _ = db.Exec(`INSERT OR REPLACE INTO graph_edges (id, run_id, from_id, to_id, edge_type, source_event_id, created_at)
			VALUES (?, ?, ?, ?, 'policy_decision_session', ?, ?)`,
			ids.New("edge"), event.RunID, policyNodeID, event.SessionID, eventID, now)
	}
	blockCount := int64(0)
	quarantineCount := int64(0)
	if IsEnforcingDecision(decision.Decision) {
		blockCount = 1
	}
	switch decision.Decision {
	case "quarantine":
		quarantineCount = 1
		if event.SessionID != "" {
			_, _ = db.Exec(`UPDATE sessions SET status = 'quarantined', updated_at = ? WHERE id = ?`, now, event.SessionID)
			_, _ = db.Exec(`UPDATE snapshots SET status = 'tainted' WHERE session_id = ?`, event.SessionID)
		}
	case "kill":
		if event.SessionID != "" {
			_, _ = db.Exec(`UPDATE sessions SET status = 'stopped', updated_at = ? WHERE id = ?`, now, event.SessionID)
			_, _ = db.Exec(`UPDATE snapshots SET status = 'tainted' WHERE session_id = ?`, event.SessionID)
		}
		if event.ProcessID != "" {
			_, _ = db.Exec(`UPDATE processes SET status = 'killed', ended_at = ? WHERE id = ?`, now, event.ProcessID)
		}
	}
	if decision.Decision != "allow" {
		actionType := recommendedActionForDecision(decision.Decision)
		targetType, targetID := responseTarget(event, actionType)
		actionID := ids.New("action")
		payload, _ := json.Marshal(map[string]any{
			"decision": decision.Decision,
			"rule_id":  decision.RuleID,
			"reason":   decision.Reason,
		})
		_, _ = db.Exec(`INSERT INTO response_actions
			(id, run_id, session_id, process_id, snapshot_id, risk_signal_id, policy_decision_id, action_type, target_type, target_id, status, payload, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'recorded', ?, ?)`,
			actionID, event.RunID, event.SessionID, event.ProcessID, event.SnapshotID, riskSignalID, record.ID, actionType, targetType, targetID, string(payload), now)
		_, _ = db.Exec(`INSERT OR REPLACE INTO graph_edges (id, run_id, from_id, to_id, edge_type, source_event_id, created_at)
			VALUES (?, ?, ?, ?, 'risk_signal_response_action', ?, ?)`,
			ids.New("edge"), event.RunID, "risk_signal/"+riskSignalID, "response_action/"+actionID, eventID, now)
	}
	if event.RunID != "" {
		_, _ = db.Exec(`INSERT INTO cost_samples (id, run_id, session_id, policy_block_count, quarantine_count, created_at)
			VALUES (?, ?, ?, ?, ?, ?)`, ids.New("cost"), event.RunID, event.SessionID, blockCount, quarantineCount, now)
	}
	return record, nil
}

func runtimeEventForPolicy(db *sql.DB, eventID string) (Event, string, error) {
	var event Event
	var rawPayload string
	if err := db.QueryRow(`SELECT source, event_type, COALESCE(run_id, ''), COALESCE(session_id, ''),
		COALESCE(tool_call_id, ''), COALESCE(process_id, ''), COALESCE(snapshot_id, ''), payload
		FROM events WHERE id = ?`, eventID).Scan(&event.Source, &event.EventType, &event.RunID, &event.SessionID,
		&event.ToolCallID, &event.ProcessID, &event.SnapshotID, &rawPayload); err != nil {
		return Event{}, "", err
	}
	event.DstIP = firstPolicyString(rawPayload, "dst_ip", "dst", "host")
	event.Path = firstPolicyString(rawPayload, "path", "file")
	event.Args = policyArgs(rawPayload)
	// A privilege change TO ROOT is the escalation threat (the runtime's setuid to
	// an unprivileged id is benign); mark it so the privilege_escalation rule can
	// fire on that case only.
	if event.EventType == "setuid" || event.EventType == "setgid" {
		if id, ok := policyNumber(rawPayload, "uid", "gid"); ok && id == 0 {
			event.Args = append(event.Args, event.EventType+"_root")
		}
	}
	return event, rawPayload, nil
}

// policyNumber digs the (possibly wrapped) payload for the first of keys that
// holds a JSON number, returning it as an int64.
func policyNumber(payload string, keys ...string) (int64, bool) {
	var decoded any
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		return 0, false
	}
	for _, key := range keys {
		for _, value := range findPolicyValues(decoded, key) {
			if n, ok := value.(float64); ok {
				return int64(n), true
			}
		}
	}
	return 0, false
}

func policyArgs(payload string) []string {
	var decoded any
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		return nil
	}
	values := findPolicyValues(decoded, "argv")
	out := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
			out = append(out, strings.TrimSpace(text))
		}
	}
	return out
}

func firstPolicyString(payload string, keys ...string) string {
	var decoded any
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		return ""
	}
	for _, key := range keys {
		for _, value := range findPolicyValues(decoded, key) {
			if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
				if key == "dst" {
					return strings.Trim(strings.Split(strings.TrimSpace(text), ":")[0], "[]")
				}
				return strings.TrimSpace(text)
			}
		}
	}
	return ""
}

func findPolicyValues(value any, key string) []any {
	switch typed := value.(type) {
	case map[string]any:
		var out []any
		if raw, ok := typed[key]; ok {
			if items, ok := raw.([]any); ok {
				out = append(out, items...)
			} else {
				out = append(out, raw)
			}
		}
		for _, nestedKey := range []string{"payload", "raw", "event"} {
			if nested, ok := typed[nestedKey]; ok {
				out = append(out, findPolicyValues(nested, key)...)
			}
		}
		return out
	case []any:
		var out []any
		for _, item := range typed {
			out = append(out, findPolicyValues(item, key)...)
		}
		return out
	default:
		return nil
	}
}

func severityForDecision(decision string) string {
	switch decision {
	case "kill", "quarantine":
		return "high"
	case "deny":
		return "medium"
	case "audit":
		return "low"
	default:
		return "info"
	}
}

func recommendedActionForDecision(decision string) string {
	switch decision {
	case "kill":
		return "kill"
	case "quarantine":
		return "quarantine"
	case "deny":
		return "deny"
	case "audit":
		return "audit"
	default:
		return "audit"
	}
}

func responseTarget(event Event, actionType string) (string, string) {
	switch actionType {
	case "kill":
		if event.ProcessID != "" {
			return "process", event.ProcessID
		}
	case "quarantine":
		if event.SessionID != "" {
			return "session", event.SessionID
		}
	case "deny":
		if event.EventType != "" {
			return "event", event.EventType
		}
	}
	if event.SessionID != "" {
		return "session", event.SessionID
	}
	if event.ProcessID != "" {
		return "process", event.ProcessID
	}
	return "run", event.RunID
}

func isPrivateIP(raw string) bool {
	ip := net.ParseIP(raw)
	if ip == nil {
		return false
	}
	return ip.IsPrivate()
}
