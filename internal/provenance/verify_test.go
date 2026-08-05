package provenance

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/effects"
	"github.com/byteyellow/agentprovenance/internal/record"
	securitymodel "github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestVerifyUnknownRunFails(t *testing.T) {
	paths, err := store.Init(filepath.Join(t.TempDir(), ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// A run that left no trace anywhere must not verify clean -- there is
	// nothing to verify, so an "ok" here would be a false green.
	result, err := Verify(db, "run-does-not-exist")
	if err != nil {
		t.Fatalf("Verify returned infra error: %v", err)
	}
	if result.Status != "failed" || result.ErrorCount != 1 {
		t.Fatalf("unknown run got status=%q errors=%d, want failed/1: %+v", result.Status, result.ErrorCount, result)
	}
	if len(result.Issues) != 1 || result.Issues[0].Kind != "unknown_run" {
		t.Fatalf("expected a single unknown_run issue, got %+v", result.Issues)
	}
}

func TestVerifyCleanRun(t *testing.T) {
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

	now := time.Now().UTC().Format(time.RFC3339Nano)
	workspace := filepath.Join(root, "attempt-1")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(paths.Artifacts, "fix.patch")
	if err := os.MkdirAll(filepath.Dir(artifact), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, []byte("patch"), 0o644); err != nil {
		t.Fatal(err)
	}
	insertTraceSnapshot(t, db, "snap-1", "ready", now)
	if _, err := db.Exec(`INSERT INTO rollouts
		(id, run_id, base_snapshot_id, status, fanout, winner_attempt_id, promotion_id, risk_status, created_at, updated_at)
		VALUES ('rollout-1', 'run-1', 'snap-1', 'completed', 1, 'attempt-1', 'promo-1', 'clean', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO fork_attempts
		(id, rollout_id, tool_call_id, snapshot_id, workspace_path, fork_ms, status, risk_status, is_winner, artifact_result, created_at)
		VALUES ('attempt-1', 'rollout-1', 'tool-1', 'snap-1', ?, 1, 'passed', 'clean', 1, ?, ?)`, workspace, artifact, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO leases
		(id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES ('lease-1', 'run-1', 'task.yaml', '{}', 'allocated', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sessions
		(id, lease_id, run_id, workspace_host_path, status, created_at, updated_at)
		VALUES ('session-1', 'lease-1', 'run-1', ?, 'stopped', ?, ?)`, workspace, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO processes
		(id, session_id, tool_call_id, command, status, exit_code, started_at, ended_at)
		VALUES ('process-1', 'session-1', 'tool-1', 'pytest -q', 'exited', 0, ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tool_calls
		(id, run_id, rollout_id, attempt_id, session_id, command, status, exit_code, result_ref, created_at)
		VALUES ('tool-1', 'run-1', 'rollout-1', 'attempt-1', 'session-1', 'pytest -q', 'passed', 0, ?, ?)`, artifact, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO promotions
		(id, rollout_id, attempt_id, base_snapshot_id, status, telemetry_watermark, drain_started_at, drain_completed_at, drain_queued_before, drain_processed, drain_pending_after, risk_status, reason, created_at, updated_at)
		VALUES ('promo-1', 'rollout-1', 'attempt-1', 'snap-1', 'promoted', ?, ?, ?, 0, 0, 0, 'clean', 'ok', ?, ?)`, now, now, now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := telemetry.IngestFiltered(db, telemetry.IngestEvent{
		RunID:       "run-1",
		RolloutID:   "rollout-1",
		AttemptID:   "attempt-1",
		SessionID:   "session-1",
		ToolCallID:  "tool-1",
		ProcessID:   "process-1",
		SnapshotID:  "snap-1",
		RawEventID:  "raw-evt-1",
		ContainerID: "container-1",
		CgroupID:    "cgroup-1",
		PID:         200,
		TGID:        200,
		PPID:        100,
		Source:      "filtered_telemetry",
		EventType:   "execve",
		Payload:     `{"argv":["pytest","-q"]}`,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO execution_context_bindings
		(id, run_id, session_id, attempt_id, tool_call_id, process_id, started_at, ended_at, binding_source, confidence, created_at)
		VALUES ('bind-1', 'run-1', 'session-1', 'attempt-1', 'tool-1', 'process-1', ?, ?, 'test', 1.0, ?)`, now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := effects.RecordEffect(db, effects.CreateInput{
		RunID:      "run-1",
		AttemptID:  "attempt-1",
		SessionID:  "session-1",
		ToolCallID: "tool-1",
		ProcessID:  "process-1",
		EffectType: "api_call",
		Target:     "api.example.com",
		Mode:       "dry-run",
		Decision:   "audit",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := (ObjectStore{DB: db, Paths: paths}).MaterializeRun("run-1"); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(db, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.ErrorCount != 0 {
		t.Fatalf("verify errors=%d issues=%+v", result.ErrorCount, result.Issues)
	}
	if result.SchemaVersion != "agentprovenance.verify/v1" || result.Status != "ok" {
		t.Fatalf("unexpected verify manifest header: %+v", result)
	}

	var out bytes.Buffer
	if err := PrintVerifyResultJSON(&out, result); err != nil {
		t.Fatal(err)
	}
	var decoded VerifyResult
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != "agentprovenance.verify/v1" || decoded.RunID != "run-1" || decoded.Status != "ok" {
		t.Fatalf("unexpected verify json: %+v", decoded)
	}
}

func TestVerifyRejectsPromotedUndrainedEvidence(t *testing.T) {
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

	now := time.Now().UTC().Format(time.RFC3339Nano)
	workspace := filepath.Join(root, "attempt-1")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	insertTraceSnapshot(t, db, "snap-1", "ready", now)
	if _, err := db.Exec(`INSERT INTO rollouts
		(id, run_id, base_snapshot_id, status, fanout, winner_attempt_id, promotion_id, risk_status, created_at, updated_at)
		VALUES ('rollout-1', 'run-1', 'snap-1', 'completed', 1, 'attempt-1', 'promo-1', 'clean', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO fork_attempts
		(id, rollout_id, tool_call_id, snapshot_id, workspace_path, fork_ms, status, risk_status, is_winner, created_at)
		VALUES ('attempt-1', 'rollout-1', 'tool-1', 'snap-1', ?, 1, 'passed', 'clean', 1, ?)`, workspace, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tool_calls
		(id, run_id, rollout_id, attempt_id, command, status, exit_code, created_at)
		VALUES ('tool-1', 'run-1', 'rollout-1', 'attempt-1', 'pytest -q', 'passed', 0, ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO promotions
		(id, rollout_id, attempt_id, base_snapshot_id, status, telemetry_watermark, drain_started_at, drain_completed_at, drain_queued_before, drain_processed, drain_pending_after, risk_status, reason, created_at, updated_at)
		VALUES ('promo-1', 'rollout-1', 'attempt-1', 'snap-1', 'promoted', ?, ?, ?, 1, 0, 1, 'clean', 'bad drain', ?, ?)`, now, now, now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO evidence_events
		(id, run_id, rollout_id, attempt_id, tool_call_id, snapshot_id, event_type, priority, payload, status, created_at)
		VALUES ('evidence-1', 'run-1', 'rollout-1', 'attempt-1', 'tool-1', 'snap-1', 'attempt_finished', 'normal', '{}', 'queued', ?)`, now); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(db, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	var foundPending, foundUndrained bool
	for _, issue := range result.Issues {
		if issue.Kind == "promotion_pending_evidence" {
			foundPending = true
		}
		if issue.Kind == "promotion_undrained_evidence" {
			foundUndrained = true
		}
	}
	if !foundPending || !foundUndrained {
		t.Fatalf("expected drain issues pending=%t undrained=%t issues=%+v", foundPending, foundUndrained, result.Issues)
	}
}

func TestVerifyAllowsExternalTelemetryBindings(t *testing.T) {
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

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO execution_context_bindings
		(id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, started_at, ended_at, binding_source, confidence, created_at)
		VALUES ('bind-external', 'run-external', 'session-external', 'attempt-external', 'tool-external', 'process-external', 'container-external', 'cgroup-external', 4242, 4242, ?, '', 'external_telemetry', 0.95, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := telemetry.IngestFiltered(db, telemetry.IngestEvent{
		RunID:       "run-external",
		RawEventID:  "raw-external-1",
		ContainerID: "container-external",
		CgroupID:    "cgroup-external",
		PID:         4242,
		TGID:        4242,
		PPID:        4000,
		Timestamp:   now,
		Source:      "filtered_telemetry",
		EventType:   "execve",
		Payload:     `{"argv":["python","agent.py"]}`,
	}); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(db, "run-external")
	if err != nil {
		t.Fatal(err)
	}
	if result.ErrorCount != 0 {
		t.Fatalf("external telemetry binding should verify cleanly: %+v", result.Issues)
	}
}

func TestVerifyRiskResponseChain(t *testing.T) {
	db := setupRiskVerifyRun(t)
	defer db.Close()

	result, err := Verify(db, "run-risk-verify")
	if err != nil {
		t.Fatal(err)
	}
	if result.ErrorCount != 0 {
		t.Fatalf("risk chain should verify cleanly: %+v", result.Issues)
	}
}

func TestVerifyRejectsMissingPolicyRiskSignal(t *testing.T) {
	db := setupRiskVerifyRun(t)
	defer db.Close()

	if _, err := db.Exec(`DELETE FROM risk_signals WHERE run_id = 'run-risk-verify'`); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(db, "run-risk-verify")
	if err != nil {
		t.Fatal(err)
	}
	assertVerifyIssue(t, result, "missing_policy_risk_signal")
	assertVerifyIssue(t, result, "missing_response_risk_signal")
}

func TestVerifyRejectsMissingUnifiedSecuritySignal(t *testing.T) {
	db := setupRiskVerifyRun(t)
	defer db.Close()
	if _, err := db.Exec(`DELETE FROM signals WHERE run_id = 'run-risk-verify' AND dimension = 'security'`); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(db, "run-risk-verify")
	if err != nil {
		t.Fatal(err)
	}
	assertVerifyIssue(t, result, "missing_policy_unified_signal")
}

func TestVerifyRejectsMissingRiskResponseAction(t *testing.T) {
	db := setupRiskVerifyRun(t)
	defer db.Close()

	if _, err := db.Exec(`DELETE FROM response_actions WHERE run_id = 'run-risk-verify'`); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(db, "run-risk-verify")
	if err != nil {
		t.Fatal(err)
	}
	assertVerifyIssue(t, result, "missing_policy_response_action")
	assertVerifyIssue(t, result, "missing_risk_response_action")
}

func TestVerifyRejectsResponseRiskPolicyMismatch(t *testing.T) {
	db := setupRiskVerifyRun(t)
	defer db.Close()

	if _, err := db.Exec(`UPDATE response_actions SET policy_decision_id = 'dec-other' WHERE run_id = 'run-risk-verify'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO policy_decisions
		(id, event_id, run_id, session_id, rule_id, decision, reason, created_at)
		VALUES ('dec-other', '', 'run-risk-verify', 'session-risk-verify', 'other', 'deny', 'other', ?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(db, "run-risk-verify")
	if err != nil {
		t.Fatal(err)
	}
	assertVerifyIssue(t, result, "response_risk_policy_mismatch")
}

func TestVerifyRejectsContextDrift(t *testing.T) {
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

	now := time.Now().UTC().Format(time.RFC3339Nano)
	workspace := filepath.Join(root, "attempt-1")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	insertTraceSnapshot(t, db, "snap-1", "ready", now)
	if _, err := db.Exec(`INSERT INTO rollouts
		(id, run_id, base_snapshot_id, status, fanout, winner_attempt_id, promotion_id, risk_status, created_at, updated_at)
		VALUES ('rollout-1', 'run-1', 'snap-1', 'completed', 1, 'attempt-1', 'promo-1', 'clean', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO fork_attempts
		(id, rollout_id, tool_call_id, snapshot_id, workspace_path, fork_ms, status, risk_status, is_winner, created_at)
		VALUES ('attempt-1', 'rollout-1', 'tool-1', 'snap-1', ?, 1, 'passed', 'clean', 1, ?)`, workspace, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO leases
		(id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES ('lease-1', 'run-1', 'task.yaml', '{}', 'allocated', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sessions
		(id, lease_id, run_id, workspace_host_path, status, created_at, updated_at)
		VALUES ('session-1', 'lease-1', 'run-1', ?, 'stopped', ?, ?)`, workspace, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tool_calls
		(id, run_id, rollout_id, attempt_id, session_id, command, status, exit_code, created_at)
		VALUES ('tool-1', 'run-1', 'rollout-1', 'attempt-1', 'session-1', 'pytest -q', 'passed', 0, ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tool_calls
		(id, run_id, rollout_id, attempt_id, session_id, command, status, exit_code, created_at)
		VALUES ('tool-2', 'run-1', 'rollout-1', 'attempt-1', 'session-1', 'other', 'passed', 0, ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO processes
		(id, session_id, tool_call_id, command, status, exit_code, started_at, ended_at)
		VALUES ('process-1', 'session-1', 'tool-1', 'pytest -q', 'exited', 0, ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO promotions
		(id, rollout_id, attempt_id, base_snapshot_id, status, telemetry_watermark, drain_started_at, drain_completed_at, drain_queued_before, drain_processed, drain_pending_after, risk_status, reason, created_at, updated_at)
		VALUES ('promo-1', 'rollout-1', 'attempt-1', 'snap-1', 'promoted', ?, ?, ?, 0, 0, 0, 'clean', 'ok', ?, ?)`, now, now, now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO execution_context_bindings
		(id, run_id, session_id, attempt_id, tool_call_id, process_id, started_at, ended_at, binding_source, confidence, created_at)
		VALUES ('bind-1', 'run-1', 'session-1', 'attempt-1', 'tool-2', 'process-1', ?, ?, 'test', 1.0, ?)`, now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO events
		(id, run_id, session_id, tool_call_id, process_id, snapshot_id, source, event_type, payload, created_at, correlation_method, correlation_confidence)
		VALUES ('evt-1', 'run-1', 'session-1', 'tool-2', 'process-1', 'snap-1', 'wrapper', 'execve', '{}', ?, 'process_id:process_id', 1.0)`, now); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(db, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.ErrorCount == 0 {
		t.Fatalf("expected context drift errors, got %+v", result)
	}
	var foundBinding, foundEvent bool
	for _, issue := range result.Issues {
		if issue.Kind == "binding_process_tool_call_mismatch" {
			foundBinding = true
		}
		if issue.Kind == "event_process_tool_call_mismatch" {
			foundEvent = true
		}
	}
	if !foundBinding || !foundEvent {
		t.Fatalf("expected binding and event mismatch issues, got %+v", result.Issues)
	}
}

func TestVerifyRejectsTaintedWinner(t *testing.T) {
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

	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertTraceSnapshot(t, db, "snap-1", "ready", now)
	if _, err := db.Exec(`INSERT INTO rollouts
		(id, run_id, base_snapshot_id, status, fanout, winner_attempt_id, risk_status, created_at, updated_at)
		VALUES ('rollout-1', 'run-1', 'snap-1', 'completed', 1, 'attempt-1', 'clean', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO fork_attempts
		(id, rollout_id, snapshot_id, workspace_path, fork_ms, status, risk_status, is_winner, created_at)
		VALUES ('attempt-1', 'rollout-1', 'snap-1', ?, 1, 'quarantined', 'tainted', 1, ?)`, filepath.Join(root, "attempt-1"), now); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(db, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.ErrorCount == 0 {
		t.Fatalf("expected tainted winner error, got %+v", result)
	}
	if result.Status != "failed" {
		t.Fatalf("expected failed status, got %+v", result)
	}
	found := false
	for _, issue := range result.Issues {
		if issue.Kind == "tainted_winner" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected tainted_winner issue, got %+v", result.Issues)
	}
}

func TestVerifyRejectsStaleProcessStatus(t *testing.T) {
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

	now := time.Now().UTC().Format(time.RFC3339Nano)
	workspace := filepath.Join(root, "attempt-1")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	insertTraceSnapshot(t, db, "snap-1", "ready", now)
	if _, err := db.Exec(`INSERT INTO rollouts
		(id, run_id, base_snapshot_id, status, fanout, winner_attempt_id, risk_status, created_at, updated_at)
		VALUES ('rollout-1', 'run-1', 'snap-1', 'completed', 1, 'attempt-1', 'clean', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO fork_attempts
		(id, rollout_id, tool_call_id, snapshot_id, workspace_path, fork_ms, status, risk_status, is_winner, created_at)
		VALUES ('attempt-1', 'rollout-1', 'tool-1', 'snap-1', ?, 1, 'passed', 'clean', 1, ?)`, workspace, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO leases
		(id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES ('lease-1', 'run-1', 'task.yaml', '{}', 'allocated', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sessions
		(id, lease_id, run_id, workspace_host_path, status, created_at, updated_at)
		VALUES ('session-1', 'lease-1', 'run-1', ?, 'stopped', ?, ?)`, workspace, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tool_calls
		(id, run_id, rollout_id, attempt_id, session_id, command, status, exit_code, created_at)
		VALUES ('tool-1', 'run-1', 'rollout-1', 'attempt-1', 'session-1', 'pytest -q', 'passed', 0, ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO processes
		(id, session_id, tool_call_id, command, status, started_at)
		VALUES ('process-1', 'session-1', 'tool-1', 'pytest -q', 'running', ?)`, now); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(db, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.ErrorCount == 0 {
		t.Fatalf("expected stale process error, got %+v", result)
	}
	found := false
	for _, issue := range result.Issues {
		if issue.Kind == "stale_process_status" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected stale_process_status issue, got %+v", result.Issues)
	}
}

func TestVerifyRejectsMissingRuntimeFileEdges(t *testing.T) {
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

	now := time.Now().UTC().Format(time.RFC3339Nano)
	workspace := filepath.Join(root, "attempt-1")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	insertVerifyRuntimeBase(t, db, workspace, now)
	if _, err := db.Exec(`INSERT INTO events
		(id, run_id, session_id, tool_call_id, process_id, snapshot_id, raw_event_id, correlation_method, correlation_confidence,
		 container_id, cgroup_id, pid, tgid, ppid, source, event_type, payload, created_at)
		VALUES ('evt-file-1', 'run-1', 'session-1', 'tool-1', 'process-1', 'snap-1', 'raw-file-1', 'cgroup_id:cgroup_id', 1.0,
		 'container-1', 'cgroup-1', 200, 200, 100, 'filtered_telemetry', 'file_write', '{"path":"calculator.py"}', ?)`, now); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(db, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	assertVerifyIssue(t, result, "missing_runtime_event_file_edge")
	assertVerifyIssue(t, result, "missing_runtime_process_file_edge")
	assertVerifyIssue(t, result, "missing_runtime_tool_call_file_edge")
	assertVerifyIssue(t, result, "missing_runtime_process_parent_edge")
}

func TestVerifyRejectsInvalidTelemetryPayloadSchema(t *testing.T) {
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

	now := time.Now().UTC().Format(time.RFC3339Nano)
	workspace := filepath.Join(root, "attempt-1")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	insertVerifyRuntimeBase(t, db, workspace, now)
	if _, err := db.Exec(`INSERT INTO events
		(id, run_id, session_id, tool_call_id, process_id, snapshot_id, raw_event_id, correlation_method, correlation_confidence,
		 container_id, cgroup_id, pid, tgid, ppid, source, event_type, payload, created_at)
		VALUES ('evt-bad-schema', 'run-1', 'session-1', 'tool-1', 'process-1', 'snap-1', 'raw-bad-schema', 'process_id:process_id', 1.0,
		 'container-1', 'cgroup-1', 200, 200, 100, 'tetragon_jsonl', 'execve', '{"tool_call_id":"leaked"}', ?)`, now); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(db, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	assertVerifyIssue(t, result, "invalid_telemetry_payload_schema")
}

func TestVerifyRejectsTelemetryBatchHashMismatch(t *testing.T) {
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

	now := time.Now().UTC().Format(time.RFC3339Nano)
	workspace := filepath.Join(root, "attempt-1")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	insertVerifyRuntimeBase(t, db, workspace, now)
	eventID, err := telemetry.IngestFiltered(db, telemetry.IngestEvent{
		RunID:       "run-1",
		RolloutID:   "rollout-1",
		AttemptID:   "attempt-1",
		SessionID:   "session-1",
		ToolCallID:  "tool-1",
		ProcessID:   "process-1",
		SnapshotID:  "snap-1",
		RawEventID:  "raw-batch-1",
		ContainerID: "container-1",
		CgroupID:    "cgroup-1",
		PID:         200,
		TGID:        200,
		PPID:        100,
		Source:      "tetragon_jsonl",
		EventType:   "execve",
		Payload:     `{"argv":["pytest","-q"]}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	eventIDsJSON, err := json.Marshal([]string{eventID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO telemetry_batches
		(id, run_id, format, path, file_sha256, read_count, ingested_count, skipped_count, failed_count, event_ids_json, event_ids_sha256, created_at)
		VALUES ('telbatch-bad', 'run-1', 'tetragon', 'events.jsonl', 'abc123', 1, 1, 0, 0, ?, 'tampered', ?)`,
		string(eventIDsJSON), now); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(db, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	assertVerifyIssue(t, result, "telemetry_batch_event_hash_mismatch")
}

func TestVerifyAcceptsRuntimeCausalityEdges(t *testing.T) {
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

	now := time.Now().UTC().Format(time.RFC3339Nano)
	workspace := filepath.Join(root, "attempt-1")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	insertVerifyRuntimeBase(t, db, workspace, now)
	if _, err := telemetry.IngestFiltered(db, telemetry.IngestEvent{
		RunID:       "run-1",
		RolloutID:   "rollout-1",
		AttemptID:   "attempt-1",
		SessionID:   "session-1",
		ToolCallID:  "tool-1",
		ProcessID:   "process-1",
		SnapshotID:  "snap-1",
		RawEventID:  "raw-file-1",
		ContainerID: "container-1",
		CgroupID:    "cgroup-1",
		PID:         200,
		TGID:        200,
		PPID:        100,
		Source:      "filtered_telemetry",
		EventType:   "file_write",
		Payload:     `{"path":"calculator.py"}`,
	}); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(db, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range result.Issues {
		if strings.HasPrefix(issue.Kind, "missing_runtime_") {
			t.Fatalf("unexpected runtime causality issue: %+v", result.Issues)
		}
	}
}

func TestVerifyRejectsMissingOrphanLifecycleEvidence(t *testing.T) {
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

	workdir := filepath.Join(root, "workspace")
	if err := os.MkdirAll(workdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "app.py"), []byte("value = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := (record.Service{DB: db, Paths: paths}).Run(record.Request{
		RunID:   "run-orphan-verify",
		Name:    "orphan-verify",
		Workdir: workdir,
		Command: []string{"python3", "-c", `import subprocess, time; subprocess.Popen(["sleep", "0.8"]); time.sleep(0.08); open("app.py", "w").write("value = 2\n")`},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupVerifyObservedProcesses(result.Observed)

	clean, err := Verify(db, result.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if clean.ErrorCount != 0 {
		t.Fatalf("clean orphan record should verify: %+v", clean.Issues)
	}

	if _, err := db.Exec(`DELETE FROM evidence_events WHERE run_id = ? AND event_type = 'orphan_lifecycle_decision'`, result.RunID); err != nil {
		t.Fatal(err)
	}
	broken, err := Verify(db, result.RunID)
	if err != nil {
		t.Fatal(err)
	}
	assertVerifyIssue(t, broken, "missing_orphan_lifecycle_evidence")
	assertVerifyIssue(t, broken, "missing_orphan_lifecycle_policy_decision")
}

func TestVerifyRejectsMissingPolicyDecisionEdges(t *testing.T) {
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

	now := time.Now().UTC().Format(time.RFC3339Nano)
	workspace := filepath.Join(root, "attempt-1")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	insertVerifyRuntimeBase(t, db, workspace, now)
	if _, err := telemetry.IngestFiltered(db, telemetry.IngestEvent{
		RunID:      "run-1",
		RolloutID:  "rollout-1",
		AttemptID:  "attempt-1",
		SessionID:  "session-1",
		ToolCallID: "tool-1",
		ProcessID:  "process-1",
		SnapshotID: "snap-1",
		PID:        200,
		TGID:       200,
		PPID:       100,
		Source:     "filtered_telemetry",
		EventType:  "execve",
		Payload:    `{"argv":["pytest","-q"]}`,
	}); err != nil {
		t.Fatal(err)
	}
	var eventID string
	if err := db.QueryRow(`SELECT id FROM events WHERE run_id = 'run-1' AND event_type = 'execve' LIMIT 1`).Scan(&eventID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO policy_decisions
		(id, event_id, run_id, session_id, rule_id, decision, reason, created_at)
		VALUES ('decision-missing-edge', ?, 'run-1', 'session-1', 'test-rule', 'audit', 'missing edge', ?)`, eventID, now); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(db, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	assertVerifyIssue(t, result, "missing_policy_decision_edge")
	assertVerifyIssue(t, result, "missing_policy_session_edge")
}

func insertVerifyRuntimeBase(t *testing.T, db *sql.DB, workspace, now string) {
	t.Helper()
	insertTraceSnapshot(t, db, "snap-1", "ready", now)
	if _, err := db.Exec(`INSERT INTO rollouts
		(id, run_id, base_snapshot_id, status, fanout, winner_attempt_id, risk_status, created_at, updated_at)
		VALUES ('rollout-1', 'run-1', 'snap-1', 'completed', 1, 'attempt-1', 'clean', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO fork_attempts
		(id, rollout_id, tool_call_id, snapshot_id, workspace_path, fork_ms, status, risk_status, is_winner, created_at)
		VALUES ('attempt-1', 'rollout-1', 'tool-1', 'snap-1', ?, 1, 'passed', 'clean', 1, ?)`, workspace, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO leases
		(id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES ('lease-1', 'run-1', 'task.yaml', '{}', 'allocated', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sessions
		(id, lease_id, run_id, workspace_host_path, status, created_at, updated_at)
		VALUES ('session-1', 'lease-1', 'run-1', ?, 'stopped', ?, ?)`, workspace, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tool_calls
		(id, run_id, rollout_id, attempt_id, session_id, command, status, exit_code, created_at)
		VALUES ('tool-1', 'run-1', 'rollout-1', 'attempt-1', 'session-1', 'pytest -q', 'passed', 0, ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO processes
		(id, session_id, tool_call_id, command, status, exit_code, started_at, ended_at)
		VALUES ('process-1', 'session-1', 'tool-1', 'pytest -q', 'exited', 0, ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO execution_context_bindings
		(id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, started_at, ended_at, binding_source, confidence, created_at)
		VALUES ('bind-1', 'run-1', 'session-1', 'attempt-1', 'tool-1', 'process-1', 'container-1', 'cgroup-1', 200, 200, ?, ?, 'test', 1.0, ?)`, now, now, now); err != nil {
		t.Fatal(err)
	}
}

func setupRiskVerifyRun(t *testing.T) *sql.DB {
	t.Helper()
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO execution_context_bindings
		(id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, root_pid, pid, started_at, ended_at, binding_source, confidence, created_at)
		VALUES ('bind-risk', 'run-risk-verify', 'session-risk-verify', 'attempt-risk-verify', 'tool-risk-verify', 'process-risk-verify', 'container-risk-verify', 4242, 4242, ?, '', 'external_telemetry', 0.95, ?)`, now, now); err != nil {
		db.Close()
		t.Fatal(err)
	}
	eventID, err := telemetry.IngestFiltered(db, telemetry.IngestEvent{
		RunID:       "run-risk-verify",
		RawEventID:  "raw-risk-verify",
		ContainerID: "container-risk-verify",
		PID:         4242,
		TGID:        4242,
		PPID:        4000,
		Timestamp:   now,
		Source:      "falco_jsonl",
		EventType:   "metadata_ip",
		Payload:     `{"dst":"169.254.169.254"}`,
	})
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, persisted, err := securitymodel.EvaluateRuntimeEvent(db, eventID); err != nil {
		db.Close()
		t.Fatal(err)
	} else if !persisted {
		db.Close()
		t.Fatalf("risk event did not persist policy decision")
	}
	return db
}

func assertVerifyIssue(t *testing.T, result VerifyResult, kind string) {
	t.Helper()
	for _, issue := range result.Issues {
		if issue.Kind == kind {
			return
		}
	}
	t.Fatalf("expected issue kind %s, got %+v", kind, result.Issues)
}

func cleanupVerifyObservedProcesses(procs []record.ObservedProcess) {
	for _, proc := range procs {
		if proc.PID <= 0 {
			continue
		}
		if p, err := os.FindProcess(int(proc.PID)); err == nil {
			_ = p.Kill()
		}
	}
}
