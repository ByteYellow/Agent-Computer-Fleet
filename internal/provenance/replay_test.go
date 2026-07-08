package provenance

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/effects"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestReplayRunIncludesCommandArtifactAndExternalEffect(t *testing.T) {
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
		(id, rollout_id, tool_call_id, snapshot_id, workspace_path, fork_ms, strategy, command, status, risk_status, is_winner, artifact_result, score, cost_estimate, created_at)
		VALUES ('attempt-1', 'rollout-1', 'tool-1', 'snap-1', ?, 1, 'fix', 'pytest -q', 'passed', 'clean', 1, ?, 7, 0.001, ?)`, workspace, artifact, now); err != nil {
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
		(id, run_id, rollout_id, attempt_id, session_id, command, status, exit_code, result_ref, created_at, started_at, ended_at)
		VALUES ('tool-1', 'run-1', 'rollout-1', 'attempt-1', 'session-1', 'pytest -q', 'passed', 0, ?, ?, ?, ?)`, artifact, now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO processes
		(id, session_id, tool_call_id, command, status, exit_code, started_at, ended_at)
		VALUES ('process-1', 'session-1', 'tool-1', 'pytest -q', 'exited', 0, ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO events
		(id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, created_at)
		VALUES ('evt-1', 'run-1', 'session-1', 'tool-1', 'process-1', 'wrapper', 'execve', '{"attempt_id":"attempt-1"}', ?)`, now); err != nil {
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

	var out bytes.Buffer
	if err := ReplayRun(db, "run-1", &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"replay_run=run-1 mode=plan_only",
		"trajectory=rollout-1",
		"execution_scope=attempt-1",
		"command=\"pytest -q\"",
		"artifact=" + artifact,
		"external_effect=",
		"event=evt-1",
		"replay_blocked=false",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("replay output missing %q:\n%s", want, got)
		}
	}
}

func TestReplayAttemptMarksTaintedAttemptBlocked(t *testing.T) {
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
		(id, run_id, base_snapshot_id, status, fanout, risk_status, created_at, updated_at)
		VALUES ('rollout-1', 'run-1', 'snap-1', 'completed', 1, 'clean', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO fork_attempts
		(id, rollout_id, snapshot_id, workspace_path, fork_ms, command, status, risk_status, created_at)
		VALUES ('attempt-1', 'rollout-1', 'snap-1', ?, 1, 'curl metadata', 'quarantined', 'tainted', ?)`, filepath.Join(root, "attempt-1"), now); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := ReplayAttempt(db, "attempt-1", &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "replay_blocked=true") || !strings.Contains(got, "risk=tainted") {
		t.Fatalf("expected tainted replay to be blocked:\n%s", got)
	}
}

func TestReplayRunJSONEmitsStructuredManifest(t *testing.T) {
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
	artifact := filepath.Join(paths.Artifacts, "fix.patch")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
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
		(id, rollout_id, tool_call_id, snapshot_id, workspace_path, fork_ms, strategy, command, status, risk_status, is_winner, artifact_result, score, cost_estimate, created_at)
		VALUES ('attempt-1', 'rollout-1', 'tool-1', 'snap-1', ?, 1, 'fix', 'pytest -q', 'passed', 'clean', 1, ?, 7, 0.001, ?)`, workspace, artifact, now); err != nil {
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
		(id, run_id, rollout_id, attempt_id, session_id, command, status, exit_code, result_ref, created_at, started_at, ended_at)
		VALUES ('tool-1', 'run-1', 'rollout-1', 'attempt-1', 'session-1', 'pytest -q', 'passed', 0, ?, ?, ?, ?)`, artifact, now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO processes
		(id, session_id, tool_call_id, command, status, exit_code, started_at, ended_at)
		VALUES ('process-1', 'session-1', 'tool-1', 'pytest -q', 'exited', 0, ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO events
		(id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, created_at, correlation_method, correlation_confidence)
		VALUES ('evt-1', 'run-1', 'session-1', 'tool-1', 'process-1', 'wrapper', 'execve', '{"attempt_id":"attempt-1"}', ?, 'process_id:process_id', 1.0)`, now); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := ReplayRunJSON(db, "run-1", &out); err != nil {
		t.Fatal(err)
	}
	var manifest ReplayManifest
	if err := json.Unmarshal(out.Bytes(), &manifest); err != nil {
		t.Fatalf("invalid replay json: %v\n%s", err, out.String())
	}
	if manifest.SchemaVersion != "agentprovenance.replay/v1" || manifest.Mode != "plan_only" || manifest.Scope != "run" {
		t.Fatalf("unexpected manifest header: %+v", manifest)
	}
	if len(manifest.Rollouts) != 1 || len(manifest.Rollouts[0].Attempts) != 1 {
		t.Fatalf("unexpected manifest shape: %+v", manifest)
	}
	attempt := manifest.Rollouts[0].Attempts[0]
	if attempt.ID != "attempt-1" || attempt.ToolCall == nil || len(attempt.Processes) != 1 || len(attempt.Events) != 1 {
		t.Fatalf("attempt missing structured replay evidence: %+v", attempt)
	}
	if attempt.ArtifactDigest == nil || !attempt.ArtifactDigest.Exists || attempt.ArtifactDigest.SHA256 == "" {
		t.Fatalf("artifact digest missing: %+v", attempt.ArtifactDigest)
	}
}
