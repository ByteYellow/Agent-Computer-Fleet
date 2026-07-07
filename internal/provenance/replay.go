package provenance

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
)

type ReplayManifest struct {
	SchemaVersion string          `json:"schema_version"`
	Mode          string          `json:"mode"`
	Scope         string          `json:"scope"`
	RunID         string          `json:"run_id,omitempty"`
	AttemptID     string          `json:"attempt_id,omitempty"`
	ExecutionID   string          `json:"execution_scope_id,omitempty"`
	Trajectories  []ReplayRollout `json:"trajectories"`
	Rollouts      []ReplayRollout `json:"rollouts"`
}

type ReplayRollout struct {
	ID              string              `json:"id"`
	TrajectoryID    string              `json:"trajectory_id"`
	RunID           string              `json:"run_id"`
	BaseStateID     string              `json:"base_state_id"`
	BaseSnapshotID  string              `json:"base_snapshot_id"`
	Status          string              `json:"status"`
	SelectedScopeID string              `json:"selected_execution_scope_id"`
	WinnerAttemptID string              `json:"winner_attempt_id"`
	PromotionID     string              `json:"promotion_id"`
	RiskStatus      string              `json:"risk_status"`
	BaseState       *ReplaySnapshot     `json:"base_state,omitempty"`
	ExecutionScopes []ReplayAttemptPlan `json:"execution_scopes"`
	BaseSnapshot    *ReplaySnapshot     `json:"base_snapshot,omitempty"`
	Attempts        []ReplayAttemptPlan `json:"attempts"`
}

type ReplaySnapshot struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	PhysicalType string `json:"physical_type"`
	Path         string `json:"path"`
	ManifestHash string `json:"manifest_hash"`
	FileCount    int64  `json:"file_count"`
	Bytes        int64  `json:"bytes"`
	Status       string `json:"status"`
	Tainted      bool   `json:"tainted"`
}

type ReplayAttemptPlan struct {
	ID               string                 `json:"id"`
	ExecutionID      string                 `json:"execution_scope_id"`
	BaseStateID      string                 `json:"base_state_id,omitempty"`
	SnapshotID       string                 `json:"snapshot_id"`
	ToolCallID       string                 `json:"tool_call_id,omitempty"`
	SubstrateScopeID string                 `json:"substrate_scope_id,omitempty"`
	Workspace        string                 `json:"workspace"`
	Strategy         string                 `json:"strategy"`
	Command          string                 `json:"command"`
	Status           string                 `json:"status"`
	RiskStatus       string                 `json:"risk_status"`
	ArtifactResult   string                 `json:"artifact_result,omitempty"`
	ArtifactDigest   *ReplayArtifactDigest  `json:"artifact_digest,omitempty"`
	IsWinner         bool                   `json:"is_winner"`
	BudgetExceeded   bool                   `json:"budget_exceeded"`
	ReplayBlocked    bool                   `json:"replay_blocked"`
	BlockReasons     []string               `json:"block_reasons,omitempty"`
	Score            float64                `json:"score"`
	CostEstimate     float64                `json:"cost_estimate"`
	ToolCall         *ReplayToolCall        `json:"tool_call,omitempty"`
	Processes        []ReplayProcess        `json:"processes,omitempty"`
	ExternalEffects  []ReplayExternalEffect `json:"external_effects,omitempty"`
	Events           []ReplayEvent          `json:"events,omitempty"`
}

type ReplayArtifactDigest struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type ReplayToolCall struct {
	ID             string  `json:"id"`
	SessionID      string  `json:"session_id"`
	Command        string  `json:"command"`
	Status         string  `json:"status"`
	ExitCode       int64   `json:"exit_code"`
	WallMS         int64   `json:"wall_ms"`
	CostEstimate   float64 `json:"cost_estimate"`
	ResultRef      string  `json:"result_ref,omitempty"`
	PolicyDecision string  `json:"policy_decision"`
	StartedAt      string  `json:"started_at"`
	EndedAt        string  `json:"ended_at"`
}

type ReplayProcess struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	Command   string `json:"command"`
	Status    string `json:"status"`
	ExitCode  int64  `json:"exit_code"`
	StartedAt string `json:"started_at"`
	EndedAt   string `json:"ended_at"`
}

type ReplayExternalEffect struct {
	ID              string `json:"id"`
	EffectType      string `json:"effect_type"`
	Target          string `json:"target"`
	Mode            string `json:"mode"`
	Decision        string `json:"decision"`
	CompensationRef string `json:"compensation_ref,omitempty"`
	Status          string `json:"status"`
	Payload         string `json:"payload"`
}

type ReplayEvent struct {
	ID                    string  `json:"id"`
	EventType             string  `json:"event_type"`
	Source                string  `json:"source"`
	ProcessID             string  `json:"process_id,omitempty"`
	SnapshotID            string  `json:"snapshot_id,omitempty"`
	CorrelationMethod     string  `json:"correlation_method,omitempty"`
	CorrelationConfidence float64 `json:"correlation_confidence"`
	Payload               string  `json:"payload"`
}

func ReplayRun(db *sql.DB, runID string, out io.Writer) error {
	manifest, err := BuildReplayRun(db, runID)
	if err != nil {
		return err
	}
	PrintReplayManifest(out, manifest)
	return nil
}

func ReplayRunJSON(db *sql.DB, runID string, out io.Writer) error {
	manifest, err := BuildReplayRun(db, runID)
	if err != nil {
		return err
	}
	return PrintReplayManifestJSON(out, manifest)
}

func ReplayAttempt(db *sql.DB, attemptID string, out io.Writer) error {
	manifest, err := BuildReplayAttempt(db, attemptID)
	if err != nil {
		return err
	}
	PrintReplayManifest(out, manifest)
	return nil
}

func ReplayAttemptJSON(db *sql.DB, attemptID string, out io.Writer) error {
	manifest, err := BuildReplayAttempt(db, attemptID)
	if err != nil {
		return err
	}
	return PrintReplayManifestJSON(out, manifest)
}

func BuildReplayRun(db *sql.DB, runID string) (ReplayManifest, error) {
	if runID == "" {
		return ReplayManifest{}, fmt.Errorf("run_id is required")
	}
	manifest := ReplayManifest{SchemaVersion: "agentprovenance.replay/v1", Mode: "plan_only", Scope: "run", RunID: runID}
	rows, err := db.Query(`SELECT id FROM rollouts WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return ReplayManifest{}, err
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		found = true
		var rolloutID string
		if err := rows.Scan(&rolloutID); err != nil {
			return ReplayManifest{}, err
		}
		rollout, err := buildReplayRollout(db, rolloutID, "")
		if err != nil {
			return ReplayManifest{}, err
		}
		manifest.Trajectories = append(manifest.Trajectories, rollout)
		manifest.Rollouts = append(manifest.Rollouts, rollout)
	}
	if err := rows.Err(); err != nil {
		return ReplayManifest{}, err
	}
	if !found {
		return ReplayManifest{}, fmt.Errorf("run %q has no rollouts", runID)
	}
	return manifest, nil
}

func BuildReplayAttempt(db *sql.DB, attemptID string) (ReplayManifest, error) {
	if attemptID == "" {
		return ReplayManifest{}, fmt.Errorf("attempt_id is required")
	}
	var rolloutID, runID string
	if err := db.QueryRow(`SELECT rollout_id FROM fork_attempts WHERE id = ?`, attemptID).Scan(&rolloutID); err != nil {
		return ReplayManifest{}, err
	}
	if err := db.QueryRow(`SELECT run_id FROM rollouts WHERE id = ?`, rolloutID).Scan(&runID); err != nil {
		return ReplayManifest{}, err
	}
	rollout, err := buildReplayRollout(db, rolloutID, attemptID)
	if err != nil {
		return ReplayManifest{}, err
	}
	return ReplayManifest{SchemaVersion: "agentprovenance.replay/v1", Mode: "plan_only", Scope: "execution_scope", RunID: runID, AttemptID: attemptID, ExecutionID: attemptID, Trajectories: []ReplayRollout{rollout}, Rollouts: []ReplayRollout{rollout}}, nil
}

func buildReplayRollout(db *sql.DB, rolloutID, onlyAttemptID string) (ReplayRollout, error) {
	var rollout ReplayRollout
	err := db.QueryRow(`SELECT id, run_id, base_snapshot_id, status, winner_attempt_id, promotion_id, risk_status
		FROM rollouts WHERE id = ?`, rolloutID).Scan(&rollout.ID, &rollout.RunID, &rollout.BaseSnapshotID, &rollout.Status, &rollout.WinnerAttemptID, &rollout.PromotionID, &rollout.RiskStatus)
	if err != nil {
		return ReplayRollout{}, err
	}
	if rollout.BaseSnapshotID != "" {
		snapshot, err := buildReplaySnapshot(db, rollout.BaseSnapshotID)
		if err != nil {
			return ReplayRollout{}, err
		}
		rollout.BaseStateID = rollout.BaseSnapshotID
		rollout.BaseState = &snapshot
		rollout.BaseSnapshot = &snapshot
	}
	rollout.TrajectoryID = rollout.ID
	rollout.SelectedScopeID = rollout.WinnerAttemptID
	query := `SELECT id FROM fork_attempts WHERE rollout_id = ?`
	args := []any{rolloutID}
	if onlyAttemptID != "" {
		query += ` AND id = ?`
		args = append(args, onlyAttemptID)
	}
	query += ` ORDER BY is_winner DESC, created_at ASC`
	rows, err := db.Query(query, args...)
	if err != nil {
		return ReplayRollout{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var attemptID string
		if err := rows.Scan(&attemptID); err != nil {
			return ReplayRollout{}, err
		}
		attempt, err := buildReplayAttemptNode(db, rolloutID, attemptID)
		if err != nil {
			return ReplayRollout{}, err
		}
		rollout.ExecutionScopes = append(rollout.ExecutionScopes, attempt)
		rollout.Attempts = append(rollout.Attempts, attempt)
	}
	if err := rows.Err(); err != nil {
		return ReplayRollout{}, err
	}
	if onlyAttemptID != "" && len(rollout.Attempts) == 0 {
		return ReplayRollout{}, fmt.Errorf("attempt %q not found in rollout %q", onlyAttemptID, rolloutID)
	}
	return rollout, nil
}

func buildReplaySnapshot(db *sql.DB, snapshotID string) (ReplaySnapshot, error) {
	var snapshot ReplaySnapshot
	var tainted int64
	err := db.QueryRow(`SELECT id, COALESCE(name, ''), kind, snapshot_physical_type, path, manifest_hash, file_count, bytes, status, COALESCE(tainted, 0)
		FROM snapshots WHERE id = ?`, snapshotID).Scan(&snapshot.ID, &snapshot.Name, &snapshot.Kind, &snapshot.PhysicalType, &snapshot.Path, &snapshot.ManifestHash, &snapshot.FileCount, &snapshot.Bytes, &snapshot.Status, &tainted)
	if err != nil {
		return ReplaySnapshot{}, err
	}
	snapshot.Tainted = tainted != 0
	return snapshot, nil
}

func buildReplayAttemptNode(db *sql.DB, rolloutID, attemptID string) (ReplayAttemptPlan, error) {
	var attempt ReplayAttemptPlan
	var isWinner, budgetExceeded int
	err := db.QueryRow(`SELECT id, snapshot_id, tool_call_id, workspace_path, strategy, command, status, risk_status, COALESCE(artifact_result, ''),
			is_winner, budget_exceeded, score, cost_estimate
		FROM fork_attempts WHERE id = ? AND rollout_id = ?`, attemptID, rolloutID).
		Scan(&attempt.ID, &attempt.SnapshotID, &attempt.ToolCallID, &attempt.Workspace, &attempt.Strategy, &attempt.Command, &attempt.Status, &attempt.RiskStatus, &attempt.ArtifactResult, &isWinner, &budgetExceeded, &attempt.Score, &attempt.CostEstimate)
	if err != nil {
		return ReplayAttemptPlan{}, err
	}
	attempt.ExecutionID = attempt.ID
	attempt.BaseStateID = attempt.SnapshotID
	attempt.IsWinner = isWinner != 0
	attempt.BudgetExceeded = budgetExceeded != 0
	attempt.BlockReasons = replayBlockReasons(attempt.Status, attempt.RiskStatus, attempt.BudgetExceeded)
	attempt.ReplayBlocked = len(attempt.BlockReasons) > 0
	if attempt.ArtifactResult != "" {
		hash, size, exists := fileDigest(attempt.ArtifactResult)
		attempt.ArtifactDigest = &ReplayArtifactDigest{Path: attempt.ArtifactResult, Exists: exists, SHA256: hash, Bytes: size}
	}
	if attempt.ToolCallID != "" {
		toolCall, err := buildReplayToolCall(db, attempt.ToolCallID)
		if err != nil {
			return ReplayAttemptPlan{}, err
		}
		attempt.ToolCall = &toolCall
	}
	processes, err := buildReplayProcesses(db, attempt.ToolCallID)
	if err != nil {
		return ReplayAttemptPlan{}, err
	}
	attempt.Processes = processes
	effects, err := buildReplayExternalEffects(db, attempt.ID, attempt.ToolCallID)
	if err != nil {
		return ReplayAttemptPlan{}, err
	}
	attempt.ExternalEffects = effects
	events, err := buildReplayEvents(db, attempt.ID, attempt.ToolCallID)
	if err != nil {
		return ReplayAttemptPlan{}, err
	}
	attempt.Events = events
	return attempt, nil
}

func replayBlockReasons(status, risk string, budgetExceeded bool) []string {
	var reasons []string
	if status == "quarantined" {
		reasons = append(reasons, "attempt_quarantined")
	}
	if risk == "tainted" {
		reasons = append(reasons, "risk_tainted")
	}
	if budgetExceeded {
		reasons = append(reasons, "budget_exceeded")
	}
	return reasons
}

func buildReplayToolCall(db *sql.DB, toolCallID string) (ReplayToolCall, error) {
	var toolCall ReplayToolCall
	err := db.QueryRow(`SELECT id, session_id, command, status, COALESCE(exit_code, 0), wall_ms, cost_estimate, COALESCE(result_ref, ''), policy_decision, started_at, ended_at
		FROM tool_calls WHERE id = ?`, toolCallID).Scan(&toolCall.ID, &toolCall.SessionID, &toolCall.Command, &toolCall.Status, &toolCall.ExitCode, &toolCall.WallMS, &toolCall.CostEstimate, &toolCall.ResultRef, &toolCall.PolicyDecision, &toolCall.StartedAt, &toolCall.EndedAt)
	return toolCall, err
}

func buildReplayProcesses(db *sql.DB, toolCallID string) ([]ReplayProcess, error) {
	if toolCallID == "" {
		return nil, nil
	}
	rows, err := db.Query(`SELECT id, session_id, command, status, COALESCE(exit_code, 0), started_at, COALESCE(ended_at, '')
		FROM processes WHERE tool_call_id = ? ORDER BY started_at ASC`, toolCallID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var processes []ReplayProcess
	for rows.Next() {
		var process ReplayProcess
		if err := rows.Scan(&process.ID, &process.SessionID, &process.Command, &process.Status, &process.ExitCode, &process.StartedAt, &process.EndedAt); err != nil {
			return nil, err
		}
		processes = append(processes, process)
	}
	return processes, rows.Err()
}

func buildReplayExternalEffects(db *sql.DB, attemptID, toolCallID string) ([]ReplayExternalEffect, error) {
	rows, err := db.Query(`SELECT id, effect_type, target, mode, decision, compensation_ref, status, payload
		FROM external_effects WHERE attempt_id = ? OR tool_call_id = ? ORDER BY created_at ASC`, attemptID, toolCallID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var effects []ReplayExternalEffect
	for rows.Next() {
		var effect ReplayExternalEffect
		if err := rows.Scan(&effect.ID, &effect.EffectType, &effect.Target, &effect.Mode, &effect.Decision, &effect.CompensationRef, &effect.Status, &effect.Payload); err != nil {
			return nil, err
		}
		effects = append(effects, effect)
	}
	return effects, rows.Err()
}

func buildReplayEvents(db *sql.DB, attemptID, toolCallID string) ([]ReplayEvent, error) {
	rows, err := db.Query(`SELECT id, event_type, source, COALESCE(process_id, ''), COALESCE(snapshot_id, ''), correlation_method, correlation_confidence, payload
		FROM events WHERE tool_call_id = ? OR payload LIKE ? ORDER BY created_at ASC`, toolCallID, "%"+attemptID+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []ReplayEvent
	for rows.Next() {
		var event ReplayEvent
		if err := rows.Scan(&event.ID, &event.EventType, &event.Source, &event.ProcessID, &event.SnapshotID, &event.CorrelationMethod, &event.CorrelationConfidence, &event.Payload); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func PrintReplayManifestJSON(out io.Writer, manifest ReplayManifest) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(manifest)
}

func PrintReplayManifest(out io.Writer, manifest ReplayManifest) {
	if manifest.Scope == "attempt" {
		fmt.Fprintf(out, "replay_attempt=%s mode=%s schema=%s\n", manifest.AttemptID, manifest.Mode, manifest.SchemaVersion)
	} else {
		fmt.Fprintf(out, "replay_run=%s mode=%s schema=%s\n", manifest.RunID, manifest.Mode, manifest.SchemaVersion)
	}
	for _, rollout := range manifest.Rollouts {
		fmt.Fprintf(out, "trajectory=%s run=%s base_state=%s status=%s selected_execution=%s promotion=%s risk=%s\n",
			rollout.ID, rollout.RunID, rollout.BaseSnapshotID, rollout.Status, rollout.WinnerAttemptID, rollout.PromotionID, rollout.RiskStatus)
		if rollout.BaseSnapshot != nil {
			printReplaySnapshot(out, *rollout.BaseSnapshot)
		}
		for _, attempt := range rollout.Attempts {
			printReplayAttempt(out, attempt)
		}
	}
}

func printReplaySnapshot(out io.Writer, snapshot ReplaySnapshot) {
	fmt.Fprintf(out, "  base_state name=%s kind=%s physical=%s status=%s tainted=%t files=%d bytes=%d manifest=%s path=%s\n",
		snapshot.Name, snapshot.Kind, snapshot.PhysicalType, snapshot.Status, snapshot.Tainted, snapshot.FileCount, snapshot.Bytes, snapshot.ManifestHash, snapshot.Path)
}

func printReplayAttempt(out io.Writer, attempt ReplayAttemptPlan) {
	fmt.Fprintf(out, "  execution_scope=%s base_state=%s strategy=%s status=%s risk=%s selected=%t replay_blocked=%t score=%.3f cost=%.6f workspace=%s\n",
		attempt.ID, attempt.SnapshotID, attempt.Strategy, attempt.Status, attempt.RiskStatus, attempt.IsWinner, attempt.ReplayBlocked, attempt.Score, attempt.CostEstimate, attempt.Workspace)
	if len(attempt.BlockReasons) > 0 {
		fmt.Fprintf(out, "    block_reasons=%v\n", attempt.BlockReasons)
	}
	fmt.Fprintf(out, "    command=%q\n", attempt.Command)
	if attempt.ArtifactDigest != nil {
		fmt.Fprintf(out, "    artifact=%s exists=%t sha256=%s bytes=%d\n", attempt.ArtifactDigest.Path, attempt.ArtifactDigest.Exists, attempt.ArtifactDigest.SHA256, attempt.ArtifactDigest.Bytes)
	}
	if attempt.ToolCall != nil {
		printReplayToolCall(out, *attempt.ToolCall)
	}
	for _, process := range attempt.Processes {
		fmt.Fprintf(out, "    process=%s session=%s status=%s exit=%d started_at=%s ended_at=%s command=%q\n",
			process.ID, process.SessionID, process.Status, process.ExitCode, process.StartedAt, process.EndedAt, process.Command)
	}
	for _, effect := range attempt.ExternalEffects {
		fmt.Fprintf(out, "    external_effect=%s type=%s target=%s mode=%s decision=%s compensation_ref=%s status=%s payload=%s\n",
			effect.ID, effect.EffectType, effect.Target, effect.Mode, effect.Decision, effect.CompensationRef, effect.Status, effect.Payload)
	}
	for _, event := range attempt.Events {
		fmt.Fprintf(out, "    event=%s type=%s source=%s process=%s snapshot=%s correlation=%s confidence=%.2f payload=%s\n",
			event.ID, event.EventType, event.Source, event.ProcessID, event.SnapshotID, event.CorrelationMethod, event.CorrelationConfidence, event.Payload)
	}
}

func printReplayToolCall(out io.Writer, toolCall ReplayToolCall) {
	fmt.Fprintf(out, "    tool_call=%s session=%s status=%s exit=%d wall_ms=%d cost=%.6f policy=%s result=%s started_at=%s ended_at=%s command=%q\n",
		toolCall.ID, toolCall.SessionID, toolCall.Status, toolCall.ExitCode, toolCall.WallMS, toolCall.CostEstimate, toolCall.PolicyDecision, toolCall.ResultRef, toolCall.StartedAt, toolCall.EndedAt, toolCall.Command)
}
