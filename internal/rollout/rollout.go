package rollout

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/attempt"
	"github.com/byteyellow/agent-computer-fleet/internal/evidence"
	"github.com/byteyellow/agent-computer-fleet/internal/ids"
	runtimeplane "github.com/byteyellow/agent-computer-fleet/internal/runtime"
	"github.com/byteyellow/agent-computer-fleet/internal/state"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"gopkg.in/yaml.v3"
)

type Service struct {
	DB    *sql.DB
	Paths store.Paths
}

type StartRequest struct {
	RunID         string
	TaskPath      string
	Snapshot      string
	Strategies    []string
	Fanout        int
	BudgetSeconds int
	MaxCost       float64
	EarlyStop     bool
	Runtime       string
}

type Rollout struct {
	ID              string
	RunID           string
	TaskPath        string
	BaseSnapshotID  string
	Status          string
	Fanout          int
	BudgetSeconds   int
	MaxCost         float64
	WinnerAttemptID string
	PromotionID     string
	CostEstimate    float64
	RiskStatus      string
	CreatedAt       string
	UpdatedAt       string
}

type AttemptInfo struct {
	ID             string
	ToolCallID     string
	SnapshotID     string
	WorkspacePath  string
	Strategy       string
	Command        string
	Status         string
	ExitCode       sql.NullInt64
	WallMS         int64
	Score          float64
	CostEstimate   float64
	SavedCost      float64
	IsWinner       bool
	ArtifactResult string
	OutputSummary  string
	CreatedAt      string
}

type Promotion struct {
	ID                 string
	RolloutID          string
	AttemptID          string
	BaseSnapshotID     string
	Status             string
	TelemetryWatermark string
	RiskStatus         string
	Reason             string
	CreatedAt          string
	UpdatedAt          string
}

func (s Service) Start(req StartRequest) (Rollout, []attempt.Result, attempt.Result, Promotion, error) {
	if req.Snapshot == "" {
		return Rollout{}, nil, attempt.Result{}, Promotion{}, fmt.Errorf("--snapshot is required for rollout start in this phase")
	}
	if len(req.Strategies) == 0 {
		return Rollout{}, nil, attempt.Result{}, Promotion{}, fmt.Errorf("at least one --strategy is required")
	}
	if req.RunID == "" {
		req.RunID = runIDFromTask(req.TaskPath)
	}
	if req.RunID == "" {
		req.RunID = ids.New("run")
	}
	if req.Fanout <= 0 || req.Fanout > len(req.Strategies) {
		req.Fanout = len(req.Strategies)
	}
	if req.Runtime == "" {
		req.Runtime = "local"
	}
	if req.Runtime != "local" && req.Runtime != "docker" {
		return Rollout{}, nil, attempt.Result{}, Promotion{}, fmt.Errorf("unsupported rollout runtime %q", req.Runtime)
	}
	baseSnapshotID, err := s.resolveSnapshotID(req.Snapshot)
	if err != nil {
		return Rollout{}, nil, attempt.Result{}, Promotion{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	rolloutID := ids.New("rollout")
	_, err = s.DB.Exec(`INSERT INTO rollouts
		(id, run_id, task_path, base_snapshot_id, status, fanout, budget_seconds, max_cost, risk_status, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'running', ?, ?, ?, 'pending', ?, ?)`,
		rolloutID, req.RunID, req.TaskPath, baseSnapshotID, req.Fanout, req.BudgetSeconds, req.MaxCost, now, now)
	if err != nil {
		return Rollout{}, nil, attempt.Result{}, Promotion{}, err
	}
	stateSvc := state.Service{DB: s.DB, Paths: s.Paths}
	attemptSvc := attempt.Service{DB: s.DB, State: stateSvc}
	opts := attempt.Options{MaxFanout: req.Fanout, MaxCost: req.MaxCost, EarlyStop: req.EarlyStop, RunID: req.RunID, Runtime: req.Runtime, TaskPath: req.TaskPath, BaseSnapshotID: baseSnapshotID, Paths: s.Paths}
	if req.Runtime == "docker" {
		driver, err := runtimeplane.NewDriver("docker", s.Paths)
		if err != nil {
			_, _ = s.DB.Exec(`UPDATE rollouts SET status = 'failed', updated_at = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339Nano), rolloutID)
			return Rollout{}, nil, attempt.Result{}, Promotion{}, err
		}
		opts.Driver = driver
	}
	results, winner, err := attemptSvc.BestOfWithOptions(baseSnapshotID, req.Strategies, opts)
	if err != nil {
		_, _ = s.DB.Exec(`UPDATE rollouts SET status = 'failed', updated_at = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339Nano), rolloutID)
		return Rollout{}, results, attempt.Result{}, Promotion{}, err
	}
	totalCost := 0.0
	for _, result := range results {
		totalCost += result.CostEstimate
		_, _ = s.DB.Exec(`UPDATE fork_attempts SET rollout_id = ?, tool_call_id = ? WHERE id = ?`, rolloutID, result.ToolCallID, result.AttemptID)
		_, _ = s.DB.Exec(`UPDATE tool_calls SET rollout_id = ?, run_id = ? WHERE id = ?`, rolloutID, req.RunID, result.ToolCallID)
		_ = s.appendEvidence(req.RunID, rolloutID, result.AttemptID, result.SessionID, result.ToolCallID, baseSnapshotID, "attempt_finished", "normal",
			fmt.Sprintf(`{"status":%q,"strategy":%q,"score":%.3f,"cost":%.6f,"burst_status":%q,"process_id":%q}`, result.Status, result.Strategy, result.Score, result.CostEstimate, result.BurstStatus, result.ProcessID))
	}
	promotion, err := s.promoteWithBarrier(rolloutID, baseSnapshotID, winner.AttemptID)
	if err != nil {
		_, _ = s.DB.Exec(`UPDATE rollouts SET status = 'promotion_failed', winner_attempt_id = ?, cost_estimate = ?, updated_at = ? WHERE id = ?`,
			winner.AttemptID, totalCost, time.Now().UTC().Format(time.RFC3339Nano), rolloutID)
		return Rollout{}, results, winner, promotion, err
	}
	updated := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`UPDATE rollouts
		SET status = 'completed', winner_attempt_id = ?, promotion_id = ?, cost_estimate = ?, risk_status = ?, updated_at = ?
		WHERE id = ?`, winner.AttemptID, promotion.ID, totalCost, promotion.RiskStatus, updated, rolloutID)
	if err != nil {
		return Rollout{}, results, winner, promotion, err
	}
	_, _ = s.DB.Exec(`INSERT INTO cost_samples (id, run_id, fanout_cost, saved_cost, created_at)
		VALUES (?, ?, ?, ?, ?)`, ids.New("cost"), req.RunID, totalCost, savedCost(results), updated)
	for _, result := range results {
		if result.AttemptID != winner.AttemptID {
			_ = s.enqueueGC(req.RunID, rolloutID, result.AttemptID, result.WorkspacePath)
		}
	}
	item, err := s.Inspect(rolloutID)
	return item, results, winner, promotion, err
}

func savedCost(results []attempt.Result) float64 {
	var saved float64
	for _, result := range results {
		if result.SavedCost > saved {
			saved = result.SavedCost
		}
	}
	return saved
}

func runIDFromTask(path string) string {
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var task struct {
		RunID string `yaml:"run_id"`
	}
	if err := yaml.Unmarshal(raw, &task); err != nil {
		return ""
	}
	return task.RunID
}

func (s Service) Inspect(id string) (Rollout, error) {
	var item Rollout
	err := s.DB.QueryRow(`SELECT id, run_id, task_path, base_snapshot_id, status, fanout, budget_seconds, max_cost,
		winner_attempt_id, promotion_id, cost_estimate, risk_status, created_at, updated_at
		FROM rollouts WHERE id = ? OR run_id = ? ORDER BY created_at DESC LIMIT 1`, id, id).
		Scan(&item.ID, &item.RunID, &item.TaskPath, &item.BaseSnapshotID, &item.Status, &item.Fanout, &item.BudgetSeconds, &item.MaxCost,
			&item.WinnerAttemptID, &item.PromotionID, &item.CostEstimate, &item.RiskStatus, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s Service) Attempts(rolloutID string) ([]AttemptInfo, error) {
	rows, err := s.DB.Query(`SELECT id, tool_call_id, snapshot_id, workspace_path, strategy, command, status, exit_code, wall_ms,
		score, cost_estimate, saved_cost, is_winner, artifact_result, output_summary, created_at
		FROM fork_attempts WHERE rollout_id = ? ORDER BY created_at ASC`, rolloutID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []AttemptInfo
	for rows.Next() {
		var item AttemptInfo
		var isWinner int
		if err := rows.Scan(&item.ID, &item.ToolCallID, &item.SnapshotID, &item.WorkspacePath, &item.Strategy, &item.Command, &item.Status, &item.ExitCode, &item.WallMS,
			&item.Score, &item.CostEstimate, &item.SavedCost, &isWinner, &item.ArtifactResult, &item.OutputSummary, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.IsWinner = isWinner != 0
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s Service) Winner(rolloutID string) (AttemptInfo, Promotion, error) {
	rollout, err := s.Inspect(rolloutID)
	if err != nil {
		return AttemptInfo{}, Promotion{}, err
	}
	var item AttemptInfo
	var isWinner int
	err = s.DB.QueryRow(`SELECT id, tool_call_id, snapshot_id, workspace_path, strategy, command, status, exit_code, wall_ms,
		score, cost_estimate, saved_cost, is_winner, artifact_result, output_summary, created_at
		FROM fork_attempts WHERE id = ?`, rollout.WinnerAttemptID).
		Scan(&item.ID, &item.ToolCallID, &item.SnapshotID, &item.WorkspacePath, &item.Strategy, &item.Command, &item.Status, &item.ExitCode, &item.WallMS,
			&item.Score, &item.CostEstimate, &item.SavedCost, &isWinner, &item.ArtifactResult, &item.OutputSummary, &item.CreatedAt)
	if err != nil {
		return AttemptInfo{}, Promotion{}, err
	}
	item.IsWinner = isWinner != 0
	promotion, err := s.inspectPromotion(rollout.PromotionID)
	return item, promotion, err
}

func (s Service) TaintAttempt(attemptID, reason string) error {
	if reason == "" {
		reason = "late high-risk telemetry event"
	}
	var rolloutID, snapshotID, runID string
	var toolCallID string
	err := s.DB.QueryRow(`SELECT a.rollout_id, a.snapshot_id, COALESCE(a.tool_call_id, ''), COALESCE(r.run_id, '')
		FROM fork_attempts a LEFT JOIN rollouts r ON a.rollout_id = r.id
		WHERE a.id = ?`, attemptID).Scan(&rolloutID, &snapshotID, &toolCallID, &runID)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`UPDATE snapshots SET status = 'tainted', tainted = 1 WHERE id = ?`, snapshotID)
	if err != nil {
		return err
	}
	if err := s.TaintDescendants(snapshotID, reason); err != nil {
		return err
	}
	_, _ = s.DB.Exec(`INSERT INTO evidence_events
		(id, run_id, rollout_id, attempt_id, tool_call_id, snapshot_id, event_type, priority, payload, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, 'late_high_risk_taint', 'critical', ?, 'queued', ?)`,
		ids.New("evidence"), runID, rolloutID, attemptID, toolCallID, snapshotID, fmt.Sprintf(`{"reason":%q}`, reason), now)
	_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, snapshot_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, 'rollout', 'snapshot_tainted', ?, ?)`,
		ids.New("evt"), runID, snapshotID, fmt.Sprintf(`{"attempt_id":%q,"rollout_id":%q,"reason":%q}`, attemptID, rolloutID, reason), now)
	return nil
}

func (s Service) TaintDescendants(snapshotID, reason string) error {
	if reason == "" {
		reason = "taint propagated from ancestor"
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	queue := []string{snapshotID}
	seen := map[string]bool{}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if seen[current] {
			continue
		}
		seen[current] = true
		_, _ = s.DB.Exec(`UPDATE snapshots SET status = 'tainted', tainted = 1 WHERE id = ?`, current)
		rows, err := s.DB.Query(`SELECT e.child_id FROM snapshot_edges e JOIN snapshots sn ON sn.id = e.child_id WHERE e.parent_id = ?`, current)
		if err != nil {
			return err
		}
		for rows.Next() {
			var child string
			if err := rows.Scan(&child); err != nil {
				rows.Close()
				return err
			}
			queue = append(queue, child)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}
	for id := range seen {
		_, _ = s.DB.Exec(`INSERT INTO events (id, snapshot_id, source, event_type, payload, created_at)
			VALUES (?, ?, 'rollout', 'snapshot_taint_propagated', ?, ?)`,
			ids.New("evt"), id, fmt.Sprintf(`{"root_snapshot_id":%q,"reason":%q}`, snapshotID, reason), now)
	}
	return nil
}

func (s Service) inspectAttempt(attemptID string) (AttemptInfo, error) {
	var item AttemptInfo
	var isWinner int
	err := s.DB.QueryRow(`SELECT id, tool_call_id, snapshot_id, workspace_path, strategy, command, status, exit_code, wall_ms,
		score, cost_estimate, saved_cost, is_winner, artifact_result, output_summary, created_at
		FROM fork_attempts WHERE id = ?`, attemptID).
		Scan(&item.ID, &item.ToolCallID, &item.SnapshotID, &item.WorkspacePath, &item.Strategy, &item.Command, &item.Status, &item.ExitCode, &item.WallMS,
			&item.Score, &item.CostEstimate, &item.SavedCost, &isWinner, &item.ArtifactResult, &item.OutputSummary, &item.CreatedAt)
	item.IsWinner = isWinner != 0
	return item, err
}

func (s Service) promoteWithBarrier(rolloutID, baseSnapshotID, attemptID string) (Promotion, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	promotionID := ids.New("promo")
	watermark := now
	_, err := s.DB.Exec(`INSERT INTO promotions
		(id, rollout_id, attempt_id, base_snapshot_id, status, telemetry_watermark, risk_status, reason, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'promote_candidate', ?, 'pending', 'telemetry drain requested', ?, ?)`,
		promotionID, rolloutID, attemptID, baseSnapshotID, watermark, now, now)
	if err != nil {
		return Promotion{}, err
	}
	_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, source, event_type, payload, created_at)
		SELECT ?, run_id, 'rollout', 'promote_candidate', ?, ? FROM rollouts WHERE id = ?`,
		ids.New("evt"), fmt.Sprintf(`{"rollout_id":%q,"attempt_id":%q,"promotion_id":%q}`, rolloutID, attemptID, promotionID), now, rolloutID)

	updated := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`UPDATE promotions
		SET status = 'telemetry_drain_pending', reason = 'telemetry/evidence drain pending', updated_at = ?
		WHERE id = ?`, updated, promotionID)
	if err != nil {
		return Promotion{}, err
	}
	_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, source, event_type, payload, created_at)
		SELECT ?, run_id, 'rollout', 'telemetry_drain_pending', ?, ? FROM rollouts WHERE id = ?`,
		ids.New("evt"), fmt.Sprintf(`{"rollout_id":%q,"attempt_id":%q,"promotion_id":%q,"telemetry_watermark":%q}`, rolloutID, attemptID, promotionID, watermark), updated, rolloutID)

	drained, drainReason := s.drainPromotionEvidence(attemptID)
	if !drained {
		updated = time.Now().UTC().Format(time.RFC3339Nano)
		_, _ = s.DB.Exec(`UPDATE promotions
			SET status = 'rejected', risk_status = 'pending', reason = ?, updated_at = ?
			WHERE id = ?`, drainReason, updated, promotionID)
		_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, source, event_type, payload, created_at)
			SELECT ?, run_id, 'rollout', 'promotion_rejected', ?, ? FROM rollouts WHERE id = ?`,
			ids.New("evt"), fmt.Sprintf(`{"rollout_id":%q,"attempt_id":%q,"promotion_id":%q,"reason":%q}`, rolloutID, attemptID, promotionID, drainReason), updated, rolloutID)
		return s.inspectPromotion(promotionID)
	}

	updated = time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`UPDATE promotions
		SET status = 'risk_finalized', risk_status = 'clean', reason = ?, updated_at = ?
		WHERE id = ?`, drainReason+"; risk finalized clean", updated, promotionID)
	if err != nil {
		return Promotion{}, err
	}
	_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, source, event_type, payload, created_at)
		SELECT ?, run_id, 'rollout', 'risk_finalized', ?, ? FROM rollouts WHERE id = ?`,
		ids.New("evt"), fmt.Sprintf(`{"rollout_id":%q,"attempt_id":%q,"promotion_id":%q,"risk_status":"clean","telemetry_watermark":%q}`, rolloutID, attemptID, promotionID, watermark), updated, rolloutID)

	if tainted, reason := s.attemptTainted(attemptID, baseSnapshotID); tainted {
		updated = time.Now().UTC().Format(time.RFC3339Nano)
		_, _ = s.DB.Exec(`UPDATE promotions
			SET status = 'rejected', risk_status = 'tainted', reason = ?, updated_at = ?
			WHERE id = ?`, reason, updated, promotionID)
		_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, source, event_type, payload, created_at)
			SELECT ?, run_id, 'rollout', 'promotion_rejected', ?, ? FROM rollouts WHERE id = ?`,
			ids.New("evt"), fmt.Sprintf(`{"rollout_id":%q,"attempt_id":%q,"promotion_id":%q,"reason":%q}`, rolloutID, attemptID, promotionID, reason), updated, rolloutID)
		return s.inspectPromotion(promotionID)
	}

	updated = time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`UPDATE promotions
		SET status = 'promoted', risk_status = 'clean', reason = ?, updated_at = ?
		WHERE id = ?`, drainReason+"; risk finalized clean", updated, promotionID)
	if err != nil {
		return Promotion{}, err
	}
	_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, source, event_type, payload, created_at)
		SELECT ?, run_id, 'rollout', 'winner_promoted', ?, ? FROM rollouts WHERE id = ?`,
		ids.New("evt"), fmt.Sprintf(`{"rollout_id":%q,"attempt_id":%q,"promotion_id":%q}`, rolloutID, attemptID, promotionID), updated, rolloutID)
	return s.inspectPromotion(promotionID)
}

func (s Service) drainPromotionEvidence(attemptID string) (bool, string) {
	timeout := time.Duration(envInt64("ACF_PROMOTION_DRAIN_TIMEOUT_MS", 1000)) * time.Millisecond
	if timeout < 0 {
		timeout = 0
	}
	deadline := time.Now().Add(timeout)
	processedTotal := 0
	for {
		var queued int
		_ = s.DB.QueryRow(`SELECT COALESCE(COUNT(*), 0) FROM evidence_events
			WHERE attempt_id = ? AND status = 'queued'`, attemptID).Scan(&queued)
		if queued == 0 {
			return true, fmt.Sprintf("telemetry/evidence drained: processed=%d", processedTotal)
		}
		result, err := (evidence.Service{DB: s.DB, Paths: s.Paths}).ProcessEvidence(100)
		if err != nil {
			return false, "telemetry/evidence drain failed: " + err.Error()
		}
		processedTotal += result.Processed
		if time.Now().After(deadline) {
			return false, fmt.Sprintf("telemetry/evidence drain timeout: queued=%d processed=%d timeout_ms=%d", queued, processedTotal, timeout.Milliseconds())
		}
		if result.Processed == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func (s Service) attemptTainted(attemptID, baseSnapshotID string) (bool, string) {
	var status string
	var tainted int
	_ = s.DB.QueryRow(`SELECT status, COALESCE(tainted, 0) FROM snapshots WHERE id = ?`, baseSnapshotID).Scan(&status, &tainted)
	if tainted != 0 || status == "tainted" {
		return true, "base snapshot is tainted"
	}
	var highRiskEvidence int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM evidence_events
		WHERE attempt_id = ? AND priority IN ('high', 'critical')`, attemptID).Scan(&highRiskEvidence)
	if highRiskEvidence > 0 {
		return true, "high-risk evidence exists for attempt"
	}
	var blockingDecision int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM policy_decisions
		WHERE decision IN ('deny', 'kill', 'quarantine', 'taint_snapshot') AND (
			event_id IN (SELECT id FROM events WHERE process_id = ? OR snapshot_id = ?)
		)`, attemptID, baseSnapshotID).Scan(&blockingDecision)
	if blockingDecision > 0 {
		return true, "blocking policy decision exists for attempt"
	}
	return false, ""
}

func (s Service) appendEvidence(runID, rolloutID, attemptID, sessionID, toolCallID, snapshotID, eventType, priority, payload string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.DB.Exec(`INSERT INTO evidence_events
		(id, run_id, rollout_id, attempt_id, session_id, tool_call_id, snapshot_id, event_type, priority, payload, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?)`,
		ids.New("evidence"), runID, rolloutID, attemptID, sessionID, toolCallID, snapshotID, eventType, priority, payload, now)
	return err
}

func (s Service) enqueueGC(runID, rolloutID, attemptID, workspacePath string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.DB.Exec(`INSERT INTO gc_jobs
		(id, run_id, rollout_id, attempt_id, workspace_path, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 'queued', ?, ?)`,
		ids.New("gc"), runID, rolloutID, attemptID, workspacePath, now, now)
	return err
}

func (s Service) inspectPromotion(id string) (Promotion, error) {
	var item Promotion
	err := s.DB.QueryRow(`SELECT id, rollout_id, attempt_id, base_snapshot_id, status, telemetry_watermark,
		risk_status, reason, created_at, updated_at FROM promotions WHERE id = ?`, id).
		Scan(&item.ID, &item.RolloutID, &item.AttemptID, &item.BaseSnapshotID, &item.Status, &item.TelemetryWatermark,
			&item.RiskStatus, &item.Reason, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s Service) resolveSnapshotID(nameOrID string) (string, error) {
	var id string
	err := s.DB.QueryRow(`SELECT id FROM snapshots WHERE id = ? OR name = ? ORDER BY created_at DESC LIMIT 1`, nameOrID, nameOrID).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("resolve snapshot %q: %w", nameOrID, err)
	}
	return id, nil
}

func envInt64(name string, fallback int64) int64 {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}
