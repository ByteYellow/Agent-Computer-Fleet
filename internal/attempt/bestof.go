package attempt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/control"
	"github.com/byteyellow/agent-computer-fleet/internal/ids"
	runtimeplane "github.com/byteyellow/agent-computer-fleet/internal/runtime"
	"github.com/byteyellow/agent-computer-fleet/internal/scheduler"
	"github.com/byteyellow/agent-computer-fleet/internal/state"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
)

type Service struct {
	DB    *sql.DB
	State state.Service
}

type Result struct {
	AttemptID      string
	ToolCallID     string
	SessionID      string
	ProcessID      string
	WorkspacePath  string
	Strategy       string
	Command        string
	Status         string
	ExitCode       int
	WallMS         int64
	OutputSummary  string
	Score          float64
	BudgetSeconds  int
	ArtifactResult string
	CostEstimate   float64
	SavedCost      float64
	IsWinner       bool
	BurstID        string
	BurstStatus    string
	BurstReason    string
}

func (s Service) BestOf(snapshotNameOrID string, strategies []string) ([]Result, Result, error) {
	return s.BestOfWithOptions(snapshotNameOrID, strategies, Options{MaxFanout: len(strategies)})
}

type Options struct {
	MaxFanout       int
	MaxCost         float64
	EarlyStop       bool
	RunID           string
	BurstCPURequest float64
	BurstTTL        time.Duration
	Runtime         string
	TaskPath        string
	BaseSnapshotID  string
	Paths           store.Paths
	Driver          runtimeplane.Driver
}

type Strategy struct {
	Name           string
	Command        string
	BudgetSeconds  int
	ScoreParser    string
	ArtifactResult string
}

func (s Service) BestOfWithOptions(snapshotNameOrID string, strategies []string, opts Options) ([]Result, Result, error) {
	if len(strategies) == 0 {
		return nil, Result{}, fmt.Errorf("at least one --strategy is required")
	}
	parsed := parseStrategies(strategies)
	if opts.MaxFanout <= 0 || opts.MaxFanout > len(parsed) {
		opts.MaxFanout = len(parsed)
	}
	if opts.MaxCost > 0 {
		maxByCost := int(opts.MaxCost / 0.001)
		if maxByCost < 1 {
			maxByCost = 1
		}
		if maxByCost < opts.MaxFanout {
			opts.MaxFanout = maxByCost
		}
	}
	parsed = parsed[:opts.MaxFanout]
	forks, err := s.State.Fork(snapshotNameOrID, len(parsed))
	if err != nil {
		return nil, Result{}, err
	}
	toolCallIDs := make([]string, len(parsed))
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	for i, strategy := range parsed {
		toolCallID := ids.New("tool")
		toolCallIDs[i] = toolCallID
		if _, err := s.DB.Exec(`INSERT INTO tool_calls
			(id, run_id, attempt_id, command, args_hash, status, created_at)
			VALUES (?, ?, ?, ?, ?, 'prepared', ?)`,
			toolCallID, opts.RunID, forks[i].AttemptID, strategy.Command, argsHash(strategy.Command), createdAt); err != nil {
			return nil, Result{}, err
		}
	}
	results := make([]Result, len(parsed))
	var wg sync.WaitGroup
	for i, fork := range forks {
		wg.Add(1)
		go func(i int, fork state.ForkResult, strategy Strategy, toolCallID string) {
			defer wg.Done()
			results[i] = s.runAttemptWithBurst(fork.AttemptID, toolCallID, fork.WorkspacePath, strategy, opts)
		}(i, fork, parsed[i], toolCallIDs[i])
	}
	wg.Wait()

	winnerIndex := -1
	var totalCost float64
	for i, result := range results {
		totalCost += result.CostEstimate
		if _, err := s.DB.Exec(`UPDATE fork_attempts
			SET tool_call_id = ?, strategy = ?, command = ?, status = ?, exit_code = ?, wall_ms = ?, output_summary = ?, score = ?, budget_seconds = ?, artifact_result = ?, cost_estimate = ?, saved_cost = ?
			WHERE id = ?`, result.ToolCallID, result.Strategy, result.Command, result.Status, result.ExitCode, result.WallMS, result.OutputSummary, result.Score, result.BudgetSeconds, result.ArtifactResult, result.CostEstimate, result.SavedCost, result.AttemptID); err != nil {
			return results, Result{}, err
		}
		endedAt := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := s.DB.Exec(`UPDATE tool_calls
			SET session_id = ?, status = ?, exit_code = ?, wall_ms = ?, cost_estimate = ?, result_ref = ?, policy_decision = 'allow', started_at = COALESCE(NULLIF(started_at, ''), created_at), ended_at = ?
			WHERE id = ?`, result.SessionID, result.Status, result.ExitCode, result.WallMS, result.CostEstimate, result.ArtifactResult, endedAt, result.ToolCallID); err != nil {
			return results, Result{}, err
		}
		if winnerIndex == -1 || better(result, results[winnerIndex]) {
			winnerIndex = i
		}
	}
	if winnerIndex == -1 {
		return results, Result{}, fmt.Errorf("no attempts executed")
	}
	winner := results[winnerIndex]
	winner.IsWinner = true
	results[winnerIndex].IsWinner = true
	if _, err := s.DB.Exec(`UPDATE fork_attempts SET is_winner = CASE WHEN id = ? THEN 1 ELSE 0 END`, winner.AttemptID); err != nil {
		return results, Result{}, err
	}
	saved := float64(len(strategies)-len(results)) * 0.001
	for i := range results {
		results[i].SavedCost = saved
		_, _ = s.DB.Exec(`UPDATE fork_attempts SET saved_cost = ? WHERE id = ?`, saved, results[i].AttemptID)
	}
	_, _ = s.DB.Exec(`INSERT INTO cost_samples (id, run_id, fanout_cost, saved_cost, created_at)
		SELECT 'cost-' || lower(hex(randomblob(6))), COALESCE(s.run_id, 'unknown'), ?, ?, ?
		FROM snapshots sn LEFT JOIN sessions s ON sn.session_id = s.id WHERE sn.id = (SELECT snapshot_id FROM fork_attempts WHERE id = ?)
		LIMIT 1`, totalCost, saved, time.Now().UTC().Format(time.RFC3339Nano), winner.AttemptID)
	return results, winner, nil
}

func (s Service) runAttemptWithBurst(attemptID, toolCallID, workspacePath string, strategy Strategy, opts Options) Result {
	if strings.EqualFold(opts.Runtime, "docker") {
		return s.runDockerAttempt(attemptID, toolCallID, workspacePath, strategy, opts)
	}
	cpuRequest := opts.BurstCPURequest
	if cpuRequest <= 0 {
		cpuRequest = 1
	}
	ttl := opts.BurstTTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	runID := opts.RunID
	if runID == "" {
		runID = "unknown"
	}
	startedAt := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = s.DB.Exec(`UPDATE tool_calls SET status = 'burst_pending', started_at = ? WHERE id = ?`, startedAt, toolCallID)
	reservation, err := (scheduler.Scheduler{DB: s.DB}).ReserveBurst(runID, attemptID, toolCallID, cpuRequest, ttl)
	if err != nil {
		reason := reservation.Reason
		if reason == "" {
			reason = err.Error()
		}
		endedAt := time.Now().UTC().Format(time.RFC3339Nano)
		_, _ = s.DB.Exec(`UPDATE tool_calls
			SET status = 'rejected', exit_code = 125, result_ref = ?, policy_decision = 'allow', ended_at = ?
			WHERE id = ?`, reason, endedAt, toolCallID)
		return Result{
			AttemptID:      attemptID,
			ToolCallID:     toolCallID,
			WorkspacePath:  workspacePath,
			Strategy:       strategy.Name,
			Command:        strategy.Command,
			Status:         "rejected",
			ExitCode:       125,
			OutputSummary:  reason,
			Score:          -2000,
			BudgetSeconds:  strategy.BudgetSeconds,
			ArtifactResult: strategy.ArtifactResult,
			BurstID:        reservation.ID,
			BurstStatus:    "rejected",
			BurstReason:    reason,
		}
	}
	_, _ = s.DB.Exec(`UPDATE tool_calls SET status = 'running' WHERE id = ?`, toolCallID)
	result := runAttempt(attemptID, workspacePath, strategy)
	result.ToolCallID = toolCallID
	result.BurstID = reservation.ID
	result.BurstStatus = "released"
	result.BurstReason = reservation.Reason
	_ = (scheduler.Scheduler{DB: s.DB}).ReleaseBurst(reservation.ID)
	return result
}

func (s Service) runDockerAttempt(attemptID, toolCallID, workspacePath string, strategy Strategy, opts Options) Result {
	if opts.TaskPath == "" {
		return rejectedResult(attemptID, toolCallID, workspacePath, strategy, "docker rollout requires task path")
	}
	if opts.Driver == nil {
		return rejectedResult(attemptID, toolCallID, workspacePath, strategy, "docker rollout requires runtime driver")
	}
	ctrl := control.Service{DB: s.DB, Paths: opts.Paths, Driver: opts.Driver}
	sessionID, err := ctrl.CreateSessionFromWorkspace(control.WorkspaceSessionRequest{
		RunID:            opts.RunID,
		TaskPath:         opts.TaskPath,
		WorkspacePath:    workspacePath,
		ParentSnapshotID: opts.BaseSnapshotID,
		AttemptID:        attemptID,
	})
	if err != nil {
		return rejectedResult(attemptID, toolCallID, workspacePath, strategy, err.Error())
	}
	defer func() { _ = ctrl.RemoveSession(sessionID) }()
	var output bytes.Buffer
	start := time.Now()
	processID, execErr := ctrl.ExecStream(sessionID, []string{"sh", "-lc", strategy.Command}, &output, &output)
	wallMS := time.Since(start).Milliseconds()
	exitCode := 0
	status := "passed"
	if execErr != nil {
		status = "failed"
		exitCode = 1
		if processID != "" {
			_ = s.DB.QueryRow(`SELECT COALESCE(exit_code, 1) FROM processes WHERE id = ?`, processID).Scan(&exitCode)
		}
		if exitCode == 125 {
			status = "rejected"
		}
	}
	if processID != "" {
		var dbExit int
		if err := s.DB.QueryRow(`SELECT COALESCE(exit_code, ?) FROM processes WHERE id = ?`, exitCode, processID).Scan(&dbExit); err == nil {
			exitCode = dbExit
		}
		_, _ = s.DB.Exec(`UPDATE processes SET tool_call_id = ? WHERE id = ?`, toolCallID, processID)
		_, _ = s.DB.Exec(`UPDATE events SET tool_call_id = ? WHERE process_id = ?`, toolCallID, processID)
	}
	score := scoreOutput(output.String(), strategy.ScoreParser, wallMS, exitCode)
	if exitCode != 0 {
		score = -1000.0 - float64(exitCode)
	}
	cost := float64(wallMS) / 1000.0 * 0.001
	result := Result{
		AttemptID:      attemptID,
		ToolCallID:     toolCallID,
		SessionID:      sessionID,
		ProcessID:      processID,
		WorkspacePath:  workspacePath,
		Strategy:       strategy.Name,
		Command:        strategy.Command,
		Status:         status,
		ExitCode:       exitCode,
		WallMS:         wallMS,
		OutputSummary:  summarize(output.String()),
		Score:          score,
		BudgetSeconds:  strategy.BudgetSeconds,
		ArtifactResult: strategy.ArtifactResult,
		CostEstimate:   cost,
		BurstStatus:    "runtime",
	}
	if execErr != nil && result.OutputSummary == "" {
		result.OutputSummary = execErr.Error()
	}
	return result
}

func rejectedResult(attemptID, toolCallID, workspacePath string, strategy Strategy, reason string) Result {
	return Result{
		AttemptID:      attemptID,
		ToolCallID:     toolCallID,
		WorkspacePath:  workspacePath,
		Strategy:       strategy.Name,
		Command:        strategy.Command,
		Status:         "rejected",
		ExitCode:       125,
		OutputSummary:  reason,
		Score:          -2000,
		BudgetSeconds:  strategy.BudgetSeconds,
		ArtifactResult: strategy.ArtifactResult,
		BurstStatus:    "rejected",
		BurstReason:    reason,
	}
}

func argsHash(command string) string {
	sum := sha256.Sum256([]byte(command))
	return hex.EncodeToString(sum[:])
}

func parseStrategies(raws []string) []Strategy {
	strategies := make([]Strategy, 0, len(raws))
	for i, raw := range raws {
		strategies = append(strategies, parseStrategy(raw, i))
	}
	return strategies
}

func parseStrategy(raw string, index int) Strategy {
	parts := strings.SplitN(raw, "::", 2)
	name := fmt.Sprintf("strategy-%d", index+1)
	command := strings.TrimSpace(raw)
	if len(parts) == 2 {
		name = strings.TrimSpace(parts[0])
		command = strings.TrimSpace(parts[1])
	}
	strategy := Strategy{Name: name, Command: command, BudgetSeconds: 0}
	fields := strings.Split(command, "::")
	if len(fields) > 1 {
		strategy.Command = strings.TrimSpace(fields[0])
		for _, field := range fields[1:] {
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			switch strings.TrimSpace(key) {
			case "budget":
				strategy.BudgetSeconds, _ = strconv.Atoi(strings.TrimSpace(value))
			case "score":
				strategy.ScoreParser = strings.TrimSpace(value)
			case "artifact":
				strategy.ArtifactResult = strings.TrimSpace(value)
			}
		}
	}
	return strategy
}

func runAttempt(attemptID, workspacePath string, strategy Strategy) Result {
	start := time.Now()
	ctx := context.Background()
	cancel := func() {}
	if strategy.BudgetSeconds > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(strategy.BudgetSeconds)*time.Second)
	}
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-lc", strategy.Command)
	cmd.Dir = workspacePath
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	wallMS := time.Since(start).Milliseconds()
	exitCode := 0
	status := "passed"
	if err != nil {
		status = "failed"
		exitCode = 1
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
	}
	score := scoreOutput(output.String(), strategy.ScoreParser, wallMS, exitCode)
	if exitCode != 0 {
		score = -1000.0 - float64(exitCode)
	}
	cost := float64(wallMS) / 1000.0 * 0.001
	return Result{
		AttemptID:      attemptID,
		WorkspacePath:  workspacePath,
		Strategy:       strategy.Name,
		Command:        strategy.Command,
		Status:         status,
		ExitCode:       exitCode,
		WallMS:         wallMS,
		OutputSummary:  summarize(output.String()),
		Score:          score,
		BudgetSeconds:  strategy.BudgetSeconds,
		ArtifactResult: strategy.ArtifactResult,
		CostEstimate:   cost,
	}
}

func scoreOutput(output, parser string, wallMS int64, exitCode int) float64 {
	if strings.HasPrefix(parser, "contains:") {
		needle := strings.TrimPrefix(parser, "contains:")
		if strings.Contains(output, needle) {
			return 1000.0 - float64(wallMS)/1000
		}
		return -100.0
	}
	if strings.HasPrefix(parser, "number:") {
		value := strings.TrimSpace(output)
		score, err := strconv.ParseFloat(value, 64)
		if err == nil {
			return score
		}
	}
	return 1000.0 - float64(wallMS)/1000
}

func better(a, b Result) bool {
	if a.ExitCode == 0 && b.ExitCode != 0 {
		return true
	}
	if a.ExitCode != 0 && b.ExitCode == 0 {
		return false
	}
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	return a.WallMS < b.WallMS
}

func summarize(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.ReplaceAll(raw, "\n", " | ")
	if len(raw) > 240 {
		return raw[:240]
	}
	return raw
}
