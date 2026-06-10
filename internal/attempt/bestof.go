package attempt

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/state"
)

type Service struct {
	DB    *sql.DB
	State state.Service
}

type Result struct {
	AttemptID      string
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
}

func (s Service) BestOf(snapshotNameOrID string, strategies []string) ([]Result, Result, error) {
	return s.BestOfWithOptions(snapshotNameOrID, strategies, Options{MaxFanout: len(strategies)})
}

type Options struct {
	MaxFanout int
	MaxCost   float64
	EarlyStop bool
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
	parsed = parsed[:opts.MaxFanout]
	forks, err := s.State.Fork(snapshotNameOrID, len(parsed))
	if err != nil {
		return nil, Result{}, err
	}
	results := make([]Result, 0, len(parsed))
	winnerIndex := -1
	var totalCost float64
	for i, fork := range forks {
		strategy := parsed[i]
		if opts.MaxCost > 0 && totalCost >= opts.MaxCost {
			break
		}
		result := runAttempt(fork.AttemptID, fork.WorkspacePath, strategy)
		totalCost += result.CostEstimate
		if _, err := s.DB.Exec(`UPDATE fork_attempts
			SET strategy = ?, command = ?, status = ?, exit_code = ?, wall_ms = ?, output_summary = ?, score = ?, budget_seconds = ?, artifact_result = ?, cost_estimate = ?, saved_cost = ?
			WHERE id = ?`, result.Strategy, result.Command, result.Status, result.ExitCode, result.WallMS, result.OutputSummary, result.Score, result.BudgetSeconds, result.ArtifactResult, result.CostEstimate, result.SavedCost, result.AttemptID); err != nil {
			return results, Result{}, err
		}
		results = append(results, result)
		if winnerIndex == -1 || better(result, results[winnerIndex]) {
			winnerIndex = i
		}
		if opts.EarlyStop && result.ExitCode == 0 && result.Score >= 1000 {
			break
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
