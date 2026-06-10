package attempt

import (
	"bytes"
	"database/sql"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/state"
)

type Service struct {
	DB    *sql.DB
	State state.Service
}

type Result struct {
	AttemptID     string
	WorkspacePath string
	Strategy      string
	Command       string
	Status        string
	ExitCode      int
	WallMS        int64
	OutputSummary string
	Score         float64
	IsWinner      bool
}

func (s Service) BestOf(snapshotNameOrID string, strategies []string) ([]Result, Result, error) {
	if len(strategies) == 0 {
		return nil, Result{}, fmt.Errorf("at least one --strategy is required")
	}
	forks, err := s.State.Fork(snapshotNameOrID, len(strategies))
	if err != nil {
		return nil, Result{}, err
	}
	results := make([]Result, 0, len(strategies))
	winnerIndex := -1
	for i, fork := range forks {
		name, command := parseStrategy(strategies[i], i)
		result := runAttempt(fork.AttemptID, fork.WorkspacePath, name, command)
		if _, err := s.DB.Exec(`UPDATE fork_attempts
			SET strategy = ?, command = ?, status = ?, exit_code = ?, wall_ms = ?, output_summary = ?, score = ?
			WHERE id = ?`, result.Strategy, result.Command, result.Status, result.ExitCode, result.WallMS, result.OutputSummary, result.Score, result.AttemptID); err != nil {
			return results, Result{}, err
		}
		results = append(results, result)
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
	return results, winner, nil
}

func parseStrategy(raw string, index int) (string, string) {
	parts := strings.SplitN(raw, "::", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	return fmt.Sprintf("strategy-%d", index+1), strings.TrimSpace(raw)
}

func runAttempt(attemptID, workspacePath, strategy, command string) Result {
	start := time.Now()
	cmd := exec.Command("sh", "-lc", command)
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
	score := 1000.0 - float64(wallMS)/1000
	if exitCode != 0 {
		score = -1000.0 - float64(exitCode)
	}
	return Result{
		AttemptID:     attemptID,
		WorkspacePath: workspacePath,
		Strategy:      strategy,
		Command:       command,
		Status:        status,
		ExitCode:      exitCode,
		WallMS:        wallMS,
		OutputSummary: summarize(output.String()),
		Score:         score,
	}
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
