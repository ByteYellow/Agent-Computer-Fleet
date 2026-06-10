package attempt

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agent-computer-fleet/internal/state"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
)

func TestBestOfSelectsPassingWinner(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".acf"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	taskPath := filepath.Join(root, "task.yaml")
	if err := os.WriteFile(taskPath, []byte("run_id: run-test\nimage: alpine:3.20\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stack, err := state.Service{DB: db, Paths: paths}.CreateStack(taskPath)
	if err != nil {
		t.Fatal(err)
	}

	results, winner, err := Service{DB: db, State: state.Service{DB: db, Paths: paths}}.BestOf(stack.ReadySnapshotID, []string{
		"bad::exit 7",
		"good::test -f task.yaml && echo ok",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	if winner.Strategy != "good" || !winner.IsWinner || winner.ExitCode != 0 {
		t.Fatalf("winner = %+v, want passing good strategy", winner)
	}

	var winnerCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fork_attempts WHERE is_winner = 1`).Scan(&winnerCount); err != nil {
		t.Fatal(err)
	}
	if winnerCount != 1 {
		t.Fatalf("winner count = %d, want 1", winnerCount)
	}
}
