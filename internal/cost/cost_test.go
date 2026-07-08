package cost

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestAdmitUsesActiveCPUAndMemorySafety(t *testing.T) {
	ok := Admit(AdmissionInput{
		PhysicalCPU:       4,
		OvercommitRatio:   2,
		ActiveCPURequest:  6,
		IdleCPURequest:    10,
		IdleDiscount:      0.1,
		MemoryAllocatedMB: 512,
		MemoryRequestMB:   512,
		MemoryTotalMB:     2048,
		MemorySafetyRatio: 0.9,
	})
	if !ok {
		t.Fatalf("expected idle-discounted CPU request to be admitted")
	}

	ok = Admit(AdmissionInput{
		PhysicalCPU:       4,
		OvercommitRatio:   2,
		ActiveCPURequest:  9,
		IdleCPURequest:    0,
		MemoryAllocatedMB: 0,
		MemoryRequestMB:   256,
		MemoryTotalMB:     2048,
	})
	if ok {
		t.Fatalf("expected active CPU over capacity to be rejected")
	}

	ok = Admit(AdmissionInput{
		PhysicalCPU:       8,
		OvercommitRatio:   2,
		ActiveCPURequest:  1,
		MemoryAllocatedMB: 1900,
		MemoryRequestMB:   200,
		MemoryTotalMB:     2048,
		MemorySafetyRatio: 0.9,
	})
	if ok {
		t.Fatalf("expected unsafe memory allocation to be rejected")
	}
}

func TestShowCostIncludesRolloutPruningSummary(t *testing.T) {
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
	_, err = db.Exec(`INSERT INTO snapshots (id, name, kind, source, path, manifest_hash, file_count, bytes, status, created_at)
		VALUES ('snap-test', 'ready', 'ready', 'test', ?, 'hash', 1, 1, 'ready', ?)`, filepath.Join(root, "snap-test"), now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO rollouts (id, run_id, status, fanout, winner_attempt_id, cost_estimate, risk_status, created_at, updated_at)
		VALUES ('rollout-test', 'run-test', 'completed', 3, 'attempt-win', 0.003, 'clean', ?, ?)`, now, now)
	if err != nil {
		t.Fatal(err)
	}
	attempts := []struct {
		id       string
		status   string
		cost     float64
		saved    float64
		isWinner int
	}{
		{"attempt-win", "passed", 0.002, 0.001, 1},
		{"attempt-full", "failed", 0.001, 0.001, 0},
		{"attempt-pruned", "pruned", 0.0001, 0.001, 0},
	}
	for _, attempt := range attempts {
		_, err = db.Exec(`INSERT INTO fork_attempts (id, rollout_id, snapshot_id, workspace_path, fork_ms, status, score, cost_estimate, saved_cost, is_winner, created_at)
			VALUES (?, 'rollout-test', 'snap-test', ?, 1, ?, 1, ?, ?, ?, ?)`,
			attempt.id, filepath.Join(root, attempt.id), attempt.status, attempt.cost, attempt.saved, attempt.isWinner, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = db.Exec(`INSERT INTO cost_samples (id, run_id, fanout_cost, saved_cost, created_at)
		VALUES ('cost-test', 'run-test', 0.0031, 0.001, ?)`, now)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := ShowCost(db, "run-test", &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"rollout_cost_summary attempts=3 executed=2 pruned=1 winners=1",
		"fanout_cost=0.003100",
		"saved_cost=0.001000",
		"saved_ratio=0.244",
		"attempt_id=attempt-pruned",
		"status=pruned",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("cost output missing %q:\n%s", want, got)
		}
	}
}
