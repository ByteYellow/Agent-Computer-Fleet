package scheduler

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/store"
)

func TestReserveBurstRejectsOverInflightLimit(t *testing.T) {
	t.Setenv("ACF_NODE_CPU", "8")
	t.Setenv("ACF_BURST_MAX_INFLIGHT", "1")
	paths, err := store.Init(filepath.Join(t.TempDir(), ".acf"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := Scheduler{DB: db}
	first, err := s.ReserveBurst("run-1", "sbx-1", "proc-1", 1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Admitted {
		t.Fatalf("first reservation rejected: %+v", first)
	}
	second, err := s.ReserveBurst("run-1", "sbx-2", "proc-2", 1, time.Minute)
	if err == nil || second.Admitted {
		t.Fatalf("expected second reservation to be rejected, got reservation=%+v err=%v", second, err)
	}
	state, err := s.NodeState("")
	if err != nil {
		t.Fatal(err)
	}
	if state.BurstInflight != 1 || state.BurstRejectCount != 1 {
		t.Fatalf("unexpected burst state: %+v", state)
	}
	if err := s.ReleaseBurst(first.ID); err != nil {
		t.Fatal(err)
	}
	third, err := s.ReserveBurst("run-1", "sbx-3", "proc-3", 1, time.Minute)
	if err != nil || !third.Admitted {
		t.Fatalf("expected reservation after release to pass, got reservation=%+v err=%v", third, err)
	}
}

func TestReserveBurstDelayWaitsForSlot(t *testing.T) {
	t.Setenv("ACF_NODE_CPU", "8")
	t.Setenv("ACF_BURST_MAX_INFLIGHT", "1")
	t.Setenv("ACF_BURST_OVERFLOW_POLICY", "delay")
	t.Setenv("ACF_BURST_QUEUE_TIMEOUT_MS", "1000")
	paths, err := store.Init(filepath.Join(t.TempDir(), ".acf"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := Scheduler{DB: db}
	first, err := s.ReserveBurst("run-1", "sbx-1", "proc-1", 1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = s.ReleaseBurst(first.ID)
	}()
	second, err := s.ReserveBurst("run-1", "sbx-2", "proc-2", 1, time.Minute)
	if err != nil || !second.Admitted {
		t.Fatalf("expected delayed reservation to pass, got reservation=%+v err=%v", second, err)
	}
	if second.WaitMS <= 0 {
		t.Fatalf("expected delayed reservation wait_ms > 0, got %+v", second)
	}
	var delayed int
	if err := db.QueryRow(`SELECT COUNT(*) FROM burst_reservations WHERE process_id = 'proc-2' AND status = 'delayed'`).Scan(&delayed); err != nil {
		t.Fatal(err)
	}
	if delayed == 0 {
		t.Fatalf("expected queued reservations to be marked delayed")
	}
}
