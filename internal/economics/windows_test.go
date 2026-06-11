package economics

import (
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/store"
)

func TestAggregateResourceWindowsAndRetention(t *testing.T) {
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

	base := time.Date(2026, 6, 11, 1, 2, 3, 0, time.UTC)
	samples := []struct {
		id        string
		sessionID string
		active    float64
		idle      float64
		createdAt time.Time
	}{
		{"cpu-old", "sbx-1", 0.1, 0.9, base.Add(-20 * time.Minute)},
		{"cpu-1", "sbx-1", 0.2, 0.8, base},
		{"cpu-2", "sbx-1", 0.3, 0.7, base.Add(4 * time.Second)},
		{"cpu-3", "sbx-2", 0.4, 0.6, base.Add(61 * time.Second)},
	}
	for _, sample := range samples {
		if _, err := db.Exec(`INSERT INTO cpu_samples
			(id, run_id, session_id, node_id, active_cpu_seconds, idle_seconds, cpu_percent, ewma_active_cpu, throttling, memory_pressure, created_at)
			VALUES (?, 'run-1', ?, 'local', ?, ?, 10, ?, '', 'low', ?)`,
			sample.id, sample.sessionID, sample.active, sample.idle, sample.active, sample.createdAt.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}

	if err := AggregateResourceWindows(db, WindowOptions{Windows: []int{10, 60}}); err != nil {
		t.Fatal(err)
	}
	var active, idle float64
	if err := db.QueryRow(`SELECT active_cpu_seconds, idle_seconds FROM session_resource_windows
		WHERE session_id = 'sbx-1' AND window_seconds = 10 AND window_start = ?`, base.Truncate(10*time.Second).Format(time.RFC3339Nano)).Scan(&active, &idle); err != nil {
		t.Fatal(err)
	}
	if math.Abs(active-0.5) > 0.000001 || math.Abs(idle-1.5) > 0.000001 {
		t.Fatalf("unexpected 10s aggregate active=%.3f idle=%.3f", active, idle)
	}
	var nodeSamples int64
	if err := db.QueryRow(`SELECT sample_count FROM node_resource_windows
		WHERE node_id = 'local' AND window_seconds = 60 AND window_start = ?`, base.Truncate(60*time.Second).Format(time.RFC3339Nano)).Scan(&nodeSamples); err != nil {
		t.Fatal(err)
	}
	if nodeSamples != 2 {
		t.Fatalf("expected current 60s node window to contain 2 samples, got %d", nodeSamples)
	}

	if err := RetainRawCPUSamples(db, WindowOptions{RawRetention: 10 * time.Minute, MaxRawPerSession: 2}); err != nil {
		t.Fatal(err)
	}
	var rawCount int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM cpu_samples WHERE id = 'cpu-old'`).Scan(&rawCount); err != nil {
		t.Fatal(err)
	}
	if rawCount != 0 {
		t.Fatalf("expected old raw sample to be removed")
	}
}
