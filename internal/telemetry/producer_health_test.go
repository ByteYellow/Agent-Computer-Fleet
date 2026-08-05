package telemetry

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestBuildProducerHealthReportsQueueDropsAndCoverage(t *testing.T) {
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	source := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(source, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	service := SpoolService{DB: db, Paths: paths}
	if _, err := service.Enqueue(SpoolEnqueueRequest{Format: "falco", RunID: "run-health", SourcePath: source, MaxQueued: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enqueue(SpoolEnqueueRequest{Format: "falco", RunID: "run-health", SourcePath: source, MaxQueued: 1, DropPolicy: "drop_oldest"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO events (id, run_id, source, event_type, payload, correlation_method, created_at) VALUES
		('evt-correlated', 'run-health', 'native_runtime', 'execve', '{}', 'cgroup_time_window', '2026-01-01T00:00:00Z'),
		('evt-gap', 'run-health', 'native_runtime', 'connect', '{}', '', '2026-01-01T00:00:01Z'),
		('evt-drop', 'run-health', 'agentprov_ebpf', 'resource_pressure', '{"signal":"event_drop","dropped":7}', 'cgroup_time_window', '2026-01-01T00:00:02Z')`); err != nil {
		t.Fatal(err)
	}

	report, err := BuildProducerHealth(db, ProducerHealthOptions{RunID: "run-health", MaxQueued: 1, MaxQueuedBytes: 1024, MaxBatchBytes: 512, DropPolicy: "drop_oldest"})
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != ProducerHealthSchemaVersion || report.Spool.QueuedBatches != 1 || report.Spool.DroppedBatches != 1 {
		t.Fatalf("unexpected spool health: %+v", report)
	}
	if report.Events.RuntimeEvents != 3 || report.Events.CorrelatedEvents != 2 || report.Events.UncorrelatedEvents != 1 || report.Events.SensorDroppedEvents != 7 {
		t.Fatalf("unexpected event health: %+v", report.Events)
	}
	if report.Coverage.Complete || !report.Coverage.HasSensorDrops {
		t.Fatalf("unexpected coverage health: %+v", report.Coverage)
	}
}
