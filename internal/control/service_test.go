package control

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	runtimeplane "github.com/byteyellow/agent-computer-fleet/internal/runtime"
	"github.com/byteyellow/agent-computer-fleet/internal/state"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
)

type fakeDriver struct{}

var fakeCPUWeights []int64

func (fakeDriver) Name() string { return "fake" }

func (fakeDriver) Capabilities() runtimeplane.Capabilities {
	return runtimeplane.Capabilities{
		Exec:               true,
		Stop:               true,
		Snapshot:           true,
		Fork:               true,
		Resume:             true,
		CPUWeight:          true,
		FilesystemSnapshot: "copy",
		MemorySnapshotType: "none",
		ResumeLatencyClass: "cold",
		IsolationLevel:     "container",
		QuotaSupport:       "cgroup",
		NetworkPolicy:      "proxy",
		TelemetryBinding:   []string{"label"},
	}
}

func (fakeDriver) CreateSession(ctx context.Context, req runtimeplane.CreateSessionRequest) (string, error) {
	return "container-" + req.SessionID, nil
}

func (fakeDriver) Exec(ctx context.Context, containerID string, command []string, stream bool) (runtimeplane.ExecResult, error) {
	return runtimeplane.ExecResult{ExecID: "exec-test", ExitCode: 0}, nil
}

func (fakeDriver) ExecStream(ctx context.Context, containerID string, command []string, stdout, stderr io.Writer) (runtimeplane.ExecResult, error) {
	return runtimeplane.ExecResult{ExecID: "exec-test", ExitCode: 0}, nil
}

func (fakeDriver) Interrupt(ctx context.Context, containerID string) error {
	return nil
}

func (fakeDriver) Stop(ctx context.Context, containerID string) error {
	return nil
}

func (fakeDriver) Remove(ctx context.Context, containerID string) error {
	return nil
}

func (fakeDriver) CreateDirectorySnapshot(ctx context.Context, src, dst string) (state.Manifest, error) {
	return state.Manifest{}, nil
}

func (fakeDriver) ForkDirectorySnapshot(ctx context.Context, src, dst string) (state.Manifest, error) {
	return state.Manifest{}, nil
}

func (fakeDriver) ResumeDirectorySnapshot(ctx context.Context, src, dst string) (state.Manifest, error) {
	return state.Manifest{}, nil
}

func (fakeDriver) SetCPUWeight(ctx context.Context, containerID string, weight int64) error {
	fakeCPUWeights = append(fakeCPUWeights, weight)
	return nil
}

func TestCreateLeaseAndSession(t *testing.T) {
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
	taskYAML := []byte("run_id: run-test\nimage: alpine:3.20\nworkspace: /workspace\nrisk_tier: medium\n")
	if err := osWriteFile(taskPath, taskYAML); err != nil {
		t.Fatal(err)
	}

	svc := Service{DB: db, Paths: paths, Driver: fakeDriver{}}
	fakeCPUWeights = nil
	leaseID, err := svc.CreateLease(taskPath)
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := svc.CreateSession(leaseID)
	if err != nil {
		t.Fatal(err)
	}
	if leaseID == "" || sessionID == "" {
		t.Fatalf("empty ids lease=%q session=%q", leaseID, sessionID)
	}

	var leaseStatus, sessionStatus string
	if err := db.QueryRow(`SELECT status FROM leases WHERE id = ?`, leaseID).Scan(&leaseStatus); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT status FROM sessions WHERE id = ?`, sessionID).Scan(&sessionStatus); err != nil {
		t.Fatal(err)
	}
	if leaseStatus != "allocated" || sessionStatus != "running" {
		t.Fatalf("statuses lease=%s session=%s", leaseStatus, sessionStatus)
	}
}

func TestExecSwitchesCPUProfileForToolPhase(t *testing.T) {
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
	taskYAML := []byte("run_id: run-test\nimage: alpine:3.20\nworkspace: /workspace\nrisk_tier: medium\n")
	if err := osWriteFile(taskPath, taskYAML); err != nil {
		t.Fatal(err)
	}
	svc := Service{DB: db, Paths: paths, Driver: fakeDriver{}}
	fakeCPUWeights = nil
	leaseID, err := svc.CreateLease(taskPath)
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := svc.CreateSession(leaseID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Exec(sessionID, []string{"echo", "ok"}, false); err != nil {
		t.Fatal(err)
	}
	if len(fakeCPUWeights) < 3 {
		t.Fatalf("expected create think + exec tool/think CPU weight updates, got %v", fakeCPUWeights)
	}
	if fakeCPUWeights[len(fakeCPUWeights)-2] != CPUWeightTool || fakeCPUWeights[len(fakeCPUWeights)-1] != CPUWeightThink {
		t.Fatalf("expected exec to switch tool then think, got %v", fakeCPUWeights)
	}
	var events int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE event_type = 'cpu_weight_set' AND session_id = ?`, sessionID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events < 3 {
		t.Fatalf("expected cpu_weight_set events, got %d", events)
	}
}

func osWriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}
