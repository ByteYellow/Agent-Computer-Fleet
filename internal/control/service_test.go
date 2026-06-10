package control

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	runtimeplane "github.com/byteyellow/agent-computer-fleet/internal/runtime"
	"github.com/byteyellow/agent-computer-fleet/internal/state"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
)

type fakeDriver struct{}

func (fakeDriver) Name() string { return "fake" }

func (fakeDriver) Capabilities() runtimeplane.Capabilities {
	return runtimeplane.Capabilities{Exec: true, Stop: true, Snapshot: true, Fork: true, Resume: true}
}

func (fakeDriver) CreateSession(ctx context.Context, req runtimeplane.CreateSessionRequest) (string, error) {
	return "container-" + req.SessionID, nil
}

func (fakeDriver) Exec(ctx context.Context, containerID string, command []string, stream bool) (runtimeplane.ExecResult, error) {
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

func osWriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}
