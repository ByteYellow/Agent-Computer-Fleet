package control

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agent-computer-fleet/internal/node"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
)

type fakeRuntime struct{}

func (fakeRuntime) CreateSession(req node.CreateSessionRequest) (string, error) {
	return "container-" + req.SessionID, nil
}

func (fakeRuntime) Exec(containerID string, command []string, stream bool) (node.ExecResult, error) {
	return node.ExecResult{ExecID: "exec-test", ExitCode: 0}, nil
}

func (fakeRuntime) Interrupt(containerID string) error {
	return nil
}

func (fakeRuntime) Stop(containerID string) error {
	return nil
}

func (fakeRuntime) Remove(containerID string) error {
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

	svc := Service{DB: db, Paths: paths, Runtime: fakeRuntime{}}
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
