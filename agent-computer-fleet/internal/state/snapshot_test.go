package state

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/store"
)

func TestCreateSnapshotAndForkWorkspaces(t *testing.T) {
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

	workspace := filepath.Join(paths.Workspaces, "sbx-test")
	if err := os.MkdirAll(filepath.Join(workspace, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "nested", "hello.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	insertSession(t, db, workspace)

	svc := Service{DB: db, Paths: paths}
	snapshotID, manifest, snapshotCreateMS, err := svc.CreateDirectorySnapshot("sbx-test", "/workspace", "ready")
	if err != nil {
		t.Fatal(err)
	}
	if snapshotID == "" || manifest.Files != 1 || manifest.Bytes != 5 {
		t.Fatalf("unexpected snapshot result id=%q manifest=%+v", snapshotID, manifest)
	}
	if snapshotCreateMS < 0 {
		t.Fatalf("snapshotCreateMS = %d, want >= 0", snapshotCreateMS)
	}

	forks, err := svc.Fork("ready", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(forks) != 2 {
		t.Fatalf("fork count = %d, want 2", len(forks))
	}
	for _, fork := range forks {
		if fork.AttemptID == "" || fork.WorkspacePath == "" || fork.ForkMS < 0 {
			t.Fatalf("unexpected fork result: %+v", fork)
		}
		b, err := os.ReadFile(filepath.Join(fork.WorkspacePath, "nested", "hello.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "hello" {
			t.Fatalf("forked file = %q, want hello", string(b))
		}
	}
}

func insertSession(t *testing.T, db *sql.DB, workspace string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := db.Exec(`INSERT INTO leases (id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES ('lease-test', 'run-test', 'task.yaml', '{}', 'allocated', ?, ?)`, now, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO sessions (id, lease_id, run_id, container_id, workspace_host_path, status, created_at, updated_at)
		VALUES ('sbx-test', 'lease-test', 'run-test', 'container-test', ?, 'running', ?, ?)`, workspace, now, now)
	if err != nil {
		t.Fatal(err)
	}
}
