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

func TestCreateStackRecordsLineage(t *testing.T) {
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
	result, err := Service{DB: db, Paths: paths}.CreateStack(taskPath)
	if err != nil {
		t.Fatal(err)
	}
	if result.TemplateSnapshotID == "" || result.ReadySnapshotID == "" || result.Attempt.AttemptID == "" {
		t.Fatalf("unexpected stack result: %+v", result)
	}
	ready, lineage, err := Service{DB: db, Paths: paths}.InspectSnapshot(result.ReadySnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if ready.Kind != "ready" || ready.ParentID != result.TemplateSnapshotID || ready.Bytes == 0 {
		t.Fatalf("unexpected ready snapshot: %+v", ready)
	}
	if len(lineage) != 2 || lineage[1].Kind != "template" {
		t.Fatalf("lineage = %+v, want ready -> template", lineage)
	}
}

func TestCreateStackFromTemplateRecordsBundleLineage(t *testing.T) {
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

	templateID := "tmpl-test"
	templateDir := filepath.Join(paths.Templates, templateID)
	if err := os.MkdirAll(templateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(templateDir, "task.yaml"), []byte("run_id: run-test\nimage: alpine:3.20\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest, err := BuildManifest(templateDir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = db.Exec(`INSERT INTO templates (id, name, task_path, image, risk_tier, network_mode, manifest_hash, bytes, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ready', ?)`,
		templateID, "test-template", filepath.Join(root, "task.yaml"), "alpine:3.20", "medium", "allowlist", manifest.Hash, manifest.Bytes, now)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Service{DB: db, Paths: paths}.CreateStackFromTemplate("test-template")
	if err != nil {
		t.Fatal(err)
	}
	if result.TemplateSnapshotID != templateID {
		t.Fatalf("template snapshot = %s, want %s", result.TemplateSnapshotID, templateID)
	}
	ready, lineage, err := Service{DB: db, Paths: paths}.InspectSnapshot(result.ReadySnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if ready.ParentID != templateID || len(lineage) != 2 || lineage[1].ID != templateID {
		t.Fatalf("unexpected lineage: ready=%+v lineage=%+v", ready, lineage)
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
