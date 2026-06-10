package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

const DefaultDataDir = ".acf"

type Paths struct {
	Root       string
	DB         string
	Workspaces string
	Snapshots  string
	Artifacts  string
	Logs       string
}

func ResolvePaths(root string) Paths {
	if root == "" {
		root = DefaultDataDir
	}
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}
	return Paths{
		Root:       root,
		DB:         filepath.Join(root, "acf.db"),
		Workspaces: filepath.Join(root, "workspaces"),
		Snapshots:  filepath.Join(root, "snapshots"),
		Artifacts:  filepath.Join(root, "artifacts"),
		Logs:       filepath.Join(root, "logs"),
	}
}

func Init(root string) (Paths, error) {
	paths := ResolvePaths(root)
	for _, dir := range []string{paths.Root, paths.Workspaces, paths.Snapshots, paths.Artifacts, paths.Logs} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return paths, err
		}
	}
	db, err := Open(paths)
	if err != nil {
		return paths, err
	}
	defer db.Close()
	return paths, EnsureSchema(db)
}

func Open(paths Paths) (*sql.DB, error) {
	if err := os.MkdirAll(paths.Root, 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", paths.DB)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA foreign_keys = ON;`); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func EnsureSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS leases (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL,
			task_path TEXT NOT NULL,
			task_yaml TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			lease_id TEXT NOT NULL,
			run_id TEXT NOT NULL,
			container_id TEXT,
			workspace_host_path TEXT NOT NULL,
			status TEXT NOT NULL,
			startup_cold_ms INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			FOREIGN KEY(lease_id) REFERENCES leases(id)
		);`,
		`CREATE TABLE IF NOT EXISTS processes (
			id TEXT PRIMARY KEY,
			session_id TEXT NOT NULL,
			container_id TEXT,
			exec_id TEXT,
			command TEXT NOT NULL,
			status TEXT NOT NULL,
			exit_code INTEGER,
			started_at TEXT NOT NULL,
			ended_at TEXT,
			FOREIGN KEY(session_id) REFERENCES sessions(id)
		);`,
		`CREATE TABLE IF NOT EXISTS snapshots (
			id TEXT PRIMARY KEY,
			name TEXT,
			session_id TEXT,
			parent_id TEXT,
			path TEXT NOT NULL,
			manifest_hash TEXT NOT NULL,
			file_count INTEGER NOT NULL,
			bytes INTEGER NOT NULL,
			snapshot_create_ms INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS fork_attempts (
			id TEXT PRIMARY KEY,
			snapshot_id TEXT NOT NULL,
			workspace_path TEXT NOT NULL,
			fork_ms INTEGER NOT NULL,
			created_at TEXT NOT NULL,
			FOREIGN KEY(snapshot_id) REFERENCES snapshots(id)
		);`,
		`CREATE TABLE IF NOT EXISTS events (
			id TEXT PRIMARY KEY,
			run_id TEXT,
			session_id TEXT,
			source TEXT NOT NULL,
			event_type TEXT NOT NULL,
			payload TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS policy_decisions (
			id TEXT PRIMARY KEY,
			event_id TEXT,
			run_id TEXT,
			session_id TEXT,
			decision TEXT NOT NULL,
			reason TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS cost_samples (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL,
			session_id TEXT,
			active_cpu_seconds REAL NOT NULL DEFAULT 0,
			idle_seconds REAL NOT NULL DEFAULT 0,
			wall_seconds REAL NOT NULL DEFAULT 0,
			snapshot_bytes INTEGER NOT NULL DEFAULT 0,
			policy_block_count INTEGER NOT NULL DEFAULT 0,
			quarantine_count INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		);`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("ensure schema: %w", err)
		}
	}
	alterStmts := []string{
		`ALTER TABLE sessions ADD COLUMN startup_cold_ms INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE processes ADD COLUMN exit_code INTEGER;`,
		`ALTER TABLE snapshots ADD COLUMN snapshot_create_ms INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE cost_samples ADD COLUMN quarantine_count INTEGER NOT NULL DEFAULT 0;`,
	}
	for _, stmt := range alterStmts {
		if _, err := db.Exec(stmt); err != nil && !isDuplicateColumn(err) {
			return fmt.Errorf("migrate schema: %w", err)
		}
	}
	return nil
}

func isDuplicateColumn(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate column name")
}
