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
	Templates  string
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
		Templates:  filepath.Join(root, "templates"),
		Artifacts:  filepath.Join(root, "artifacts"),
		Logs:       filepath.Join(root, "logs"),
	}
}

func Init(root string) (Paths, error) {
	paths := ResolvePaths(root)
	for _, dir := range []string{paths.Root, paths.Workspaces, paths.Snapshots, paths.Templates, paths.Artifacts, paths.Logs} {
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
			kind TEXT NOT NULL DEFAULT 'directory',
			source TEXT NOT NULL DEFAULT 'session',
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
			strategy TEXT NOT NULL DEFAULT '',
			command TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'prepared',
			exit_code INTEGER,
			wall_ms INTEGER NOT NULL DEFAULT 0,
			output_summary TEXT NOT NULL DEFAULT '',
			score REAL NOT NULL DEFAULT 0,
			is_winner INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL,
			FOREIGN KEY(snapshot_id) REFERENCES snapshots(id)
		);`,
		`CREATE TABLE IF NOT EXISTS events (
			id TEXT PRIMARY KEY,
			run_id TEXT,
			session_id TEXT,
			tool_call_id TEXT NOT NULL DEFAULT '',
			process_id TEXT NOT NULL DEFAULT '',
			snapshot_id TEXT NOT NULL DEFAULT '',
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
		`CREATE TABLE IF NOT EXISTS ports (
			id TEXT PRIMARY KEY,
			session_id TEXT NOT NULL,
			run_id TEXT NOT NULL,
			container_id TEXT NOT NULL,
			container_port INTEGER NOT NULL,
			host_port INTEGER NOT NULL,
			preview_url TEXT NOT NULL,
			pid INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS templates (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			task_path TEXT NOT NULL,
			image TEXT NOT NULL,
			risk_tier TEXT NOT NULL,
			network_mode TEXT NOT NULL,
			manifest_hash TEXT NOT NULL,
			bytes INTEGER NOT NULL,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS baseline_profiles (
			id TEXT PRIMARY KEY,
			template_name TEXT NOT NULL,
			exec_count INTEGER NOT NULL,
			network_event_count INTEGER NOT NULL,
			policy_block_count INTEGER NOT NULL,
			active_cpu_seconds REAL NOT NULL,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS warm_pool_items (
			id TEXT PRIMARY KEY,
			template_name TEXT NOT NULL,
			session_id TEXT,
			workspace_path TEXT,
			frequency INTEGER NOT NULL DEFAULT 0,
			cold_start_p95_ms INTEGER NOT NULL DEFAULT 0,
			size_score REAL NOT NULL DEFAULT 1,
			priority REAL NOT NULL DEFAULT 0,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS forensics_bundles (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL,
			path TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS nodes (
			id TEXT PRIMARY KEY,
			address TEXT NOT NULL,
			runtime TEXT NOT NULL,
			labels TEXT NOT NULL DEFAULT '',
			cpu_capacity REAL NOT NULL DEFAULT 0,
			memory_mb INTEGER NOT NULL DEFAULT 0,
			active_cpu_debt REAL NOT NULL DEFAULT 0,
			warm_hit_count INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
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
		`ALTER TABLE snapshots ADD COLUMN kind TEXT NOT NULL DEFAULT 'directory';`,
		`ALTER TABLE snapshots ADD COLUMN source TEXT NOT NULL DEFAULT 'session';`,
		`ALTER TABLE snapshots ADD COLUMN snapshot_create_ms INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE fork_attempts ADD COLUMN strategy TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE fork_attempts ADD COLUMN command TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE fork_attempts ADD COLUMN status TEXT NOT NULL DEFAULT 'prepared';`,
		`ALTER TABLE fork_attempts ADD COLUMN exit_code INTEGER;`,
		`ALTER TABLE fork_attempts ADD COLUMN wall_ms INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE fork_attempts ADD COLUMN output_summary TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE fork_attempts ADD COLUMN score REAL NOT NULL DEFAULT 0;`,
		`ALTER TABLE fork_attempts ADD COLUMN is_winner INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE cost_samples ADD COLUMN quarantine_count INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE events ADD COLUMN tool_call_id TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE events ADD COLUMN process_id TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE events ADD COLUMN snapshot_id TEXT NOT NULL DEFAULT '';`,
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
