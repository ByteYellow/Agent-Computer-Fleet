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
const SchemaVersion = 4

type Paths struct {
	Root       string
	DB         string
	Workspaces string
	Snapshots  string
	Templates  string
	Artifacts  string
	Secrets    string
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
		Secrets:    filepath.Join(root, "secrets"),
		Logs:       filepath.Join(root, "logs"),
	}
}

func Init(root string) (Paths, error) {
	paths := ResolvePaths(root)
	for _, dir := range []string{paths.Root, paths.Workspaces, paths.Snapshots, paths.Templates, paths.Artifacts, paths.Secrets, paths.Logs} {
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
	if _, err := db.Exec(`PRAGMA journal_mode = WAL;`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func EnsureSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS schema_versions (
			version INTEGER PRIMARY KEY,
			description TEXT NOT NULL,
			applied_at TEXT NOT NULL
		);`,
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
			runtime TEXT NOT NULL DEFAULT 'docker',
			parent_snapshot_id TEXT NOT NULL DEFAULT '',
			resumed_from_snapshot_id TEXT NOT NULL DEFAULT '',
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
			tool_call_id TEXT NOT NULL DEFAULT '',
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
			delta_parent_id TEXT NOT NULL DEFAULT '',
			delta_files_added INTEGER NOT NULL DEFAULT 0,
			delta_files_modified INTEGER NOT NULL DEFAULT 0,
			delta_files_deleted INTEGER NOT NULL DEFAULT 0,
			planner_score REAL NOT NULL DEFAULT 0,
			snapshot_semantic_type TEXT NOT NULL DEFAULT 'directory',
			snapshot_physical_type TEXT NOT NULL DEFAULT 'copy',
			logical_bytes INTEGER NOT NULL DEFAULT 0,
			physical_bytes INTEGER NOT NULL DEFAULT 0,
			dirty_bytes_estimate INTEGER NOT NULL DEFAULT 0,
			inode_estimate INTEGER NOT NULL DEFAULT 0,
			storage_amplification_ratio REAL NOT NULL DEFAULT 1,
			hot_metadata_paths TEXT NOT NULL DEFAULT '',
			metadata_ops_estimate INTEGER NOT NULL DEFAULT 0,
			copy_up_risk TEXT NOT NULL DEFAULT 'low',
			upperdir_device TEXT NOT NULL DEFAULT '',
			tainted INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS snapshot_files (
			snapshot_id TEXT NOT NULL,
			path TEXT NOT NULL,
			sha256 TEXT NOT NULL,
			size_bytes INTEGER NOT NULL,
			mode TEXT NOT NULL DEFAULT '',
			PRIMARY KEY(snapshot_id, path)
		);`,
		`CREATE TABLE IF NOT EXISTS snapshot_edges (
			id TEXT PRIMARY KEY,
			parent_id TEXT NOT NULL,
			child_id TEXT NOT NULL,
			edge_type TEXT NOT NULL,
			plan TEXT NOT NULL DEFAULT '',
			plan_reason TEXT NOT NULL DEFAULT '',
			planner_score REAL NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS fork_attempts (
			id TEXT PRIMARY KEY,
			rollout_id TEXT NOT NULL DEFAULT '',
			tool_call_id TEXT NOT NULL DEFAULT '',
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
			budget_seconds INTEGER NOT NULL DEFAULT 0,
			artifact_result TEXT NOT NULL DEFAULT '',
			cost_estimate REAL NOT NULL DEFAULT 0,
			saved_cost REAL NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL,
			FOREIGN KEY(snapshot_id) REFERENCES snapshots(id)
		);`,
		`CREATE TABLE IF NOT EXISTS tool_calls (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL DEFAULT '',
			rollout_id TEXT NOT NULL DEFAULT '',
			attempt_id TEXT NOT NULL DEFAULT '',
			session_id TEXT NOT NULL DEFAULT '',
			command TEXT NOT NULL DEFAULT '',
			args_hash TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			exit_code INTEGER,
			wall_ms INTEGER NOT NULL DEFAULT 0,
			cost_estimate REAL NOT NULL DEFAULT 0,
			result_ref TEXT NOT NULL DEFAULT '',
			policy_decision TEXT NOT NULL DEFAULT 'allow',
			created_at TEXT NOT NULL,
			started_at TEXT NOT NULL DEFAULT '',
			ended_at TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE TABLE IF NOT EXISTS rollouts (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL,
			task_path TEXT NOT NULL DEFAULT '',
			base_snapshot_id TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			fanout INTEGER NOT NULL DEFAULT 0,
			budget_seconds INTEGER NOT NULL DEFAULT 0,
			max_cost REAL NOT NULL DEFAULT 0,
			winner_attempt_id TEXT NOT NULL DEFAULT '',
			promotion_id TEXT NOT NULL DEFAULT '',
			cost_estimate REAL NOT NULL DEFAULT 0,
			risk_status TEXT NOT NULL DEFAULT 'pending',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS promotions (
			id TEXT PRIMARY KEY,
			rollout_id TEXT NOT NULL,
			attempt_id TEXT NOT NULL,
			base_snapshot_id TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			telemetry_watermark TEXT NOT NULL DEFAULT '',
			risk_status TEXT NOT NULL DEFAULT 'pending',
			reason TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS evidence_events (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL DEFAULT '',
			rollout_id TEXT NOT NULL DEFAULT '',
			attempt_id TEXT NOT NULL DEFAULT '',
			session_id TEXT NOT NULL DEFAULT '',
			tool_call_id TEXT NOT NULL DEFAULT '',
			snapshot_id TEXT NOT NULL DEFAULT '',
			event_type TEXT NOT NULL,
			priority TEXT NOT NULL DEFAULT 'normal',
			payload TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'queued',
			created_at TEXT NOT NULL,
			processed_at TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE TABLE IF NOT EXISTS gc_jobs (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL DEFAULT '',
			rollout_id TEXT NOT NULL DEFAULT '',
			attempt_id TEXT NOT NULL DEFAULT '',
			workspace_path TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'queued',
			reclaimed_bytes INTEGER NOT NULL DEFAULT 0,
			reclaimed_inodes INTEGER NOT NULL DEFAULT 0,
			gc_latency_ms INTEGER NOT NULL DEFAULT 0,
			failure_reason TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS graph_edges (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL DEFAULT '',
			rollout_id TEXT NOT NULL DEFAULT '',
			from_id TEXT NOT NULL,
			to_id TEXT NOT NULL,
			edge_type TEXT NOT NULL,
			source_event_id TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
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
			rule_id TEXT NOT NULL DEFAULT '',
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
			node_id TEXT NOT NULL DEFAULT 'local',
			fanout_cost REAL NOT NULL DEFAULT 0,
			saved_cost REAL NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS cpu_samples (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL,
			session_id TEXT NOT NULL,
			node_id TEXT NOT NULL DEFAULT 'local',
			active_cpu_seconds REAL NOT NULL DEFAULT 0,
			idle_seconds REAL NOT NULL DEFAULT 0,
			cpu_percent REAL NOT NULL DEFAULT 0,
			ewma_active_cpu REAL NOT NULL DEFAULT 0,
			throttling TEXT NOT NULL DEFAULT '',
			memory_pressure TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS session_resource_windows (
			run_id TEXT NOT NULL,
			session_id TEXT NOT NULL,
			node_id TEXT NOT NULL DEFAULT 'local',
			window_seconds INTEGER NOT NULL,
			window_start TEXT NOT NULL,
			active_cpu_seconds REAL NOT NULL DEFAULT 0,
			idle_seconds REAL NOT NULL DEFAULT 0,
			avg_cpu_percent REAL NOT NULL DEFAULT 0,
			ewma_active_cpu REAL NOT NULL DEFAULT 0,
			throttling_count INTEGER NOT NULL DEFAULT 0,
			memory_pressure_count INTEGER NOT NULL DEFAULT 0,
			sample_count INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL,
			PRIMARY KEY(session_id, window_seconds, window_start)
		);`,
		`CREATE TABLE IF NOT EXISTS node_resource_windows (
			node_id TEXT NOT NULL DEFAULT 'local',
			window_seconds INTEGER NOT NULL,
			window_start TEXT NOT NULL,
			active_cpu_seconds REAL NOT NULL DEFAULT 0,
			idle_seconds REAL NOT NULL DEFAULT 0,
			avg_cpu_percent REAL NOT NULL DEFAULT 0,
			ewma_active_cpu REAL NOT NULL DEFAULT 0,
			throttling_count INTEGER NOT NULL DEFAULT 0,
			memory_pressure_count INTEGER NOT NULL DEFAULT 0,
			session_count INTEGER NOT NULL DEFAULT 0,
			sample_count INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL,
			PRIMARY KEY(node_id, window_seconds, window_start)
		);`,
		`CREATE TABLE IF NOT EXISTS burst_reservations (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL,
			session_id TEXT NOT NULL,
			process_id TEXT NOT NULL DEFAULT '',
			node_id TEXT NOT NULL DEFAULT 'local',
			cpu_request REAL NOT NULL DEFAULT 1,
			status TEXT NOT NULL,
			reason TEXT NOT NULL DEFAULT '',
			expires_at TEXT NOT NULL,
			created_at TEXT NOT NULL,
			released_at TEXT NOT NULL DEFAULT ''
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
			hit_count INTEGER NOT NULL DEFAULT 0,
			last_hit_at TEXT NOT NULL DEFAULT '',
			cold_start_saved_ms INTEGER NOT NULL DEFAULT 0,
			memory_mb INTEGER NOT NULL DEFAULT 0,
			disk_bytes INTEGER NOT NULL DEFAULT 0,
			eviction_reason TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS forensics_bundles (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL,
			path TEXT NOT NULL,
			sha256 TEXT NOT NULL DEFAULT '',
			size_bytes INTEGER NOT NULL DEFAULT 0,
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
		`CREATE TABLE IF NOT EXISTS egress_proxies (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL DEFAULT '',
			session_id TEXT NOT NULL DEFAULT '',
			host_port INTEGER NOT NULL,
			proxy_url TEXT NOT NULL,
			container_proxy_url TEXT NOT NULL,
			mode TEXT NOT NULL DEFAULT 'host',
			network_name TEXT NOT NULL DEFAULT '',
			container_id TEXT NOT NULL DEFAULT '',
			pid INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS egress_allowlist (
			host TEXT PRIMARY KEY,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS egress_credentials (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			host TEXT NOT NULL,
			path_prefix TEXT NOT NULL DEFAULT '/',
			header_name TEXT NOT NULL,
			secret_ref TEXT NOT NULL,
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
		`ALTER TABLE processes ADD COLUMN tool_call_id TEXT NOT NULL DEFAULT '';`,
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
		`ALTER TABLE egress_proxies ADD COLUMN run_id TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE egress_proxies ADD COLUMN session_id TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE egress_proxies ADD COLUMN mode TEXT NOT NULL DEFAULT 'host';`,
		`ALTER TABLE egress_proxies ADD COLUMN network_name TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE egress_proxies ADD COLUMN container_id TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE forensics_bundles ADD COLUMN sha256 TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE forensics_bundles ADD COLUMN size_bytes INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE policy_decisions ADD COLUMN rule_id TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE sessions ADD COLUMN runtime TEXT NOT NULL DEFAULT 'docker';`,
		`ALTER TABLE sessions ADD COLUMN parent_snapshot_id TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE sessions ADD COLUMN resumed_from_snapshot_id TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE cost_samples ADD COLUMN node_id TEXT NOT NULL DEFAULT 'local';`,
		`ALTER TABLE cost_samples ADD COLUMN fanout_cost REAL NOT NULL DEFAULT 0;`,
		`ALTER TABLE cost_samples ADD COLUMN saved_cost REAL NOT NULL DEFAULT 0;`,
		`ALTER TABLE snapshots ADD COLUMN delta_parent_id TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE snapshots ADD COLUMN delta_files_added INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE snapshots ADD COLUMN delta_files_modified INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE snapshots ADD COLUMN delta_files_deleted INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE snapshots ADD COLUMN planner_score REAL NOT NULL DEFAULT 0;`,
		`ALTER TABLE snapshots ADD COLUMN snapshot_semantic_type TEXT NOT NULL DEFAULT 'directory';`,
		`ALTER TABLE snapshots ADD COLUMN snapshot_physical_type TEXT NOT NULL DEFAULT 'copy';`,
		`ALTER TABLE snapshots ADD COLUMN logical_bytes INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE snapshots ADD COLUMN physical_bytes INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE snapshots ADD COLUMN dirty_bytes_estimate INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE snapshots ADD COLUMN inode_estimate INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE snapshots ADD COLUMN storage_amplification_ratio REAL NOT NULL DEFAULT 1;`,
		`ALTER TABLE snapshots ADD COLUMN hot_metadata_paths TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE snapshots ADD COLUMN metadata_ops_estimate INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE snapshots ADD COLUMN copy_up_risk TEXT NOT NULL DEFAULT 'low';`,
		`ALTER TABLE snapshots ADD COLUMN upperdir_device TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE snapshots ADD COLUMN tainted INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE snapshot_edges ADD COLUMN plan_reason TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE snapshot_edges ADD COLUMN planner_score REAL NOT NULL DEFAULT 0;`,
		`ALTER TABLE fork_attempts ADD COLUMN budget_seconds INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE fork_attempts ADD COLUMN artifact_result TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE fork_attempts ADD COLUMN cost_estimate REAL NOT NULL DEFAULT 0;`,
		`ALTER TABLE fork_attempts ADD COLUMN saved_cost REAL NOT NULL DEFAULT 0;`,
		`ALTER TABLE fork_attempts ADD COLUMN rollout_id TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE fork_attempts ADD COLUMN tool_call_id TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE warm_pool_items ADD COLUMN hit_count INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE warm_pool_items ADD COLUMN last_hit_at TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE warm_pool_items ADD COLUMN cold_start_saved_ms INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE warm_pool_items ADD COLUMN memory_mb INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE warm_pool_items ADD COLUMN disk_bytes INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE warm_pool_items ADD COLUMN eviction_reason TEXT NOT NULL DEFAULT '';`,
	}
	for _, stmt := range alterStmts {
		if _, err := db.Exec(stmt); err != nil && !isDuplicateColumn(err) {
			return fmt.Errorf("migrate schema: %w", err)
		}
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO schema_versions (version, description, applied_at)
		VALUES (1, 'initial local control plane schema', datetime('now'))`); err != nil {
		return fmt.Errorf("record schema version: %w", err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO schema_versions (version, description, applied_at)
		VALUES (?, 'agent rollout tool_call, evidence graph, and resource window schema', datetime('now'))`, SchemaVersion); err != nil {
		return fmt.Errorf("record schema version: %w", err)
	}
	return nil
}

func isDuplicateColumn(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate column name")
}
