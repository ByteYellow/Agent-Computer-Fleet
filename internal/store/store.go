package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

const DefaultDataDir = ".agentprov"
const SchemaVersion = 15

type Paths struct {
	Root       string
	DB         string
	Workspaces string
	Snapshots  string
	Templates  string
	Artifacts  string
	Provenance string
	Secrets    string
	Logs       string
	Spool      string
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
		DB:         filepath.Join(root, "agentprov.db"),
		Workspaces: filepath.Join(root, "workspaces"),
		Snapshots:  filepath.Join(root, "snapshots"),
		Templates:  filepath.Join(root, "templates"),
		Artifacts:  filepath.Join(root, "artifacts"),
		Provenance: filepath.Join(root, "provenance"),
		Secrets:    filepath.Join(root, "secrets"),
		Logs:       filepath.Join(root, "logs"),
		Spool:      filepath.Join(root, "spool"),
	}
}

func Init(root string) (Paths, error) {
	paths := ResolvePaths(root)
	for _, dir := range []string{paths.Root, paths.Workspaces, paths.Snapshots, paths.Templates, paths.Artifacts, paths.Provenance, paths.Secrets, paths.Logs, paths.Spool} {
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
	// Pragmas are set in the DSN so they apply to EVERY pooled connection.
	// Setting them via a single db.Exec only configures whichever connection
	// served that statement; other connections the pool opens lazily would have
	// no busy_timeout and hit immediate "database is locked" (SQLITE_BUSY) under
	// concurrent writers - exactly the daemon's sampler-vs-handler case.
	//
	// We do NOT cap the pool to one connection (SetMaxOpenConns(1)): the
	// codebase has read loops that issue a nested DB call inside an open rows
	// cursor (directly in provenance/verify.go, indirectly via helpers like
	// attemptIsTainted), which would deadlock on a single shared connection.
	// WAL + a busy_timeout applied to all connections lets concurrent writers
	// serialize through the busy handler instead.
	dsn := "file:" + paths.DB + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
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
		`CREATE TABLE IF NOT EXISTS execution_context_bindings (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL DEFAULT '',
			session_id TEXT NOT NULL DEFAULT '',
			attempt_id TEXT NOT NULL DEFAULT '',
			tool_call_id TEXT NOT NULL DEFAULT '',
			process_id TEXT NOT NULL DEFAULT '',
			container_id TEXT NOT NULL DEFAULT '',
			cgroup_id TEXT NOT NULL DEFAULT '',
			root_pid INTEGER NOT NULL DEFAULT 0,
			pid INTEGER NOT NULL DEFAULT 0,
			started_at TEXT NOT NULL,
			ended_at TEXT NOT NULL DEFAULT '',
			binding_source TEXT NOT NULL DEFAULT 'control_plane',
			confidence REAL NOT NULL DEFAULT 1,
			created_at TEXT NOT NULL
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
			risk_status TEXT NOT NULL DEFAULT 'unknown',
			budget_exceeded INTEGER NOT NULL DEFAULT 0,
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
		// PRIMARY KEY is (run_id, id), NOT id alone: every run has its own "main"
		// orchestrator (and agent ids can repeat across runs), so a single-column
		// id PK would let one run's agent rows clobber another's -- breaking
		// multi-run stores, forensics import, and dashboard replay. Agent identity
		// is only ever resolved run-scoped (the lens/bridge always filter by
		// run_id), so the graph node id stays "agent/<id>".
		`CREATE TABLE IF NOT EXISTS agents (
			id TEXT NOT NULL,
			run_id TEXT NOT NULL DEFAULT '',
			name TEXT NOT NULL DEFAULT '',
			agent_type TEXT NOT NULL DEFAULT '',
			parent_agent_id TEXT NOT NULL DEFAULT '',
			binding_source TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			started_at TEXT NOT NULL DEFAULT '',
			ended_at TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (run_id, id)
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
			drain_started_at TEXT NOT NULL DEFAULT '',
			drain_completed_at TEXT NOT NULL DEFAULT '',
			drain_queued_before INTEGER NOT NULL DEFAULT 0,
			drain_processed INTEGER NOT NULL DEFAULT 0,
			drain_pending_after INTEGER NOT NULL DEFAULT 0,
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
		`CREATE TABLE IF NOT EXISTS external_effects (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL DEFAULT '',
			rollout_id TEXT NOT NULL DEFAULT '',
			attempt_id TEXT NOT NULL DEFAULT '',
			session_id TEXT NOT NULL DEFAULT '',
			tool_call_id TEXT NOT NULL DEFAULT '',
			process_id TEXT NOT NULL DEFAULT '',
			effect_type TEXT NOT NULL,
			target TEXT NOT NULL,
			mode TEXT NOT NULL,
			decision TEXT NOT NULL,
			compensation_ref TEXT NOT NULL DEFAULT '',
			payload TEXT NOT NULL DEFAULT '{}',
			status TEXT NOT NULL DEFAULT 'recorded',
			created_at TEXT NOT NULL
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
			raw_event_id TEXT NOT NULL DEFAULT '',
			correlation_method TEXT NOT NULL DEFAULT '',
			correlation_confidence REAL NOT NULL DEFAULT 0,
			container_id TEXT NOT NULL DEFAULT '',
			cgroup_id TEXT NOT NULL DEFAULT '',
			pid INTEGER NOT NULL DEFAULT 0,
			tgid INTEGER NOT NULL DEFAULT 0,
			ppid INTEGER NOT NULL DEFAULT 0,
			binding_source TEXT NOT NULL DEFAULT '',
			source TEXT NOT NULL,
			event_type TEXT NOT NULL,
			payload TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS telemetry_batches (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL DEFAULT '',
			format TEXT NOT NULL,
			path TEXT NOT NULL,
			file_sha256 TEXT NOT NULL,
			read_count INTEGER NOT NULL DEFAULT 0,
			ingested_count INTEGER NOT NULL DEFAULT 0,
			skipped_count INTEGER NOT NULL DEFAULT 0,
			failed_count INTEGER NOT NULL DEFAULT 0,
			event_ids_json TEXT NOT NULL DEFAULT '[]',
			event_ids_sha256 TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS telemetry_spool_batches (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL DEFAULT '',
			format TEXT NOT NULL,
			source_path TEXT NOT NULL DEFAULT '',
			spool_path TEXT NOT NULL,
			file_sha256 TEXT NOT NULL DEFAULT '',
			size_bytes INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL,
			priority INTEGER NOT NULL DEFAULT 0,
			attempts INTEGER NOT NULL DEFAULT 0,
			policy_enabled INTEGER NOT NULL DEFAULT 1,
			ingest_batch_id TEXT NOT NULL DEFAULT '',
			ingested_count INTEGER NOT NULL DEFAULT 0,
			failed_count INTEGER NOT NULL DEFAULT 0,
			error TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			processed_at TEXT NOT NULL DEFAULT '',
			dropped_at TEXT NOT NULL DEFAULT '',
			drop_reason TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE TABLE IF NOT EXISTS telemetry_event_windows (
			run_id TEXT NOT NULL DEFAULT '',
			session_id TEXT NOT NULL DEFAULT '',
			tool_call_id TEXT NOT NULL DEFAULT '',
			source TEXT NOT NULL DEFAULT '',
			event_type TEXT NOT NULL DEFAULT '',
			window_seconds INTEGER NOT NULL,
			window_start TEXT NOT NULL,
			event_count INTEGER NOT NULL DEFAULT 0,
			resolved_count INTEGER NOT NULL DEFAULT 0,
			unresolved_count INTEGER NOT NULL DEFAULT 0,
			high_risk_count INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL,
			PRIMARY KEY(run_id, session_id, tool_call_id, source, event_type, window_seconds, window_start)
		);`,
		`CREATE TABLE IF NOT EXISTS record_batches (
			id TEXT PRIMARY KEY,
			input_sha256 TEXT NOT NULL DEFAULT '',
			started_at TEXT NOT NULL,
			ended_at TEXT NOT NULL,
			job_count INTEGER NOT NULL DEFAULT 0,
			passed INTEGER NOT NULL DEFAULT 0,
			failed INTEGER NOT NULL DEFAULT 0,
			skipped INTEGER NOT NULL DEFAULT 0,
			status_counts_json TEXT NOT NULL DEFAULT '{}',
			run_ids_json TEXT NOT NULL DEFAULT '[]',
			shards_json TEXT NOT NULL DEFAULT '{}',
			result_set_id TEXT NOT NULL DEFAULT '',
			page_hash TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS record_batch_items (
			batch_id TEXT NOT NULL,
			idx INTEGER NOT NULL,
			job_id TEXT NOT NULL DEFAULT '',
			shard_id TEXT NOT NULL DEFAULT '',
			run_id TEXT NOT NULL DEFAULT '',
			attempt_id TEXT NOT NULL DEFAULT '',
			tool_call_id TEXT NOT NULL DEFAULT '',
			process_id TEXT NOT NULL DEFAULT '',
			workdir TEXT NOT NULL DEFAULT '',
			command TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT '',
			exit_code INTEGER NOT NULL DEFAULT 0,
			wall_ms INTEGER NOT NULL DEFAULT 0,
			changed_file_count INTEGER NOT NULL DEFAULT 0,
			changed_files_json TEXT NOT NULL DEFAULT '[]',
			error TEXT NOT NULL DEFAULT '',
			evidence_manifest_command TEXT NOT NULL DEFAULT '',
			eval_context_command TEXT NOT NULL DEFAULT '',
			explain_command TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			PRIMARY KEY(batch_id, idx)
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
		`CREATE TABLE IF NOT EXISTS risk_signals (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL DEFAULT '',
			session_id TEXT NOT NULL DEFAULT '',
			tool_call_id TEXT NOT NULL DEFAULT '',
			process_id TEXT NOT NULL DEFAULT '',
			snapshot_id TEXT NOT NULL DEFAULT '',
			event_id TEXT NOT NULL DEFAULT '',
			policy_decision_id TEXT NOT NULL DEFAULT '',
			signal_type TEXT NOT NULL,
			severity TEXT NOT NULL,
			reason TEXT NOT NULL,
			recommended_action TEXT NOT NULL DEFAULT 'audit',
			payload TEXT NOT NULL DEFAULT '{}',
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS baseline_deviations (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL DEFAULT '',
			template_name TEXT NOT NULL DEFAULT '',
			profile_id TEXT NOT NULL DEFAULT '',
			deviation_type TEXT NOT NULL,
			status TEXT NOT NULL,
			expected_value REAL NOT NULL DEFAULT 0,
			observed_value REAL NOT NULL DEFAULT 0,
			recommended_action TEXT NOT NULL DEFAULT 'audit',
			payload TEXT NOT NULL DEFAULT '{}',
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS response_actions (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL DEFAULT '',
			session_id TEXT NOT NULL DEFAULT '',
			process_id TEXT NOT NULL DEFAULT '',
			snapshot_id TEXT NOT NULL DEFAULT '',
			risk_signal_id TEXT NOT NULL DEFAULT '',
			policy_decision_id TEXT NOT NULL DEFAULT '',
			action_type TEXT NOT NULL,
			target_type TEXT NOT NULL DEFAULT '',
			target_id TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			result_ref TEXT NOT NULL DEFAULT '',
			payload TEXT NOT NULL DEFAULT '{}',
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
			payload TEXT NOT NULL DEFAULT '{}',
			status TEXT NOT NULL,
			created_at TEXT NOT NULL
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
		`CREATE TABLE IF NOT EXISTS provenance_objects (
			hash TEXT PRIMARY KEY,
			object_type TEXT NOT NULL,
			source_id TEXT NOT NULL,
			run_id TEXT NOT NULL DEFAULT '',
			rollout_id TEXT NOT NULL DEFAULT '',
			parent_hashes TEXT NOT NULL DEFAULT '',
			path TEXT NOT NULL,
			size_bytes INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		);`,
		// Unified graph-attached signal model (the infra contract).
		// Every observability dimension - behavior, quality, security, and the
		// cross-cutting cost dimension - lands here as one row type keyed to the
		// same causality graph, instead of the per-dimension silos
		// (risk_signals / baseline_deviations / cost_samples / Python EvalSignal).
		`CREATE TABLE IF NOT EXISTS signals (
			id TEXT PRIMARY KEY,
			dimension TEXT NOT NULL,                  -- behavior | cost | quality | security
			signal_type TEXT NOT NULL,               -- cpu_spike | reward_feature | ssrf_attempt | policy_violation ...
			graph_ref_kind TEXT NOT NULL DEFAULT '', -- run | session | tool_call | process | event | object | edge
			graph_ref_id TEXT NOT NULL DEFAULT '',
			run_id TEXT NOT NULL DEFAULT '',
			session_id TEXT NOT NULL DEFAULT '',
			tool_call_id TEXT NOT NULL DEFAULT '',
			process_id TEXT NOT NULL DEFAULT '',
			event_id TEXT NOT NULL DEFAULT '',
			object_ref TEXT NOT NULL DEFAULT '',
			severity TEXT NOT NULL DEFAULT '',        -- security/risk only: info|low|medium|high|critical
			label TEXT NOT NULL DEFAULT '',           -- categorical tag (e.g. quality pass|candidate|reject)
			value REAL NOT NULL DEFAULT 0,            -- numeric measure (cost / quality)
			reference TEXT NOT NULL DEFAULT '',       -- norm / baseline / budget that produced it
			confidence REAL NOT NULL DEFAULT 1,
			recommended_action TEXT NOT NULL DEFAULT '',
			produced_by TEXT NOT NULL DEFAULT '',     -- security.policy | baseline | cost | evaluator:<name>
			evidence_refs TEXT NOT NULL DEFAULT '[]', -- JSON array of content-addressed object refs
			payload TEXT NOT NULL DEFAULT '{}',
			source_table TEXT NOT NULL DEFAULT '',    -- legacy silo this row was projected from (provenance)
			source_id TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_signals_run ON signals(run_id);`,
		`CREATE INDEX IF NOT EXISTS idx_signals_dimension ON signals(dimension);`,
		`CREATE INDEX IF NOT EXISTS idx_signals_graph_ref ON signals(graph_ref_kind, graph_ref_id);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_signals_source ON signals(source_table, source_id) WHERE source_table != '';`,
		// intent_diffs is the Intent-Runtime Diff evidence: for each captured
		// contract (a tool call / peer message / refusal, each declaring the
		// effects it should and must-not produce) versus the runtime effects
		// actually attributed to its scope, one typed diff row. It makes mismatch a
		// first-class node the graph, verdict, and a lens can read. Expected /
		// forbidden / observed effect sets are serialized inline (v1) rather than
		// split into separate contract/effect tables -- minimal schema churn while
		// keeping the divergence first-class.
		`CREATE TABLE IF NOT EXISTS intent_diffs (
			id TEXT PRIMARY KEY,
			run_id TEXT NOT NULL DEFAULT '',
			agent_id TEXT NOT NULL DEFAULT '',
			tool_call_id TEXT NOT NULL DEFAULT '',
			contract_kind TEXT NOT NULL DEFAULT '',      -- tool_call | peer_message | refusal
			operation TEXT NOT NULL DEFAULT '',          -- exec | install | file_read | file_write | ...
			target TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,                        -- declared_vs_effect_mismatch | refused_but_runtime_happened | decided_and_executed | intent_coverage_gap
			finding TEXT NOT NULL DEFAULT '',            -- refined label, e.g. peer_message_intent_mismatch
			confidence REAL NOT NULL DEFAULT 0,
			declared_effects TEXT NOT NULL DEFAULT '[]',
			forbidden_effects TEXT NOT NULL DEFAULT '[]',
			observed_effects TEXT NOT NULL DEFAULT '[]',
			mismatch_reason TEXT NOT NULL DEFAULT '',
			source TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_intent_diffs_run ON intent_diffs(run_id);`,
		`CREATE INDEX IF NOT EXISTS idx_intent_diffs_run_status ON intent_diffs(run_id, status);`,
		`CREATE INDEX IF NOT EXISTS idx_events_run_time_id ON events(run_id, created_at, id);`,
		`CREATE INDEX IF NOT EXISTS idx_events_run_type_time ON events(run_id, event_type, created_at);`,
		`CREATE INDEX IF NOT EXISTS idx_events_run_tool_time ON events(run_id, tool_call_id, created_at);`,
		`CREATE INDEX IF NOT EXISTS idx_events_run_process_time ON events(run_id, process_id, created_at);`,
		`CREATE INDEX IF NOT EXISTS idx_events_run_pid_time ON events(run_id, pid, created_at);`,
		`CREATE INDEX IF NOT EXISTS idx_graph_edges_run_from ON graph_edges(run_id, from_id);`,
		`CREATE INDEX IF NOT EXISTS idx_graph_edges_run_to ON graph_edges(run_id, to_id);`,
		`CREATE INDEX IF NOT EXISTS idx_graph_edges_run_type ON graph_edges(run_id, edge_type);`,
		// The lens loads a run's edges ordered by (created_at, id); this covering
		// index lets a large run skip sorting tens of thousands of rows.
		`CREATE INDEX IF NOT EXISTS idx_graph_edges_run_time ON graph_edges(run_id, created_at, id);`,
		`CREATE INDEX IF NOT EXISTS idx_risk_signals_run_event ON risk_signals(run_id, event_id);`,
		`CREATE INDEX IF NOT EXISTS idx_risk_signals_run_tool ON risk_signals(run_id, tool_call_id);`,
		`CREATE INDEX IF NOT EXISTS idx_risk_signals_run_process ON risk_signals(run_id, process_id);`,
		`CREATE INDEX IF NOT EXISTS idx_policy_decisions_run_event ON policy_decisions(run_id, event_id);`,
		`CREATE INDEX IF NOT EXISTS idx_response_actions_run_risk ON response_actions(run_id, risk_signal_id);`,
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
		`ALTER TABLE events ADD COLUMN raw_event_id TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE events ADD COLUMN correlation_method TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE events ADD COLUMN correlation_confidence REAL NOT NULL DEFAULT 0;`,
		`ALTER TABLE events ADD COLUMN container_id TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE events ADD COLUMN cgroup_id TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE events ADD COLUMN pid INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE events ADD COLUMN tgid INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE events ADD COLUMN ppid INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE events ADD COLUMN binding_source TEXT NOT NULL DEFAULT '';`,
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
		`ALTER TABLE promotions ADD COLUMN drain_started_at TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE promotions ADD COLUMN drain_completed_at TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE promotions ADD COLUMN drain_queued_before INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE promotions ADD COLUMN drain_processed INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE promotions ADD COLUMN drain_pending_after INTEGER NOT NULL DEFAULT 0;`,
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
		`ALTER TABLE fork_attempts ADD COLUMN risk_status TEXT NOT NULL DEFAULT 'unknown';`,
		`ALTER TABLE fork_attempts ADD COLUMN budget_exceeded INTEGER NOT NULL DEFAULT 0;`,
		`ALTER TABLE baseline_profiles ADD COLUMN payload TEXT NOT NULL DEFAULT '{}';`,
		`ALTER TABLE telemetry_spool_batches ADD COLUMN dropped_at TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE telemetry_spool_batches ADD COLUMN drop_reason TEXT NOT NULL DEFAULT '';`,
		// Multi-agent orchestration: which agent/sub-agent ran a tool call (from
		// the harness hooks bridge). Empty for main-thread / non-agent calls.
		`ALTER TABLE tool_calls ADD COLUMN agent_id TEXT NOT NULL DEFAULT '';`,
		// Indexes for the agent tables/columns added above (run after the ALTER so
		// the agent_id column exists; IF NOT EXISTS keeps them idempotent).
		`CREATE INDEX IF NOT EXISTS idx_agents_run ON agents(run_id);`,
		`CREATE INDEX IF NOT EXISTS idx_tool_calls_run_agent ON tool_calls(run_id, agent_id);`,
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
		VALUES (?, 'agent provenance, telemetry correlation, security evidence, and resource window schema', datetime('now'))`, SchemaVersion); err != nil {
		return fmt.Errorf("record schema version: %w", err)
	}
	return nil
}

func isDuplicateColumn(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate column name")
}
