package forensics

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/ids"
	"github.com/byteyellow/agent-computer-fleet/internal/security"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/byteyellow/agent-computer-fleet/internal/telemetry"
)

type Service struct {
	DB    *sql.DB
	Paths store.Paths
}

func (s Service) Export(runID string) (string, error) {
	if runID == "" {
		return "", fmt.Errorf("run_id is required")
	}
	events, err := telemetry.ListEvents(s.DB, runID, "")
	if err != nil {
		return "", err
	}
	decisions, err := security.ListDecisions(s.DB, runID)
	if err != nil {
		return "", err
	}
	sessions, err := selectRows(s.DB, `SELECT id, lease_id, status, run_id, COALESCE(container_id, '') AS container_id, workspace_host_path, startup_cold_ms, created_at, updated_at
		FROM sessions WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return "", err
	}
	processes, err := selectRows(s.DB, `SELECT id, session_id, COALESCE(container_id, '') AS container_id, COALESCE(exec_id, '') AS exec_id, command, status, COALESCE(exit_code, 0) AS exit_code, started_at, COALESCE(ended_at, '') AS ended_at
		FROM processes WHERE session_id IN (SELECT id FROM sessions WHERE run_id = ?) ORDER BY started_at ASC`, runID)
	if err != nil {
		return "", err
	}
	snapshots, err := selectRows(s.DB, `SELECT id, COALESCE(name, '') AS name, COALESCE(session_id, '') AS session_id, COALESCE(parent_id, '') AS parent_id, kind, source, path, manifest_hash, file_count, bytes, snapshot_create_ms, status, created_at
		FROM snapshots WHERE session_id IN (SELECT id FROM sessions WHERE run_id = ?) ORDER BY created_at ASC`, runID)
	if err != nil {
		return "", err
	}

	bundle := map[string]any{
		"run_id":           runID,
		"exported_at":      time.Now().UTC().Format(time.RFC3339Nano),
		"sessions":         sessions,
		"processes":        processes,
		"snapshots":        snapshots,
		"events":           events,
		"policy_decisions": decisions,
	}
	raw, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return "", err
	}
	bundleID := ids.New("forensics")
	path := filepath.Join(s.Paths.Artifacts, bundleID+".json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return "", err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`INSERT INTO forensics_bundles (id, run_id, path, status, created_at)
		VALUES (?, ?, ?, 'ready', ?)`, bundleID, runID, path, now)
	if err != nil {
		return "", err
	}
	return path, nil
}

func selectRows(db *sql.DB, query string, args ...any) ([]map[string]any, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	result := []map[string]any{}
	for rows.Next() {
		values := make([]any, len(columns))
		valuePtrs := make([]any, len(columns))
		for i := range columns {
			valuePtrs[i] = &values[i]
		}
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}
		item := map[string]any{}
		for i, column := range columns {
			switch v := values[i].(type) {
			case []byte:
				item[column] = string(v)
			default:
				item[column] = v
			}
		}
		result = append(result, item)
	}
	return result, rows.Err()
}
