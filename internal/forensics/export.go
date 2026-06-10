package forensics

import (
	"crypto/sha256"
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

type BundleInfo struct {
	ID        string
	RunID     string
	Path      string
	SHA256    string
	SizeBytes int64
	Status    string
	CreatedAt string
}

func (s Service) Export(runID string) (string, error) {
	info, err := s.ExportBundle(runID)
	if err != nil {
		return "", err
	}
	return info.Path, nil
}

func (s Service) ExportBundle(runID string) (BundleInfo, error) {
	if runID == "" {
		return BundleInfo{}, fmt.Errorf("run_id is required")
	}
	events, err := telemetry.ListEvents(s.DB, runID, "")
	if err != nil {
		return BundleInfo{}, err
	}
	decisions, err := security.ListDecisions(s.DB, runID)
	if err != nil {
		return BundleInfo{}, err
	}
	sessions, err := selectRows(s.DB, `SELECT id, lease_id, status, run_id, COALESCE(container_id, '') AS container_id, workspace_host_path, startup_cold_ms, created_at, updated_at
		FROM sessions WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return BundleInfo{}, err
	}
	processes, err := selectRows(s.DB, `SELECT id, session_id, COALESCE(container_id, '') AS container_id, COALESCE(exec_id, '') AS exec_id, command, status, COALESCE(exit_code, 0) AS exit_code, started_at, COALESCE(ended_at, '') AS ended_at
		FROM processes WHERE session_id IN (SELECT id FROM sessions WHERE run_id = ?) ORDER BY started_at ASC`, runID)
	if err != nil {
		return BundleInfo{}, err
	}
	snapshots, err := selectRows(s.DB, `SELECT id, COALESCE(name, '') AS name, COALESCE(session_id, '') AS session_id, COALESCE(parent_id, '') AS parent_id, kind, source, path, manifest_hash, file_count, bytes, snapshot_create_ms, status, created_at
		FROM snapshots WHERE session_id IN (SELECT id FROM sessions WHERE run_id = ?) ORDER BY created_at ASC`, runID)
	if err != nil {
		return BundleInfo{}, err
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
		return BundleInfo{}, err
	}
	bundleID := ids.New("forensics")
	path := filepath.Join(s.Paths.Artifacts, bundleID+".json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return BundleInfo{}, err
	}
	sum := sha256.Sum256(raw)
	hash := fmt.Sprintf("%x", sum[:])
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`INSERT INTO forensics_bundles (id, run_id, path, sha256, size_bytes, status, created_at)
		VALUES (?, ?, ?, ?, ?, 'ready', ?)`, bundleID, runID, path, hash, len(raw), now)
	if err != nil {
		return BundleInfo{}, err
	}
	return BundleInfo{ID: bundleID, RunID: runID, Path: path, SHA256: hash, SizeBytes: int64(len(raw)), Status: "ready", CreatedAt: now}, nil
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
