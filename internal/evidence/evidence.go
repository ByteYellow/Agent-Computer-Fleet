package evidence

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/ids"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
)

type Service struct {
	DB    *sql.DB
	Paths store.Paths
}

type ProcessResult struct {
	Processed int
}

type GCResult struct {
	Processed       int
	ReclaimedBytes  int64
	ReclaimedInodes int64
	Failed          int
}

func (s Service) ProcessEvidence(limit int) (ProcessResult, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.DB.Query(`SELECT id, run_id, rollout_id, attempt_id, session_id, tool_call_id, snapshot_id, event_type, created_at
		FROM evidence_events WHERE status = 'queued' ORDER BY created_at LIMIT ?`, limit)
	if err != nil {
		return ProcessResult{}, err
	}
	defer rows.Close()
	type event struct {
		id, runID, rolloutID, attemptID, sessionID, toolCallID, snapshotID, eventType, createdAt string
	}
	var events []event
	for rows.Next() {
		var ev event
		if err := rows.Scan(&ev.id, &ev.runID, &ev.rolloutID, &ev.attemptID, &ev.sessionID, &ev.toolCallID, &ev.snapshotID, &ev.eventType, &ev.createdAt); err != nil {
			return ProcessResult{}, err
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return ProcessResult{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, ev := range events {
		if ev.rolloutID != "" && ev.attemptID != "" {
			_, _ = s.DB.Exec(`INSERT INTO graph_edges (id, run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				ids.New("edge"), ev.runID, ev.rolloutID, ev.rolloutID, ev.attemptID, "rollout_attempt", ev.id, now)
		}
		if ev.snapshotID != "" && ev.attemptID != "" {
			_, _ = s.DB.Exec(`INSERT INTO graph_edges (id, run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				ids.New("edge"), ev.runID, ev.rolloutID, ev.snapshotID, ev.attemptID, "snapshot_attempt", ev.id, now)
		}
		if ev.attemptID != "" && ev.toolCallID != "" {
			_, _ = s.DB.Exec(`INSERT INTO graph_edges (id, run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				ids.New("edge"), ev.runID, ev.rolloutID, ev.attemptID, ev.toolCallID, "attempt_tool_call", ev.id, now)
		}
		if ev.attemptID != "" && ev.sessionID != "" {
			_, _ = s.DB.Exec(`INSERT INTO graph_edges (id, run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				ids.New("edge"), ev.runID, ev.rolloutID, ev.attemptID, ev.sessionID, "attempt_session", ev.id, now)
		}
		if ev.toolCallID != "" && ev.sessionID != "" {
			_, _ = s.DB.Exec(`INSERT INTO graph_edges (id, run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				ids.New("edge"), ev.runID, ev.rolloutID, ev.toolCallID, ev.sessionID, "tool_call_session", ev.id, now)
		}
		if _, err := s.DB.Exec(`UPDATE evidence_events SET status = 'processed', processed_at = ? WHERE id = ?`, now, ev.id); err != nil {
			return ProcessResult{Processed: len(events)}, err
		}
	}
	return ProcessResult{Processed: len(events)}, nil
}

func (s Service) RunGC(limit int) (GCResult, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.DB.Query(`SELECT id, workspace_path FROM gc_jobs WHERE status = 'queued' ORDER BY created_at LIMIT ?`, limit)
	if err != nil {
		return GCResult{}, err
	}
	defer rows.Close()
	type job struct{ id, workspacePath string }
	var jobs []job
	for rows.Next() {
		var item job
		if err := rows.Scan(&item.id, &item.workspacePath); err != nil {
			return GCResult{}, err
		}
		jobs = append(jobs, item)
	}
	if err := rows.Err(); err != nil {
		return GCResult{}, err
	}
	var result GCResult
	for _, item := range jobs {
		start := time.Now()
		bytes, inodes, statErr := dirUsage(item.workspacePath)
		removeErr := os.RemoveAll(item.workspacePath)
		latency := time.Since(start).Milliseconds()
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if statErr != nil || removeErr != nil {
			result.Failed++
			reason := ""
			if statErr != nil {
				reason = statErr.Error()
			}
			if removeErr != nil {
				if reason != "" {
					reason += "; "
				}
				reason += removeErr.Error()
			}
			_, _ = s.DB.Exec(`UPDATE gc_jobs SET status = 'failed', reclaimed_bytes = ?, reclaimed_inodes = ?, gc_latency_ms = ?, failure_reason = ?, updated_at = ? WHERE id = ?`,
				bytes, inodes, latency, reason, now, item.id)
			continue
		}
		result.Processed++
		result.ReclaimedBytes += bytes
		result.ReclaimedInodes += inodes
		_, _ = s.DB.Exec(`UPDATE gc_jobs SET status = 'completed', reclaimed_bytes = ?, reclaimed_inodes = ?, gc_latency_ms = ?, updated_at = ? WHERE id = ?`,
			bytes, inodes, latency, now, item.id)
	}
	return result, nil
}

func dirUsage(root string) (int64, int64, error) {
	var bytes int64
	var inodes int64
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		inodes++
		if entry.Type().IsRegular() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			bytes += info.Size()
		}
		return nil
	})
	if os.IsNotExist(err) {
		return 0, 0, nil
	}
	if err != nil {
		return bytes, inodes, fmt.Errorf("measure workspace %s: %w", root, err)
	}
	return bytes, inodes, nil
}
