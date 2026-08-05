package telemetry

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/store"
)

type SpoolService struct {
	DB    *sql.DB
	Paths store.Paths
}

type SpoolEnqueueRequest struct {
	Format         string
	RunID          string
	SourcePath     string
	PolicyEnabled  bool
	MaxQueued      int
	MaxQueuedBytes int64
	MaxBatchBytes  int64
	DropPolicy     string
}

type SpoolBatch struct {
	ID            string `json:"id"`
	RunID         string `json:"run_id"`
	Format        string `json:"format"`
	SourcePath    string `json:"source_path"`
	SpoolPath     string `json:"spool_path"`
	FileSHA256    string `json:"file_sha256"`
	SizeBytes     int64  `json:"size_bytes"`
	Status        string `json:"status"`
	Priority      int    `json:"priority"`
	Attempts      int    `json:"attempts"`
	PolicyEnabled bool   `json:"policy_enabled"`
	IngestBatchID string `json:"ingest_batch_id"`
	IngestedCount int    `json:"ingested_count"`
	FailedCount   int    `json:"failed_count"`
	Error         string `json:"error"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
	ProcessedAt   string `json:"processed_at"`
	DroppedAt     string `json:"dropped_at"`
	DropReason    string `json:"drop_reason"`
}

type SpoolProcessResult struct {
	Processed int                   `json:"processed"`
	Failed    int                   `json:"failed"`
	Batches   []SpoolProcessedBatch `json:"batches,omitempty"`
	Errors    []string              `json:"errors,omitempty"`
}

type SpoolProcessedBatch struct {
	ID                  string `json:"id"`
	IngestBatchID       string `json:"ingest_batch_id"`
	IngestedCount       int    `json:"ingested_count"`
	FailedCount         int    `json:"failed_count"`
	RowResultsTruncated bool   `json:"row_results_truncated,omitempty"`
}

type SpoolBackpressureError struct {
	Queued         int    `json:"queued"`
	QueuedBytes    int64  `json:"queued_bytes"`
	IncomingBytes  int64  `json:"incoming_bytes"`
	MaxQueued      int    `json:"max_queued"`
	MaxQueuedBytes int64  `json:"max_queued_bytes"`
	MaxBatchBytes  int64  `json:"max_batch_bytes"`
	Reason         string `json:"reason"`
}

func (e SpoolBackpressureError) Error() string {
	return fmt.Sprintf("telemetry spool backpressure: queued=%d queued_bytes=%d incoming_bytes=%d max_queued=%d max_queued_bytes=%d max_batch_bytes=%d reason=%s",
		e.Queued, e.QueuedBytes, e.IncomingBytes, e.MaxQueued, e.MaxQueuedBytes, e.MaxBatchBytes, e.Reason)
}

type SpoolQueueStats struct {
	QueuedBatches int   `json:"queued_batches"`
	QueuedBytes   int64 `json:"queued_bytes"`
}

func (s SpoolService) Enqueue(req SpoolEnqueueRequest) (SpoolBatch, error) {
	if s.DB == nil {
		return SpoolBatch{}, fmt.Errorf("database is required")
	}
	if req.Format == "" {
		req.Format = "falco"
	}
	if req.Format != "falco" {
		return SpoolBatch{}, fmt.Errorf("unsupported spool format %q", req.Format)
	}
	if req.SourcePath == "" {
		return SpoolBatch{}, fmt.Errorf("source_path is required")
	}
	source, err := os.Open(req.SourcePath)
	if err != nil {
		return SpoolBatch{}, err
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return SpoolBatch{}, err
	}
	if !info.Mode().IsRegular() {
		return SpoolBatch{}, fmt.Errorf("source_path must be a regular file")
	}
	if err := s.applyBackpressure(req.MaxQueued, req.MaxQueuedBytes, req.MaxBatchBytes, info.Size(), req.DropPolicy); err != nil {
		return SpoolBatch{}, err
	}
	if err := os.MkdirAll(s.Paths.Spool, 0o755); err != nil {
		return SpoolBatch{}, err
	}
	id := ids.New("spool")
	spoolPath := filepath.Join(s.Paths.Spool, id+".jsonl")
	target, err := os.OpenFile(spoolPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return SpoolBatch{}, err
	}
	hasher := sha256.New()
	var reader io.Reader = source
	copyLimit := positiveByteLimit(req.MaxBatchBytes, req.MaxQueuedBytes)
	if copyLimit > 0 {
		reader = io.LimitReader(source, copyLimit+1)
	}
	written, copyErr := io.Copy(io.MultiWriter(target, hasher), reader)
	closeErr := target.Close()
	if copyErr != nil {
		_ = os.Remove(spoolPath)
		return SpoolBatch{}, copyErr
	}
	if closeErr != nil {
		_ = os.Remove(spoolPath)
		return SpoolBatch{}, closeErr
	}
	if written != info.Size() {
		if err := s.applyBackpressure(req.MaxQueued, req.MaxQueuedBytes, req.MaxBatchBytes, written, req.DropPolicy); err != nil {
			_ = os.Remove(spoolPath)
			return SpoolBatch{}, err
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	policyEnabled := 0
	if req.PolicyEnabled {
		policyEnabled = 1
	}
	hash := hex.EncodeToString(hasher.Sum(nil))
	_, err = s.DB.Exec(`INSERT INTO telemetry_spool_batches
		(id, run_id, format, source_path, spool_path, file_sha256, size_bytes, status, policy_enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?)`,
		id, req.RunID, req.Format, req.SourcePath, spoolPath, hash, written, policyEnabled, now, now)
	if err != nil {
		_ = os.Remove(spoolPath)
		return SpoolBatch{}, err
	}
	return SpoolBatch{
		ID:            id,
		RunID:         req.RunID,
		Format:        req.Format,
		SourcePath:    req.SourcePath,
		SpoolPath:     spoolPath,
		FileSHA256:    hash,
		SizeBytes:     written,
		Status:        "queued",
		PolicyEnabled: req.PolicyEnabled,
		CreatedAt:     now,
		UpdatedAt:     now,
	}, nil
}

func positiveByteLimit(values ...int64) int64 {
	var limit int64
	for _, value := range values {
		if value > 0 && (limit == 0 || value < limit) {
			limit = value
		}
	}
	return limit
}

func (s SpoolService) CountQueued() (int, error) {
	stats, err := s.QueueStats()
	return stats.QueuedBatches, err
}

func (s SpoolService) QueueStats() (SpoolQueueStats, error) {
	var stats SpoolQueueStats
	err := s.DB.QueryRow(`SELECT COALESCE(COUNT(*), 0), COALESCE(SUM(size_bytes), 0)
		FROM telemetry_spool_batches WHERE status IN ('queued', 'processing')`).Scan(&stats.QueuedBatches, &stats.QueuedBytes)
	return stats, err
}

func (s SpoolService) applyBackpressure(maxQueued int, maxQueuedBytes, maxBatchBytes, incomingBytes int64, dropPolicy string) error {
	if maxBatchBytes > 0 && incomingBytes > maxBatchBytes {
		return SpoolBackpressureError{IncomingBytes: incomingBytes, MaxQueued: maxQueued, MaxQueuedBytes: maxQueuedBytes, MaxBatchBytes: maxBatchBytes, Reason: "telemetry_spool_batch_too_large"}
	}
	if maxQueued <= 0 && maxQueuedBytes <= 0 {
		return nil
	}
	stats, err := s.QueueStats()
	if err != nil {
		return err
	}
	withinCount := maxQueued <= 0 || stats.QueuedBatches < maxQueued
	withinBytes := maxQueuedBytes <= 0 || stats.QueuedBytes+incomingBytes <= maxQueuedBytes
	if withinCount && withinBytes {
		return nil
	}
	if dropPolicy == "" {
		dropPolicy = "reject"
	}
	switch dropPolicy {
	case "reject":
		reason := "telemetry_spool_queue_full"
		if !withinBytes {
			reason = "telemetry_spool_bytes_full"
		}
		return SpoolBackpressureError{Queued: stats.QueuedBatches, QueuedBytes: stats.QueuedBytes, IncomingBytes: incomingBytes, MaxQueued: maxQueued, MaxQueuedBytes: maxQueuedBytes, MaxBatchBytes: maxBatchBytes, Reason: reason}
	case "drop_oldest":
		for !(withinCount && withinBytes) {
			dropped, err := s.dropOldestQueued("queue_limit")
			if err != nil {
				return err
			}
			if !dropped {
				return SpoolBackpressureError{Queued: stats.QueuedBatches, QueuedBytes: stats.QueuedBytes, IncomingBytes: incomingBytes, MaxQueued: maxQueued, MaxQueuedBytes: maxQueuedBytes, MaxBatchBytes: maxBatchBytes, Reason: "telemetry_spool_capacity_unavailable"}
			}
			stats, err = s.QueueStats()
			if err != nil {
				return err
			}
			withinCount = maxQueued <= 0 || stats.QueuedBatches < maxQueued
			withinBytes = maxQueuedBytes <= 0 || stats.QueuedBytes+incomingBytes <= maxQueuedBytes
		}
		return nil
	default:
		return fmt.Errorf("unsupported telemetry spool drop_policy %q", dropPolicy)
	}
}

func (s SpoolService) dropOldestQueued(reason string) (bool, error) {
	var id, spoolPath string
	err := s.DB.QueryRow(`SELECT id, spool_path FROM telemetry_spool_batches
		WHERE status = 'queued' ORDER BY priority ASC, created_at ASC LIMIT 1`).Scan(&id, &spoolPath)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`UPDATE telemetry_spool_batches
		SET status = 'dropped', drop_reason = ?, dropped_at = ?, updated_at = ?
		WHERE id = ? AND status = 'queued'`, reason, now, now, id); err != nil {
		return false, err
	}
	if spoolPath != "" {
		_ = os.Remove(spoolPath)
	}
	return true, nil
}

func (s SpoolService) Process(limit int) (SpoolProcessResult, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.DB.Query(`SELECT id, run_id, format, spool_path, policy_enabled FROM telemetry_spool_batches
		WHERE status = 'queued' ORDER BY priority DESC, created_at ASC LIMIT ?`, limit)
	if err != nil {
		return SpoolProcessResult{}, err
	}
	defer rows.Close()
	type item struct {
		id, runID, format, spoolPath string
		policyEnabled                int
	}
	var items []item
	for rows.Next() {
		var item item
		if err := rows.Scan(&item.id, &item.runID, &item.format, &item.spoolPath, &item.policyEnabled); err != nil {
			return SpoolProcessResult{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return SpoolProcessResult{}, err
	}
	var result SpoolProcessResult
	for _, item := range items {
		ingest, err := s.processOne(item.id, item.runID, item.format, item.spoolPath, item.policyEnabled != 0)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", item.id, err))
			continue
		}
		result.Processed++
		result.Batches = append(result.Batches, SpoolProcessedBatch{
			ID:                  item.id,
			IngestBatchID:       ingest.BatchID,
			IngestedCount:       ingest.Ingested,
			FailedCount:         ingest.Failed,
			RowResultsTruncated: ingest.RowsTruncated,
		})
	}
	return result, nil
}

func (s SpoolService) processOne(id, runID, format, spoolPath string, policyEnabled bool) (JSONLIngestResult, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`UPDATE telemetry_spool_batches SET status = 'processing', attempts = attempts + 1, updated_at = ? WHERE id = ? AND status = 'queued'`, now, id); err != nil {
		return JSONLIngestResult{}, err
	}
	file, err := os.Open(spoolPath)
	if err != nil {
		_ = s.failSpool(id, err)
		return JSONLIngestResult{}, err
	}
	defer file.Close()
	var ingest JSONLIngestResult
	switch format {
	case "falco":
		ingest, err = IngestFalco(s.DB, FalcoIngestOptions{Path: spoolPath, RunID: runID}, file)
	default:
		err = fmt.Errorf("unsupported spool format %q", format)
	}
	if err == nil && policyEnabled {
		evaluateSpoolPolicy(s.DB, &ingest)
	}
	if err != nil {
		_ = s.failSpool(id, err)
		return ingest, err
	}
	now = time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`UPDATE telemetry_spool_batches
		SET status = 'processed', ingest_batch_id = ?, ingested_count = ?, failed_count = ?, error = '', updated_at = ?, processed_at = ?
		WHERE id = ?`, ingest.BatchID, ingest.Ingested, ingest.Failed, now, now, id)
	return ingest, err
}

func (s SpoolService) failSpool(id string, cause error) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.DB.Exec(`UPDATE telemetry_spool_batches SET status = 'failed', failed_count = failed_count + 1, error = ?, updated_at = ? WHERE id = ?`, cause.Error(), now, id)
	return err
}

func evaluateSpoolPolicy(db *sql.DB, result *JSONLIngestResult) {
	if result == nil {
		return
	}
	for _, eventID := range result.EventIDs {
		record, persisted, err := security.EvaluateRuntimeEvent(db, eventID)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("event %s: policy failed: %v", eventID, err))
			result.Failed++
			continue
		}
		if persisted {
			result.PolicyDecisions++
			result.PolicyDecisionIDs = append(result.PolicyDecisionIDs, record.ID)
		}
	}
}

func (s SpoolService) List(runID string) ([]SpoolBatch, error) {
	query := `SELECT id, run_id, format, source_path, spool_path, file_sha256, size_bytes, status, priority, attempts, policy_enabled,
		ingest_batch_id, ingested_count, failed_count, error, created_at, updated_at, processed_at, dropped_at, drop_reason FROM telemetry_spool_batches`
	args := []any{}
	if runID != "" {
		query += ` WHERE run_id = ?`
		args = append(args, runID)
	}
	query += ` ORDER BY created_at ASC`
	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SpoolBatch
	for rows.Next() {
		var item SpoolBatch
		var policyEnabled int
		if err := rows.Scan(&item.ID, &item.RunID, &item.Format, &item.SourcePath, &item.SpoolPath, &item.FileSHA256, &item.SizeBytes, &item.Status, &item.Priority, &item.Attempts, &policyEnabled, &item.IngestBatchID, &item.IngestedCount, &item.FailedCount, &item.Error, &item.CreatedAt, &item.UpdatedAt, &item.ProcessedAt, &item.DroppedAt, &item.DropReason); err != nil {
			return nil, err
		}
		item.PolicyEnabled = policyEnabled != 0
		out = append(out, item)
	}
	return out, rows.Err()
}
