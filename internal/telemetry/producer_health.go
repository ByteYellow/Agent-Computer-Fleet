package telemetry

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

const ProducerHealthSchemaVersion = "agentprovenance.producer_health/v1"

type ProducerHealthOptions struct {
	RunID          string
	MaxQueued      int
	MaxQueuedBytes int64
	MaxBatchBytes  int64
	DropPolicy     string
}

type ProducerHealthReport struct {
	SchemaVersion string                 `json:"schema_version"`
	GeneratedAt   string                 `json:"generated_at"`
	RunID         string                 `json:"run_id,omitempty"`
	Limits        ProducerLimits         `json:"limits"`
	Spool         ProducerSpoolHealth    `json:"spool"`
	Events        ProducerEventHealth    `json:"events"`
	Coverage      ProducerCoverageHealth `json:"coverage"`
}

type ProducerLimits struct {
	MaxQueuedBatches int    `json:"max_queued_batches"`
	MaxQueuedBytes   int64  `json:"max_queued_bytes"`
	MaxBatchBytes    int64  `json:"max_batch_bytes"`
	DropPolicy       string `json:"drop_policy"`
}

type ProducerSpoolHealth struct {
	ReceivedBatches   int            `json:"received_batches"`
	QueuedBatches     int            `json:"queued_batches"`
	QueuedBytes       int64          `json:"queued_bytes"`
	ProcessingBatches int            `json:"processing_batches"`
	ProcessedBatches  int            `json:"processed_batches"`
	DroppedBatches    int            `json:"dropped_batches"`
	DroppedBytes      int64          `json:"dropped_bytes"`
	FailedBatches     int            `json:"failed_batches"`
	IngestedEvents    int            `json:"ingested_events"`
	FailedEvents      int            `json:"failed_events"`
	ByStatus          map[string]int `json:"by_status"`
}

type ProducerEventHealth struct {
	RuntimeEvents       int            `json:"runtime_events"`
	CorrelatedEvents    int            `json:"correlated_events"`
	UncorrelatedEvents  int            `json:"uncorrelated_events"`
	SensorDroppedEvents int64          `json:"sensor_dropped_events"`
	BySource            map[string]int `json:"by_source"`
}

type ProducerCoverageHealth struct {
	CorrelationRatio float64 `json:"correlation_ratio"`
	HasSensorDrops   bool    `json:"has_sensor_drops"`
	Complete         bool    `json:"complete"`
}

func BuildProducerHealth(db *sql.DB, opts ProducerHealthOptions) (ProducerHealthReport, error) {
	report := ProducerHealthReport{
		SchemaVersion: ProducerHealthSchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		RunID:         opts.RunID,
		Limits: ProducerLimits{
			MaxQueuedBatches: opts.MaxQueued,
			MaxQueuedBytes:   opts.MaxQueuedBytes,
			MaxBatchBytes:    opts.MaxBatchBytes,
			DropPolicy:       opts.DropPolicy,
		},
		Spool:  ProducerSpoolHealth{ByStatus: map[string]int{}},
		Events: ProducerEventHealth{BySource: map[string]int{}},
	}
	if db == nil {
		return report, fmt.Errorf("database is required")
	}
	if err := populateSpoolHealth(db, opts.RunID, &report.Spool); err != nil {
		return report, err
	}
	if err := populateEventHealth(db, opts.RunID, &report.Events); err != nil {
		return report, err
	}
	if report.Events.RuntimeEvents > 0 {
		report.Coverage.CorrelationRatio = float64(report.Events.CorrelatedEvents) / float64(report.Events.RuntimeEvents)
	}
	report.Coverage.HasSensorDrops = report.Events.SensorDroppedEvents > 0
	report.Coverage.Complete = report.Events.RuntimeEvents > 0 && report.Events.UncorrelatedEvents == 0 && !report.Coverage.HasSensorDrops
	return report, nil
}

func populateSpoolHealth(db *sql.DB, runID string, out *ProducerSpoolHealth) error {
	query := `SELECT status, COUNT(*), COALESCE(SUM(size_bytes), 0), COALESCE(SUM(ingested_count), 0), COALESCE(SUM(failed_count), 0)
		FROM telemetry_spool_batches`
	args := []any{}
	if runID != "" {
		query += ` WHERE run_id = ?`
		args = append(args, runID)
	}
	query += ` GROUP BY status`
	rows, err := db.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var count int
		var bytes int64
		var ingested, failed int
		if err := rows.Scan(&status, &count, &bytes, &ingested, &failed); err != nil {
			return err
		}
		out.ReceivedBatches += count
		out.IngestedEvents += ingested
		out.FailedEvents += failed
		out.ByStatus[status] = count
		switch status {
		case "queued":
			out.QueuedBatches += count
			out.QueuedBytes += bytes
		case "processing":
			out.ProcessingBatches += count
			out.QueuedBytes += bytes
		case "processed":
			out.ProcessedBatches += count
		case "dropped":
			out.DroppedBatches += count
			out.DroppedBytes += bytes
		case "failed":
			out.FailedBatches += count
		}
	}
	return rows.Err()
}

func populateEventHealth(db *sql.DB, runID string, out *ProducerEventHealth) error {
	sources := producerRuntimeSources()
	placeholders := ""
	args := make([]any, 0, len(sources)+1)
	for i, source := range sources {
		if i > 0 {
			placeholders += ","
		}
		placeholders += "?"
		args = append(args, source)
	}
	query := `SELECT source, COUNT(*), COALESCE(SUM(CASE WHEN correlation_method != '' THEN 1 ELSE 0 END), 0)
		FROM events WHERE source IN (` + placeholders + `)`
	if runID != "" {
		query += ` AND run_id = ?`
		args = append(args, runID)
	}
	query += ` GROUP BY source`
	rows, err := db.Query(query, args...)
	if err != nil {
		return err
	}
	for rows.Next() {
		var source string
		var count, correlated int
		if err := rows.Scan(&source, &count, &correlated); err != nil {
			rows.Close()
			return err
		}
		out.RuntimeEvents += count
		out.CorrelatedEvents += correlated
		out.BySource[source] = count
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	out.UncorrelatedEvents = out.RuntimeEvents - out.CorrelatedEvents

	dropQuery := `SELECT payload FROM events WHERE event_type = 'resource_pressure' AND source IN (` + placeholders + `)`
	dropArgs := append([]any(nil), args[:len(sources)]...)
	if runID != "" {
		dropQuery += ` AND run_id = ?`
		dropArgs = append(dropArgs, runID)
	}
	dropRows, err := db.Query(dropQuery, dropArgs...)
	if err != nil {
		return err
	}
	defer dropRows.Close()
	for dropRows.Next() {
		var payload string
		if err := dropRows.Scan(&payload); err != nil {
			return err
		}
		var body struct {
			Signal  string `json:"signal"`
			Dropped int64  `json:"dropped"`
		}
		if json.Unmarshal([]byte(payload), &body) == nil && body.Signal == "event_drop" && body.Dropped > out.SensorDroppedEvents {
			out.SensorDroppedEvents = body.Dropped
		}
	}
	return dropRows.Err()
}

func producerRuntimeSources() []string {
	return []string{
		"agentprov_ebpf", "external_telemetry", "falco_jsonl", "filtered_telemetry", "kernel",
		"loongcollector", "loongcollector_jsonl", "native_runtime", "record_file_diff",
		"record_process_sample", "runtime", "tetragon_jsonl", "wrapper_runtime", "zero_sdk_record",
		"zero_sdk_record_descendant",
	}
}
