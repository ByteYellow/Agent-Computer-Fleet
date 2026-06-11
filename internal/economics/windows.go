package economics

import (
	"database/sql"
	"fmt"
	"time"
)

type WindowOptions struct {
	Windows          []int
	RawRetention     time.Duration
	MaxRawPerSession int
}

type cpuSampleRow struct {
	RunID            string
	SessionID        string
	NodeID           string
	ActiveCPUSeconds float64
	IdleSeconds      float64
	CPUPercent       float64
	EWMAActiveCPU    float64
	Throttling       string
	MemoryPressure   string
	CreatedAt        time.Time
}

type sessionWindowAgg struct {
	RunID               string
	SessionID           string
	NodeID              string
	WindowSeconds       int
	WindowStart         time.Time
	ActiveCPUSeconds    float64
	IdleSeconds         float64
	CPUPercentSum       float64
	EWMAActiveCPUMax    float64
	ThrottlingCount     int64
	MemoryPressureCount int64
	SampleCount         int64
}

type nodeWindowAgg struct {
	NodeID              string
	WindowSeconds       int
	WindowStart         time.Time
	ActiveCPUSeconds    float64
	IdleSeconds         float64
	CPUPercentSum       float64
	EWMAActiveCPUMax    float64
	ThrottlingCount     int64
	MemoryPressureCount int64
	Sessions            map[string]struct{}
	SampleCount         int64
}

func AggregateResourceWindows(db *sql.DB, opts WindowOptions) error {
	if len(opts.Windows) == 0 {
		opts.Windows = []int{10, 60}
	}
	rows, err := db.Query(`SELECT run_id, session_id, node_id, active_cpu_seconds, idle_seconds, cpu_percent, ewma_active_cpu, throttling, memory_pressure, created_at
		FROM cpu_samples ORDER BY created_at ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	sessionAggs := map[string]*sessionWindowAgg{}
	nodeAggs := map[string]*nodeWindowAgg{}
	for rows.Next() {
		var sample cpuSampleRow
		var createdAt string
		if err := rows.Scan(&sample.RunID, &sample.SessionID, &sample.NodeID, &sample.ActiveCPUSeconds, &sample.IdleSeconds, &sample.CPUPercent, &sample.EWMAActiveCPU, &sample.Throttling, &sample.MemoryPressure, &createdAt); err != nil {
			return err
		}
		parsed, err := time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			continue
		}
		sample.CreatedAt = parsed.UTC()
		for _, seconds := range opts.Windows {
			if seconds <= 0 {
				continue
			}
			windowStart := sample.CreatedAt.Truncate(time.Duration(seconds) * time.Second)
			sessionKey := fmt.Sprintf("%s|%s|%d|%s", sample.SessionID, sample.NodeID, seconds, windowStart.Format(time.RFC3339Nano))
			sessionAgg := sessionAggs[sessionKey]
			if sessionAgg == nil {
				sessionAgg = &sessionWindowAgg{
					RunID:         sample.RunID,
					SessionID:     sample.SessionID,
					NodeID:        sample.NodeID,
					WindowSeconds: seconds,
					WindowStart:   windowStart,
				}
				sessionAggs[sessionKey] = sessionAgg
			}
			addSampleToSessionAgg(sessionAgg, sample)

			nodeKey := fmt.Sprintf("%s|%d|%s", sample.NodeID, seconds, windowStart.Format(time.RFC3339Nano))
			nodeAgg := nodeAggs[nodeKey]
			if nodeAgg == nil {
				nodeAgg = &nodeWindowAgg{
					NodeID:        sample.NodeID,
					WindowSeconds: seconds,
					WindowStart:   windowStart,
					Sessions:      map[string]struct{}{},
				}
				nodeAggs[nodeKey] = nodeAgg
			}
			addSampleToNodeAgg(nodeAgg, sample)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, agg := range sessionAggs {
		avgCPU := 0.0
		if agg.SampleCount > 0 {
			avgCPU = agg.CPUPercentSum / float64(agg.SampleCount)
		}
		if _, err := tx.Exec(`INSERT INTO session_resource_windows
			(run_id, session_id, node_id, window_seconds, window_start, active_cpu_seconds, idle_seconds, avg_cpu_percent, ewma_active_cpu, throttling_count, memory_pressure_count, sample_count, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(session_id, window_seconds, window_start) DO UPDATE SET
				run_id = excluded.run_id,
				node_id = excluded.node_id,
				active_cpu_seconds = excluded.active_cpu_seconds,
				idle_seconds = excluded.idle_seconds,
				avg_cpu_percent = excluded.avg_cpu_percent,
				ewma_active_cpu = excluded.ewma_active_cpu,
				throttling_count = excluded.throttling_count,
				memory_pressure_count = excluded.memory_pressure_count,
				sample_count = excluded.sample_count,
				updated_at = excluded.updated_at`,
			agg.RunID, agg.SessionID, agg.NodeID, agg.WindowSeconds, agg.WindowStart.Format(time.RFC3339Nano), agg.ActiveCPUSeconds, agg.IdleSeconds, avgCPU, agg.EWMAActiveCPUMax, agg.ThrottlingCount, agg.MemoryPressureCount, agg.SampleCount, now); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	for _, agg := range nodeAggs {
		avgCPU := 0.0
		if agg.SampleCount > 0 {
			avgCPU = agg.CPUPercentSum / float64(agg.SampleCount)
		}
		if _, err := tx.Exec(`INSERT INTO node_resource_windows
			(node_id, window_seconds, window_start, active_cpu_seconds, idle_seconds, avg_cpu_percent, ewma_active_cpu, throttling_count, memory_pressure_count, session_count, sample_count, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(node_id, window_seconds, window_start) DO UPDATE SET
				active_cpu_seconds = excluded.active_cpu_seconds,
				idle_seconds = excluded.idle_seconds,
				avg_cpu_percent = excluded.avg_cpu_percent,
				ewma_active_cpu = excluded.ewma_active_cpu,
				throttling_count = excluded.throttling_count,
				memory_pressure_count = excluded.memory_pressure_count,
				session_count = excluded.session_count,
				sample_count = excluded.sample_count,
				updated_at = excluded.updated_at`,
			agg.NodeID, agg.WindowSeconds, agg.WindowStart.Format(time.RFC3339Nano), agg.ActiveCPUSeconds, agg.IdleSeconds, avgCPU, agg.EWMAActiveCPUMax, agg.ThrottlingCount, agg.MemoryPressureCount, len(agg.Sessions), agg.SampleCount, now); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func RetainRawCPUSamples(db *sql.DB, opts WindowOptions) error {
	if opts.RawRetention <= 0 {
		opts.RawRetention = 10 * time.Minute
	}
	if opts.MaxRawPerSession <= 0 {
		opts.MaxRawPerSession = 512
	}
	cutoff := time.Now().UTC().Add(-opts.RawRetention).Format(time.RFC3339Nano)
	if _, err := db.Exec(`DELETE FROM cpu_samples WHERE created_at < ?`, cutoff); err != nil {
		return err
	}
	rows, err := db.Query(`SELECT DISTINCT session_id FROM cpu_samples`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var sessions []string
	for rows.Next() {
		var sessionID string
		if err := rows.Scan(&sessionID); err != nil {
			return err
		}
		sessions = append(sessions, sessionID)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, sessionID := range sessions {
		if _, err := db.Exec(`DELETE FROM cpu_samples
			WHERE session_id = ?
			  AND id NOT IN (
				SELECT id FROM cpu_samples
				WHERE session_id = ?
				ORDER BY created_at DESC
				LIMIT ?
			  )`, sessionID, sessionID, opts.MaxRawPerSession); err != nil {
			return err
		}
	}
	return nil
}

func addSampleToSessionAgg(agg *sessionWindowAgg, sample cpuSampleRow) {
	agg.ActiveCPUSeconds += sample.ActiveCPUSeconds
	agg.IdleSeconds += sample.IdleSeconds
	agg.CPUPercentSum += sample.CPUPercent
	if sample.EWMAActiveCPU > agg.EWMAActiveCPUMax {
		agg.EWMAActiveCPUMax = sample.EWMAActiveCPU
	}
	if sample.Throttling != "" && sample.Throttling != "unknown" {
		agg.ThrottlingCount++
	}
	if sample.MemoryPressure != "" && sample.MemoryPressure != "low" {
		agg.MemoryPressureCount++
	}
	agg.SampleCount++
}

func addSampleToNodeAgg(agg *nodeWindowAgg, sample cpuSampleRow) {
	agg.ActiveCPUSeconds += sample.ActiveCPUSeconds
	agg.IdleSeconds += sample.IdleSeconds
	agg.CPUPercentSum += sample.CPUPercent
	if sample.EWMAActiveCPU > agg.EWMAActiveCPUMax {
		agg.EWMAActiveCPUMax = sample.EWMAActiveCPU
	}
	if sample.Throttling != "" && sample.Throttling != "unknown" {
		agg.ThrottlingCount++
	}
	if sample.MemoryPressure != "" && sample.MemoryPressure != "low" {
		agg.MemoryPressureCount++
	}
	agg.Sessions[sample.SessionID] = struct{}{}
	agg.SampleCount++
}
