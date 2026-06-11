package economics

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/ids"
)

type DockerStatsSample struct {
	SessionID        string
	RunID            string
	ContainerID      string
	CPUPerc          float64
	MemoryUsageBytes int64
	MemoryLimitBytes int64
	ActiveCPUSeconds float64
	IdleSeconds      float64
	Throttling       string
	MemoryPressure   string
	EWMAActiveCPU    float64
}

type SamplerResult struct {
	Sampled int
	Failed  int
	Skipped int
	Errors  []string
}

func SampleRunningDockerSessions(db *sql.DB) (SamplerResult, error) {
	return SampleRunningDockerSessionsWithOptions(db, SamplerOptions{})
}

type SamplerOptions struct {
	Limit            int
	Timeout          time.Duration
	RawRetention     time.Duration
	MaxRawPerSession int
}

func SampleRunningDockerSessionsWithOptions(db *sql.DB, opts SamplerOptions) (SamplerResult, error) {
	if opts.Limit <= 0 {
		opts.Limit = 64
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions
		WHERE status IN ('running', 'idle', 'quarantined')
		  AND COALESCE(runtime, 'docker') = 'docker'
		  AND COALESCE(container_id, '') != ''`).Scan(&total); err != nil {
		return SamplerResult{}, err
	}
	rows, err := db.Query(`SELECT s.id FROM sessions s
		LEFT JOIN (
			SELECT session_id, MAX(created_at) AS last_sampled_at
			FROM cpu_samples
			GROUP BY session_id
		) cs ON cs.session_id = s.id
		WHERE s.status IN ('running', 'idle', 'quarantined')
		  AND COALESCE(s.runtime, 'docker') = 'docker'
		  AND COALESCE(s.container_id, '') != ''
		ORDER BY COALESCE(cs.last_sampled_at, ''), s.created_at ASC
		LIMIT ?`, opts.Limit)
	if err != nil {
		return SamplerResult{}, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var sessionID string
		if err := rows.Scan(&sessionID); err != nil {
			return SamplerResult{}, err
		}
		ids = append(ids, sessionID)
	}
	if err := rows.Err(); err != nil {
		return SamplerResult{}, err
	}
	result := SamplerResult{Skipped: total - len(ids)}
	if result.Skipped < 0 {
		result.Skipped = 0
	}
	for _, sessionID := range ids {
		ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
		_, err := SampleDockerStatsContext(ctx, db, sessionID)
		cancel()
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", sessionID, err))
			continue
		}
		result.Sampled++
	}
	if err := AggregateResourceWindows(db, WindowOptions{Windows: []int{10, 60}}); err != nil {
		return result, err
	}
	if err := RetainRawCPUSamples(db, WindowOptions{RawRetention: opts.RawRetention, MaxRawPerSession: opts.MaxRawPerSession}); err != nil {
		return result, err
	}
	return result, nil
}

func SampleDockerStats(db *sql.DB, sessionID string) (DockerStatsSample, error) {
	return SampleDockerStatsContext(context.Background(), db, sessionID)
}

func SampleDockerStatsContext(ctx context.Context, db *sql.DB, sessionID string) (DockerStatsSample, error) {
	var runID, containerID string
	if err := db.QueryRow(`SELECT run_id, COALESCE(container_id, '') FROM sessions WHERE id = ?`, sessionID).Scan(&runID, &containerID); err != nil {
		return DockerStatsSample{}, err
	}
	if containerID == "" {
		return DockerStatsSample{}, fmt.Errorf("session %s has no container id", sessionID)
	}
	raw, err := exec.CommandContext(ctx, "docker", "stats", "--no-stream", "--format", "{{json .}}", containerID).Output()
	if err != nil {
		return DockerStatsSample{}, err
	}
	var row struct {
		CPUPerc  string `json:"CPUPerc"`
		MemUsage string `json:"MemUsage"`
	}
	if err := json.Unmarshal(raw, &row); err != nil {
		return DockerStatsSample{}, err
	}
	cpu := parsePercent(row.CPUPerc)
	used, limit := parseMemUsage(row.MemUsage)
	active := cpu / 100.0
	if active < 0 {
		active = 0
	}
	idle := 1.0 - active
	if idle < 0 {
		idle = 0
	}
	pressure := "low"
	if limit > 0 && float64(used)/float64(limit) > 0.85 {
		pressure = "high"
	}
	throttling := "unknown"
	if cpu > 95 {
		throttling = "possible"
	}
	sample := DockerStatsSample{
		SessionID:        sessionID,
		RunID:            runID,
		ContainerID:      containerID,
		CPUPerc:          cpu,
		MemoryUsageBytes: used,
		MemoryLimitBytes: limit,
		ActiveCPUSeconds: active,
		IdleSeconds:      idle,
		Throttling:       throttling,
		MemoryPressure:   pressure,
	}
	const alpha = 0.35
	var prevEWMA float64
	_ = db.QueryRow(`SELECT COALESCE(ewma_active_cpu, 0) FROM cpu_samples WHERE session_id = ? ORDER BY created_at DESC LIMIT 1`, sessionID).Scan(&prevEWMA)
	if prevEWMA == 0 {
		sample.EWMAActiveCPU = sample.ActiveCPUSeconds
	} else {
		sample.EWMAActiveCPU = alpha*sample.ActiveCPUSeconds + (1-alpha)*prevEWMA
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = db.Exec(`INSERT INTO cpu_samples (id, run_id, session_id, node_id, active_cpu_seconds, idle_seconds, cpu_percent, ewma_active_cpu, throttling, memory_pressure, created_at)
		VALUES (?, ?, ?, 'local', ?, ?, ?, ?, ?, ?, ?)`, ids.New("cpu"), runID, sessionID, sample.ActiveCPUSeconds, sample.IdleSeconds, sample.CPUPerc, sample.EWMAActiveCPU, sample.Throttling, sample.MemoryPressure, now)
	_ = AggregateResourceWindows(db, WindowOptions{Windows: []int{10, 60}})
	payload := fmt.Sprintf(`{"cpu_percent":%.3f,"memory_usage_bytes":%d,"memory_limit_bytes":%d,"throttling":%q,"memory_pressure":%q}`,
		sample.CPUPerc, sample.MemoryUsageBytes, sample.MemoryLimitBytes, sample.Throttling, sample.MemoryPressure)
	_, _ = db.Exec(`INSERT INTO events (id, run_id, session_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, 'docker_stats', 'resource_sample', ?, ?)`, ids.New("evt"), runID, sessionID, payload, now)
	return sample, nil
}

func parsePercent(value string) float64 {
	value = strings.TrimSpace(strings.TrimSuffix(value, "%"))
	parsed, _ := strconv.ParseFloat(value, 64)
	return parsed
}

func parseMemUsage(value string) (int64, int64) {
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return 0, 0
	}
	return parseBytes(parts[0]), parseBytes(parts[1])
}

func parseBytes(value string) int64 {
	value = strings.TrimSpace(value)
	units := []struct {
		suffix string
		scale  float64
	}{
		{"GiB", 1024 * 1024 * 1024}, {"MiB", 1024 * 1024}, {"KiB", 1024},
		{"GB", 1000 * 1000 * 1000}, {"MB", 1000 * 1000}, {"KB", 1000},
		{"B", 1},
	}
	for _, unit := range units {
		if strings.HasSuffix(value, unit.suffix) {
			raw := strings.TrimSpace(strings.TrimSuffix(value, unit.suffix))
			parsed, _ := strconv.ParseFloat(raw, 64)
			return int64(parsed * unit.scale)
		}
	}
	parsed, _ := strconv.ParseFloat(value, 64)
	return int64(parsed)
}
