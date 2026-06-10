package economics

import (
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

func SampleDockerStats(db *sql.DB, sessionID string) (DockerStatsSample, error) {
	var runID, containerID string
	if err := db.QueryRow(`SELECT run_id, COALESCE(container_id, '') FROM sessions WHERE id = ?`, sessionID).Scan(&runID, &containerID); err != nil {
		return DockerStatsSample{}, err
	}
	if containerID == "" {
		return DockerStatsSample{}, fmt.Errorf("session %s has no container id", sessionID)
	}
	raw, err := exec.Command("docker", "stats", "--no-stream", "--format", "{{json .}}", containerID).Output()
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
	_, _ = db.Exec(`INSERT INTO cost_samples (id, run_id, session_id, node_id, active_cpu_seconds, idle_seconds, wall_seconds, created_at)
		VALUES (?, ?, ?, 'local', ?, ?, 1, ?)`, ids.New("cost"), runID, sessionID, sample.ActiveCPUSeconds, sample.IdleSeconds, now)
	_, _ = db.Exec(`INSERT INTO cpu_samples (id, run_id, session_id, node_id, active_cpu_seconds, idle_seconds, cpu_percent, ewma_active_cpu, throttling, memory_pressure, created_at)
		VALUES (?, ?, ?, 'local', ?, ?, ?, ?, ?, ?, ?)`, ids.New("cpu"), runID, sessionID, sample.ActiveCPUSeconds, sample.IdleSeconds, sample.CPUPerc, sample.EWMAActiveCPU, sample.Throttling, sample.MemoryPressure, now)
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
