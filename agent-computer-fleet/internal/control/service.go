package control

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/economics"
	"github.com/byteyellow/agent-computer-fleet/internal/ids"
	"github.com/byteyellow/agent-computer-fleet/internal/node"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
)

type Service struct {
	DB      *sql.DB
	Paths   store.Paths
	Runtime node.Runtime
}

type SessionInfo struct {
	ID            string
	LeaseID       string
	RunID         string
	ContainerID   string
	WorkspacePath string
	Status        string
	StartupColdMS int64
	CreatedAt     string
	UpdatedAt     string
}

func (s Service) CreateLease(taskPath string) (string, error) {
	task, raw, err := LoadTask(taskPath)
	if err != nil {
		return "", err
	}
	if task.RunID == "" {
		task.RunID = ids.New("run")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	leaseID := ids.New("lease")
	_, err = s.DB.Exec(`INSERT INTO leases (id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'created', ?, ?)`, leaseID, task.RunID, taskPath, string(raw), now, now)
	return leaseID, err
}

func (s Service) CreateSession(leaseID string) (string, error) {
	var runID, taskPath string
	if err := s.DB.QueryRow(`SELECT run_id, task_path FROM leases WHERE id = ?`, leaseID).Scan(&runID, &taskPath); err != nil {
		return "", err
	}
	task, _, err := LoadTask(taskPath)
	if err != nil {
		return "", err
	}
	sessionID := ids.New("sbx")
	workspace := filepath.Join(s.Paths.Workspaces, sessionID)
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		return "", err
	}
	if err := s.admit(task); err != nil {
		return "", err
	}
	start := time.Now()
	containerID, err := s.Runtime.CreateSession(node.CreateSessionRequest{
		SessionID:         sessionID,
		LeaseID:           leaseID,
		RunID:             runID,
		Image:             task.Image,
		WorkspaceHostPath: workspace,
		MemoryMB:          task.MemoryMB,
		CPURequest:        task.CPURequest,
		NetworkMode:       task.NetworkMode,
	})
	if err != nil {
		return "", err
	}
	startupColdMS := time.Since(start).Milliseconds()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`INSERT INTO sessions (id, lease_id, run_id, container_id, workspace_host_path, status, startup_cold_ms, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 'running', ?, ?, ?)`, sessionID, leaseID, runID, containerID, workspace, startupColdMS, now, now)
	if err != nil {
		return "", err
	}
	_, _ = s.DB.Exec(`UPDATE leases SET status = 'allocated', updated_at = ? WHERE id = ?`, now, leaseID)
	_, _ = s.DB.Exec(`INSERT INTO cost_samples (id, run_id, session_id, wall_seconds, created_at)
		VALUES (?, ?, ?, ?, ?)`, ids.New("cost"), runID, sessionID, float64(startupColdMS)/1000, now)
	return sessionID, nil
}

func (s Service) Exec(sessionID string, command []string, stream bool) (string, error) {
	if len(command) == 0 {
		return "", fmt.Errorf("command is required")
	}
	var containerID, runID string
	if err := s.DB.QueryRow(`SELECT container_id, run_id FROM sessions WHERE id = ?`, sessionID).Scan(&containerID, &runID); err != nil {
		return "", err
	}
	processID := ids.New("proc")
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.DB.Exec(`INSERT INTO processes (id, session_id, container_id, command, status, started_at)
		VALUES (?, ?, ?, ?, 'running', ?)`, processID, sessionID, containerID, strings.Join(command, " "), now)
	if err != nil {
		return "", err
	}
	start := time.Now()
	result, err := s.Runtime.Exec(containerID, command, stream)
	wallSeconds := time.Since(start).Seconds()
	status := "exited"
	if err != nil {
		status = "failed"
	}
	ended := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = s.DB.Exec(`UPDATE processes SET exec_id = ?, status = ?, exit_code = ?, ended_at = ? WHERE id = ?`, result.ExecID, status, result.ExitCode, ended, processID)
	_, _ = s.DB.Exec(`INSERT INTO cost_samples (id, run_id, session_id, wall_seconds, active_cpu_seconds, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, ids.New("cost"), runID, sessionID, wallSeconds, wallSeconds, ended)
	return processID, err
}

func (s Service) Interrupt(processID string) error {
	var containerID string
	if err := s.DB.QueryRow(`SELECT container_id FROM processes WHERE id = ?`, processID).Scan(&containerID); err != nil {
		return err
	}
	return s.Runtime.Interrupt(containerID)
}

func (s Service) ExposePort(sessionID string, port int) (string, error) {
	var runID string
	if err := s.DB.QueryRow(`SELECT run_id FROM sessions WHERE id = ?`, sessionID).Scan(&runID); err != nil {
		return "", err
	}
	url := fmt.Sprintf("http://localhost:%d", port)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, session_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, 'acfctl', 'port_expose', ?, ?)`, ids.New("evt"), runID, sessionID, fmt.Sprintf(`{"port":%d,"url":%q}`, port, url), now)
	return url, nil
}

func (s Service) ListSessions() ([]SessionInfo, error) {
	rows, err := s.DB.Query(`SELECT id, lease_id, run_id, COALESCE(container_id, ''), workspace_host_path, status, startup_cold_ms, created_at, updated_at
		FROM sessions ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sessions []SessionInfo
	for rows.Next() {
		var session SessionInfo
		if err := rows.Scan(&session.ID, &session.LeaseID, &session.RunID, &session.ContainerID, &session.WorkspacePath, &session.Status, &session.StartupColdMS, &session.CreatedAt, &session.UpdatedAt); err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func (s Service) InspectSession(sessionID string) (SessionInfo, error) {
	var session SessionInfo
	err := s.DB.QueryRow(`SELECT id, lease_id, run_id, COALESCE(container_id, ''), workspace_host_path, status, startup_cold_ms, created_at, updated_at
		FROM sessions WHERE id = ?`, sessionID).Scan(&session.ID, &session.LeaseID, &session.RunID, &session.ContainerID, &session.WorkspacePath, &session.Status, &session.StartupColdMS, &session.CreatedAt, &session.UpdatedAt)
	return session, err
}

func (s Service) StopSession(sessionID string) error {
	session, err := s.InspectSession(sessionID)
	if err != nil {
		return err
	}
	if session.ContainerID != "" && s.Runtime != nil {
		if err := s.Runtime.Stop(session.ContainerID); err != nil {
			return err
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`UPDATE sessions SET status = 'stopped', updated_at = ? WHERE id = ?`, now, sessionID)
	return err
}

func (s Service) RemoveSession(sessionID string) error {
	session, err := s.InspectSession(sessionID)
	if err != nil {
		return err
	}
	if session.ContainerID != "" && s.Runtime != nil {
		if err := s.Runtime.Remove(session.ContainerID); err != nil {
			return err
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`UPDATE sessions SET status = 'removed', container_id = '', updated_at = ? WHERE id = ?`, now, sessionID)
	return err
}

func (s Service) admit(task Task) error {
	memoryTotalMB := envInt64("ACF_NODE_MEMORY_MB", 8192)
	physicalCPU := float64(envInt("ACF_NODE_CPU", goruntime.NumCPU()))
	overcommitRatio := envFloat("ACF_CPU_OVERCOMMIT_RATIO", 2.0)
	idleDiscount := envFloat("ACF_IDLE_CPU_DISCOUNT", 0.1)
	memorySafetyRatio := envFloat("ACF_MEMORY_SAFETY_RATIO", 0.9)
	// The task YAML is stored as text, so v1 conservatively counts only the new request.
	input := economics.AdmissionInput{
		PhysicalCPU:       physicalCPU,
		OvercommitRatio:   overcommitRatio,
		ActiveCPURequest:  task.CPURequest,
		IdleCPURequest:    task.CPURequest,
		IdleDiscount:      idleDiscount,
		MemoryAllocatedMB: 0,
		MemoryRequestMB:   task.MemoryMB,
		MemoryTotalMB:     memoryTotalMB,
		MemorySafetyRatio: memorySafetyRatio,
	}
	if !economics.Admit(input) {
		return fmt.Errorf("admission rejected: cpu_request=%.2f memory_mb=%d capacity_cpu=%.2f memory_total_mb=%d", task.CPURequest, task.MemoryMB, physicalCPU*overcommitRatio, memoryTotalMB)
	}
	return nil
}

func envInt(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt64(name string, fallback int64) int64 {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func envFloat(name string, fallback float64) float64 {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return parsed
}
