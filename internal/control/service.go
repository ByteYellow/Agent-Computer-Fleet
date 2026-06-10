package control

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/egress"
	"github.com/byteyellow/agent-computer-fleet/internal/ids"
	runtimeplane "github.com/byteyellow/agent-computer-fleet/internal/runtime"
	"github.com/byteyellow/agent-computer-fleet/internal/scheduler"
	"github.com/byteyellow/agent-computer-fleet/internal/state"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/byteyellow/agent-computer-fleet/internal/warm"
)

type Service struct {
	DB     *sql.DB
	Paths  store.Paths
	Driver runtimeplane.Driver
}

type SessionInfo struct {
	ID                    string
	LeaseID               string
	RunID                 string
	ContainerID           string
	WorkspacePath         string
	Status                string
	StartupColdMS         int64
	RuntimeName           string
	ParentSnapshotID      string
	ResumedFromSnapshotID string
	CreatedAt             string
	UpdatedAt             string
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
	templateName := templateNameFromTaskPath(taskPath)
	warmHit := false
	if item, ok, hitErr := (warm.Service{DB: s.DB, Paths: s.Paths}).Hit(templateName, sessionID, 250, task.MemoryMB); hitErr != nil {
		return "", hitErr
	} else if ok {
		workspace = item.WorkspacePath
		warmHit = true
	}
	if !warmHit {
		if err := os.MkdirAll(workspace, 0o755); err != nil {
			return "", err
		}
	}
	decision, err := (scheduler.Scheduler{DB: s.DB}).Admit(scheduler.Request{
		RunID:      runID,
		SessionID:  sessionID,
		Runtime:    "docker",
		RiskTier:   task.RiskTier,
		CPURequest: task.CPURequest,
		MemoryMB:   task.MemoryMB,
	})
	if err != nil {
		return "", err
	}
	if !decision.Admitted {
		return "", fmt.Errorf("admission rejected: reject_reason=%s effective_cpu=%.3f debt=%.3f burst_risk=%s overcommit_ratio=%.2f queue_pressure=%s memory_pressure=%s memory_allocated_mb=%d memory_request_mb=%d memory_capacity_mb=%d",
			decision.RejectReason, decision.EffectiveCPU, decision.ActiveCPUDebt, decision.BurstRisk, decision.OvercommitRatio, decision.QueuePressure, decision.MemoryPressure, decision.MemoryAllocatedMB, decision.MemoryRequestMB, decision.MemoryCapacityMB)
	}
	var egressProxy egress.ProxyInfo
	if s.isDockerRuntime() {
		egressProxy, err = (egress.Service{DB: s.DB, Paths: s.Paths}).EnsureSessionProxy(runID, sessionID)
		if err != nil {
			return "", err
		}
	}
	start := time.Now()
	containerID, err := s.createRuntimeSession(runtimeplane.CreateSessionRequest{
		SessionID:         sessionID,
		LeaseID:           leaseID,
		RunID:             runID,
		Image:             task.Image,
		WorkspaceHostPath: workspace,
		MemoryMB:          task.MemoryMB,
		CPURequest:        task.CPURequest,
		NetworkMode:       task.NetworkMode,
		ProxyURL:          egressProxy.ContainerProxyURL,
		NoProxy:           "localhost,127.0.0.1,::1",
		DockerNetworkName: egressProxy.NetworkName,
	})
	if err != nil {
		return "", err
	}
	startupColdMS := time.Since(start).Milliseconds()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	runtimeName := s.runtimeName()
	_, err = s.DB.Exec(`INSERT INTO sessions (id, lease_id, run_id, container_id, workspace_host_path, runtime, status, startup_cold_ms, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 'running', ?, ?, ?)`, sessionID, leaseID, runID, containerID, workspace, runtimeName, startupColdMS, now, now)
	if err != nil {
		return "", err
	}
	_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, session_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, 'control_plane', 'session_create', ?, ?)`, ids.New("evt"), runID, sessionID, fmt.Sprintf(`{"container_id":%q,"workspace":%q,"startup_cold_ms":%d,"runtime":%q,"scheduler_decision":%q,"node_id":%q,"warm_hit":%t}`, containerID, workspace, startupColdMS, runtimeName, decision.Reason, decision.NodeID, warmHit), now)
	_, _ = s.DB.Exec(`UPDATE leases SET status = 'allocated', updated_at = ? WHERE id = ?`, now, leaseID)
	_, _ = s.DB.Exec(`INSERT INTO cost_samples (id, run_id, session_id, wall_seconds, created_at)
		VALUES (?, ?, ?, ?, ?)`, ids.New("cost"), runID, sessionID, float64(startupColdMS)/1000, now)
	return sessionID, nil
}

func (s Service) Exec(sessionID string, command []string, stream bool) (string, error) {
	return s.exec(sessionID, command, stream, nil, nil)
}

func (s Service) ExecStream(sessionID string, command []string, stdout, stderr io.Writer) (string, error) {
	return s.exec(sessionID, command, true, stdout, stderr)
}

func (s Service) exec(sessionID string, command []string, stream bool, stdout, stderr io.Writer) (string, error) {
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
	_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, session_id, process_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, ?, 'control_plane', 'exec_start', ?, ?)`, ids.New("evt"), runID, sessionID, processID, fmt.Sprintf(`{"command":%q,"stream":%t}`, strings.Join(command, " "), stream), now)
	start := time.Now()
	result, err := s.execRuntime(containerID, command, stream, stdout, stderr)
	wallSeconds := time.Since(start).Seconds()
	status := "exited"
	if err != nil {
		status = "failed"
	}
	ended := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = s.DB.Exec(`UPDATE processes SET exec_id = ?, status = ?, exit_code = ?, ended_at = ? WHERE id = ?`, result.ExecID, status, result.ExitCode, ended, processID)
	_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, session_id, process_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, ?, 'control_plane', 'exec_end', ?, ?)`, ids.New("evt"), runID, sessionID, processID, fmt.Sprintf(`{"exec_id":%q,"exit_code":%d,"status":%q,"wall_seconds":%.6f}`, result.ExecID, result.ExitCode, status, wallSeconds), ended)
	_, _ = s.DB.Exec(`INSERT INTO cost_samples (id, run_id, session_id, node_id, wall_seconds, active_cpu_seconds, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, ids.New("cost"), runID, sessionID, "local", wallSeconds, wallSeconds, ended)
	return processID, err
}

func (s Service) Interrupt(processID string) error {
	var containerID string
	if err := s.DB.QueryRow(`SELECT container_id FROM processes WHERE id = ?`, processID).Scan(&containerID); err != nil {
		return err
	}
	if s.Driver != nil {
		return s.Driver.Interrupt(context.Background(), containerID)
	}
	return fmt.Errorf("runtime driver is required")
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
	rows, err := s.DB.Query(`SELECT id, lease_id, run_id, COALESCE(container_id, ''), workspace_host_path, status, startup_cold_ms, COALESCE(runtime, 'docker'), COALESCE(parent_snapshot_id, ''), COALESCE(resumed_from_snapshot_id, ''), created_at, updated_at
		FROM sessions ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sessions []SessionInfo
	for rows.Next() {
		var session SessionInfo
		if err := rows.Scan(&session.ID, &session.LeaseID, &session.RunID, &session.ContainerID, &session.WorkspacePath, &session.Status, &session.StartupColdMS, &session.RuntimeName, &session.ParentSnapshotID, &session.ResumedFromSnapshotID, &session.CreatedAt, &session.UpdatedAt); err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func (s Service) InspectSession(sessionID string) (SessionInfo, error) {
	var session SessionInfo
	err := s.DB.QueryRow(`SELECT id, lease_id, run_id, COALESCE(container_id, ''), workspace_host_path, status, startup_cold_ms, COALESCE(runtime, 'docker'), COALESCE(parent_snapshot_id, ''), COALESCE(resumed_from_snapshot_id, ''), created_at, updated_at
		FROM sessions WHERE id = ?`, sessionID).Scan(&session.ID, &session.LeaseID, &session.RunID, &session.ContainerID, &session.WorkspacePath, &session.Status, &session.StartupColdMS, &session.RuntimeName, &session.ParentSnapshotID, &session.ResumedFromSnapshotID, &session.CreatedAt, &session.UpdatedAt)
	return session, err
}

func (s Service) StopSession(sessionID string) error {
	session, err := s.InspectSession(sessionID)
	if err != nil {
		return err
	}
	if session.ContainerID != "" {
		if err := s.stopRuntime(session.ContainerID); err != nil {
			return err
		}
	}
	_ = (egress.Service{DB: s.DB, Paths: s.Paths}).CloseForSession(sessionID)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`UPDATE sessions SET status = 'stopped', updated_at = ? WHERE id = ?`, now, sessionID)
	return err
}

func (s Service) RemoveSession(sessionID string) error {
	session, err := s.InspectSession(sessionID)
	if err != nil {
		return err
	}
	if session.ContainerID != "" {
		if err := s.removeRuntime(session.ContainerID); err != nil {
			return err
		}
	}
	_ = (egress.Service{DB: s.DB, Paths: s.Paths}).CloseForSession(sessionID)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`UPDATE sessions SET status = 'removed', container_id = '', updated_at = ? WHERE id = ?`, now, sessionID)
	return err
}

func (s Service) ResumeSnapshot(snapshotNameOrID, leaseID string) (string, error) {
	var runID, taskPath string
	if err := s.DB.QueryRow(`SELECT run_id, task_path FROM leases WHERE id = ?`, leaseID).Scan(&runID, &taskPath); err != nil {
		return "", err
	}
	task, _, err := LoadTask(taskPath)
	if err != nil {
		return "", err
	}
	stateSvc := state.Service{DB: s.DB, Paths: s.Paths}
	plan, err := stateSvc.Plan(snapshotNameOrID, true)
	if err != nil {
		return "", err
	}
	snapshot, _, err := stateSvc.InspectSnapshot(plan.SnapshotID)
	if err != nil {
		return "", err
	}
	if snapshot.Kind != "directory" && snapshot.Kind != "ready" {
		return "", fmt.Errorf("snapshot %s kind=%s cannot be resumed by docker directory driver", snapshot.ID, snapshot.Kind)
	}
	sessionID := ids.New("sbx")
	workspace := filepath.Join(s.Paths.Workspaces, sessionID)
	startCopy := time.Now()
	if s.Driver != nil {
		if _, err := s.Driver.ResumeDirectorySnapshot(context.Background(), snapshot.Path, workspace); err != nil {
			return "", err
		}
	} else {
		if err := state.CopyDir(snapshot.Path, workspace); err != nil {
			return "", err
		}
	}
	resumeCopyMS := time.Since(startCopy).Milliseconds()
	decision, err := (scheduler.Scheduler{DB: s.DB}).Admit(scheduler.Request{
		RunID:      runID,
		SessionID:  sessionID,
		Runtime:    "docker",
		RiskTier:   task.RiskTier,
		CPURequest: task.CPURequest,
		MemoryMB:   task.MemoryMB,
		SnapshotID: snapshot.ID,
	})
	if err != nil {
		return "", err
	}
	if !decision.Admitted {
		return "", fmt.Errorf("admission rejected: reject_reason=%s effective_cpu=%.3f debt=%.3f burst_risk=%s overcommit_ratio=%.2f queue_pressure=%s memory_pressure=%s memory_allocated_mb=%d memory_request_mb=%d memory_capacity_mb=%d",
			decision.RejectReason, decision.EffectiveCPU, decision.ActiveCPUDebt, decision.BurstRisk, decision.OvercommitRatio, decision.QueuePressure, decision.MemoryPressure, decision.MemoryAllocatedMB, decision.MemoryRequestMB, decision.MemoryCapacityMB)
	}
	var egressProxy egress.ProxyInfo
	if s.isDockerRuntime() {
		egressProxy, err = (egress.Service{DB: s.DB, Paths: s.Paths}).EnsureSessionProxy(runID, sessionID)
		if err != nil {
			return "", err
		}
	}
	start := time.Now()
	containerID, err := s.createRuntimeSession(runtimeplane.CreateSessionRequest{
		SessionID:         sessionID,
		LeaseID:           leaseID,
		RunID:             runID,
		Image:             task.Image,
		WorkspaceHostPath: workspace,
		MemoryMB:          task.MemoryMB,
		CPURequest:        task.CPURequest,
		NetworkMode:       task.NetworkMode,
		ProxyURL:          egressProxy.ContainerProxyURL,
		NoProxy:           "localhost,127.0.0.1,::1",
		DockerNetworkName: egressProxy.NetworkName,
	})
	if err != nil {
		return "", err
	}
	startupColdMS := time.Since(start).Milliseconds()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	runtimeName := s.runtimeName()
	_, err = s.DB.Exec(`INSERT INTO sessions (id, lease_id, run_id, container_id, workspace_host_path, runtime, parent_snapshot_id, resumed_from_snapshot_id, status, startup_cold_ms, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?, ?)`, sessionID, leaseID, runID, containerID, workspace, runtimeName, snapshot.ID, snapshot.ID, startupColdMS, now, now)
	if err != nil {
		return "", err
	}
	_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, session_id, snapshot_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, ?, 'control_plane', 'snapshot_resume', ?, ?)`, ids.New("evt"), runID, sessionID, snapshot.ID, fmt.Sprintf(`{"container_id":%q,"workspace":%q,"resume_copy_ms":%d,"startup_cold_ms":%d,"runtime":%q}`, containerID, workspace, resumeCopyMS, startupColdMS, runtimeName), now)
	_, _ = s.DB.Exec(`INSERT INTO snapshot_edges (id, parent_id, child_id, edge_type, plan, plan_reason, planner_score, created_at)
		VALUES (?, ?, ?, 'resume', ?, ?, ?, ?)`, ids.New("edge"), snapshot.ID, sessionID, plan.Plan, plan.Reason, plan.Score, now)
	_, _ = s.DB.Exec(`UPDATE leases SET status = 'allocated', updated_at = ? WHERE id = ?`, now, leaseID)
	_, _ = s.DB.Exec(`INSERT INTO cost_samples (id, run_id, session_id, node_id, wall_seconds, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, ids.New("cost"), runID, sessionID, "local", float64(resumeCopyMS+startupColdMS)/1000, now)
	return sessionID, nil
}

func (s Service) createRuntimeSession(req runtimeplane.CreateSessionRequest) (string, error) {
	if s.Driver != nil {
		return s.Driver.CreateSession(context.Background(), req)
	}
	return "", fmt.Errorf("runtime driver is required")
}

func (s Service) execRuntime(containerID string, command []string, stream bool, stdout, stderr io.Writer) (runtimeplane.ExecResult, error) {
	if s.Driver != nil {
		if stdout != nil || stderr != nil {
			return s.Driver.ExecStream(context.Background(), containerID, command, stdout, stderr)
		}
		return s.Driver.Exec(context.Background(), containerID, command, stream)
	}
	return runtimeplane.ExecResult{}, fmt.Errorf("runtime driver is required")
}

func (s Service) stopRuntime(containerID string) error {
	if s.Driver != nil {
		return s.Driver.Stop(context.Background(), containerID)
	}
	return fmt.Errorf("runtime driver is required")
}

func (s Service) removeRuntime(containerID string) error {
	if s.Driver != nil {
		return s.Driver.Remove(context.Background(), containerID)
	}
	return fmt.Errorf("runtime driver is required")
}

func (s Service) runtimeName() string {
	if s.Driver != nil {
		return s.Driver.Name()
	}
	return ""
}

func (s Service) isDockerRuntime() bool {
	if s.Driver != nil {
		return s.Driver.Name() == "docker"
	}
	return false
}

func templateNameFromTaskPath(taskPath string) string {
	base := filepath.Base(taskPath)
	ext := filepath.Ext(base)
	if ext != "" {
		base = strings.TrimSuffix(base, ext)
	}
	if base == "" || base == "." {
		return "default"
	}
	return base
}
