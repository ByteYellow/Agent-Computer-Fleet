package ports

import (
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/ids"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
)

type Service struct {
	DB    *sql.DB
	Paths store.Paths
}

type PortInfo struct {
	ID            string
	SessionID     string
	RunID         string
	ContainerID   string
	ContainerPort int
	HostPort      int
	PreviewURL    string
	PID           int
	Status        string
	CreatedAt     string
	UpdatedAt     string
}

func (s Service) Expose(sessionID string, containerPort int) (PortInfo, error) {
	var runID, containerID string
	if err := s.DB.QueryRow(`SELECT run_id, COALESCE(container_id, '') FROM sessions WHERE id = ?`, sessionID).Scan(&runID, &containerID); err != nil {
		return PortInfo{}, err
	}
	if containerID == "" {
		return PortInfo{}, fmt.Errorf("session %s has no container id", sessionID)
	}
	hostPort, err := freePort()
	if err != nil {
		return PortInfo{}, err
	}
	portID := ids.New("port")
	previewURL := fmt.Sprintf("http://127.0.0.1:%d", hostPort)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`INSERT INTO ports (id, session_id, run_id, container_id, container_port, host_port, preview_url, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'starting', ?, ?)`, portID, sessionID, runID, containerID, containerPort, hostPort, previewURL, now, now)
	if err != nil {
		return PortInfo{}, err
	}
	exe, err := os.Executable()
	if err != nil {
		return PortInfo{}, err
	}
	child := exec.Command(exe, "--data-dir", s.Paths.Root, "port", "serve", portID)
	logFile, err := os.OpenFile(fmt.Sprintf("%s/%s.log", s.Paths.Logs, portID), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return PortInfo{}, err
	}
	defer logFile.Close()
	child.Stdout = logFile
	child.Stderr = logFile
	if err := child.Start(); err != nil {
		return PortInfo{}, err
	}
	now = time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`UPDATE ports SET pid = ?, status = 'running', updated_at = ? WHERE id = ?`, child.Process.Pid, now, portID); err != nil {
		return PortInfo{}, err
	}
	_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, session_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, 'acfctl', 'port_expose', ?, ?)`, ids.New("evt"), runID, sessionID, fmt.Sprintf(`{"port_id":%q,"container_port":%d,"preview_url":%q}`, portID, containerPort, previewURL), now)
	return s.Inspect(portID)
}

func (s Service) List() ([]PortInfo, error) {
	rows, err := s.DB.Query(`SELECT id, session_id, run_id, container_id, container_port, host_port, preview_url, pid, status, created_at, updated_at FROM ports ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ports []PortInfo
	for rows.Next() {
		var info PortInfo
		if err := rows.Scan(&info.ID, &info.SessionID, &info.RunID, &info.ContainerID, &info.ContainerPort, &info.HostPort, &info.PreviewURL, &info.PID, &info.Status, &info.CreatedAt, &info.UpdatedAt); err != nil {
			return nil, err
		}
		ports = append(ports, info)
	}
	return ports, rows.Err()
}

func (s Service) Inspect(portID string) (PortInfo, error) {
	var info PortInfo
	err := s.DB.QueryRow(`SELECT id, session_id, run_id, container_id, container_port, host_port, preview_url, pid, status, created_at, updated_at FROM ports WHERE id = ?`, portID).Scan(&info.ID, &info.SessionID, &info.RunID, &info.ContainerID, &info.ContainerPort, &info.HostPort, &info.PreviewURL, &info.PID, &info.Status, &info.CreatedAt, &info.UpdatedAt)
	return info, err
}

func (s Service) Close(portID string) error {
	info, err := s.Inspect(portID)
	if err != nil {
		return err
	}
	if info.PID > 0 {
		if process, err := os.FindProcess(info.PID); err == nil {
			_ = process.Signal(syscall.SIGTERM)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`UPDATE ports SET status = 'closed', updated_at = ? WHERE id = ?`, now, portID)
	return err
}

func (s Service) Serve(portID string) error {
	info, err := s.Inspect(portID)
	if err != nil {
		return err
	}
	addr := "127.0.0.1:" + strconv.Itoa(info.HostPort)
	server := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := fetchFromContainer(info.ContainerID, info.ContainerPort, r.URL.RequestURI())
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			_, _ = w.Write(body)
		}),
	}
	return server.ListenAndServe()
}

func fetchFromContainer(containerID string, port int, requestURI string) ([]byte, error) {
	if requestURI == "" {
		requestURI = "/"
	}
	target := fmt.Sprintf("http://127.0.0.1:%d%s", port, requestURI)
	cmd := exec.Command("docker", "exec", containerID, "sh", "-lc", "wget -qO- "+shellQuote(target)+" || curl -fsSL "+shellQuote(target))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("container fetch failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func ReadAll(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
