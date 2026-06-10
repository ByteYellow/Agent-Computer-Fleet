package egress

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"

	"github.com/byteyellow/agent-computer-fleet/internal/ids"
	"github.com/byteyellow/agent-computer-fleet/internal/security"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
)

type Service struct {
	DB                *sql.DB
	Paths             store.Paths
	DefaultRunID      string
	DefaultSessionID  string
	DefaultToolCallID string
}

type ProxyInfo struct {
	ID                string
	RunID             string
	SessionID         string
	HostPort          int
	ProxyURL          string
	ContainerProxyURL string
	Mode              string
	NetworkName       string
	ContainerID       string
	PID               int
	Status            string
	CreatedAt         string
	UpdatedAt         string
}

type CredentialSpec struct {
	Name       string
	Host       string
	PathPrefix string
	HeaderName string
	Value      string
}

func (s Service) EnsureProxy() (ProxyInfo, error) {
	return s.ensureHostProxy("", "")
}

func (s Service) EnsureSessionProxy(runID, sessionID string) (ProxyInfo, error) {
	if sessionID == "" {
		return s.ensureHostProxy(runID, sessionID)
	}
	return s.ensureDockerProxy(runID, sessionID)
}

func (s Service) ensureHostProxy(runID, sessionID string) (ProxyInfo, error) {
	if info, err := s.runningProxy(runID, sessionID); err == nil {
		return info, nil
	}
	hostPort, err := freePort()
	if err != nil {
		return ProxyInfo{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	proxyID := ids.New("egress")
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", hostPort)
	containerURL := fmt.Sprintf("http://host.docker.internal:%d", hostPort)
	_, err = s.DB.Exec(`INSERT INTO egress_proxies (id, run_id, session_id, host_port, proxy_url, container_proxy_url, mode, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 'host', 'starting', ?, ?)`, proxyID, runID, sessionID, hostPort, proxyURL, containerURL, now, now)
	if err != nil {
		return ProxyInfo{}, err
	}
	exe, err := os.Executable()
	if err != nil {
		return ProxyInfo{}, err
	}
	logFile, err := os.OpenFile(filepath.Join(s.Paths.Logs, proxyID+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return ProxyInfo{}, err
	}
	defer logFile.Close()
	child := exec.Command(exe, "--data-dir", s.Paths.Root, "egress", "serve", proxyID)
	child.Stdout = logFile
	child.Stderr = logFile
	if err := child.Start(); err != nil {
		return ProxyInfo{}, err
	}
	now = time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`UPDATE egress_proxies SET pid = ?, status = 'running', updated_at = ? WHERE id = ?`, child.Process.Pid, now, proxyID); err != nil {
		return ProxyInfo{}, err
	}
	return s.Inspect(proxyID)
}

func (s Service) ensureDockerProxy(runID, sessionID string) (ProxyInfo, error) {
	if info, err := s.runningProxy(runID, sessionID); err == nil {
		return info, nil
	}
	cli, err := dockerClient()
	if err != nil {
		return ProxyInfo{}, err
	}
	defer cli.Close()
	ctx := context.Background()
	networkName := "acf-egress-net-" + sessionID
	proxyID := ids.New("egress")
	containerName := "acf-egress-" + sessionID
	containerURL := "http://acf-egress:8080"
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`INSERT INTO egress_proxies (id, run_id, session_id, host_port, proxy_url, container_proxy_url, mode, network_name, status, created_at, updated_at)
		VALUES (?, ?, ?, 8080, ?, ?, 'docker-sidecar', ?, 'starting', ?, ?)`, proxyID, runID, sessionID, containerURL, containerURL, networkName, now, now)
	if err != nil {
		return ProxyInfo{}, err
	}
	if _, err := cli.NetworkCreate(ctx, networkName, types.NetworkCreate{
		Driver:   "bridge",
		Internal: true,
		Labels: map[string]string{
			"acf.session_id": sessionID,
			"acf.run_id":     runID,
			"acf.role":       "egress-network",
		},
	}); err != nil && !errdefs.IsConflict(err) {
		return ProxyInfo{}, err
	}
	binaryPath, err := s.ensureLinuxProxyBinary(ctx, cli)
	if err != nil {
		return ProxyInfo{}, err
	}
	dataRoot, err := filepath.Abs(s.Paths.Root)
	if err != nil {
		return ProxyInfo{}, err
	}
	binaryPath, err = filepath.Abs(binaryPath)
	if err != nil {
		return ProxyInfo{}, err
	}
	_ = cli.ContainerRemove(ctx, containerName, types.ContainerRemoveOptions{Force: true})
	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image:      "alpine:3.20",
		Entrypoint: []string{"/usr/local/bin/acfctl"},
		Cmd:        []string{"--data-dir", "/acf-data", "egress", "serve", proxyID, "--listen", "0.0.0.0:8080"},
		Labels: map[string]string{
			"acf.session_id": sessionID,
			"acf.run_id":     runID,
			"acf.proxy_id":   proxyID,
			"acf.role":       "egress-proxy",
		},
	}, &container.HostConfig{
		Mounts: []mount.Mount{
			{Type: mount.TypeBind, Source: dataRoot, Target: "/acf-data"},
			{Type: mount.TypeBind, Source: binaryPath, Target: "/usr/local/bin/acfctl", ReadOnly: true},
		},
	}, nil, nil, containerName)
	if err != nil {
		if !isNoSuchImage(err) {
			return ProxyInfo{}, err
		}
		pull, pullErr := cli.ImagePull(ctx, "alpine:3.20", types.ImagePullOptions{})
		if pullErr != nil {
			return ProxyInfo{}, pullErr
		}
		_, _ = io.Copy(io.Discard, pull)
		_ = pull.Close()
		resp, err = cli.ContainerCreate(ctx, &container.Config{
			Image:      "alpine:3.20",
			Entrypoint: []string{"/usr/local/bin/acfctl"},
			Cmd:        []string{"--data-dir", "/acf-data", "egress", "serve", proxyID, "--listen", "0.0.0.0:8080"},
			Labels: map[string]string{
				"acf.session_id": sessionID,
				"acf.run_id":     runID,
				"acf.proxy_id":   proxyID,
				"acf.role":       "egress-proxy",
			},
		}, &container.HostConfig{
			Mounts: []mount.Mount{
				{Type: mount.TypeBind, Source: dataRoot, Target: "/acf-data"},
				{Type: mount.TypeBind, Source: binaryPath, Target: "/usr/local/bin/acfctl", ReadOnly: true},
			},
		}, nil, nil, containerName)
		if err != nil {
			return ProxyInfo{}, err
		}
	}
	if err := cli.NetworkConnect(ctx, networkName, resp.ID, &network.EndpointSettings{Aliases: []string{"acf-egress"}}); err != nil && !errdefs.IsConflict(err) {
		return ProxyInfo{}, err
	}
	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		return ProxyInfo{}, err
	}
	time.Sleep(750 * time.Millisecond)
	now = time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`UPDATE egress_proxies SET container_id = ?, status = 'running', updated_at = ? WHERE id = ?`, resp.ID, now, proxyID); err != nil {
		return ProxyInfo{}, err
	}
	return s.Inspect(proxyID)
}

func (s Service) Inspect(proxyID string) (ProxyInfo, error) {
	var info ProxyInfo
	err := s.DB.QueryRow(`SELECT id, COALESCE(run_id, ''), COALESCE(session_id, ''), host_port, proxy_url, container_proxy_url, COALESCE(mode, 'host'), COALESCE(network_name, ''), COALESCE(container_id, ''), pid, status, created_at, updated_at FROM egress_proxies WHERE id = ?`, proxyID).
		Scan(&info.ID, &info.RunID, &info.SessionID, &info.HostPort, &info.ProxyURL, &info.ContainerProxyURL, &info.Mode, &info.NetworkName, &info.ContainerID, &info.PID, &info.Status, &info.CreatedAt, &info.UpdatedAt)
	return info, err
}

func (s Service) Status() ([]ProxyInfo, error) {
	rows, err := s.DB.Query(`SELECT id, COALESCE(run_id, ''), COALESCE(session_id, ''), host_port, proxy_url, container_proxy_url, COALESCE(mode, 'host'), COALESCE(network_name, ''), COALESCE(container_id, ''), pid, status, created_at, updated_at FROM egress_proxies ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var proxies []ProxyInfo
	for rows.Next() {
		var info ProxyInfo
		if err := rows.Scan(&info.ID, &info.RunID, &info.SessionID, &info.HostPort, &info.ProxyURL, &info.ContainerProxyURL, &info.Mode, &info.NetworkName, &info.ContainerID, &info.PID, &info.Status, &info.CreatedAt, &info.UpdatedAt); err != nil {
			return nil, err
		}
		proxies = append(proxies, info)
	}
	return proxies, rows.Err()
}

func (s Service) Close(proxyID string) error {
	info, err := s.Inspect(proxyID)
	if err != nil {
		return err
	}
	if info.PID > 0 {
		if process, err := os.FindProcess(info.PID); err == nil {
			_ = process.Signal(syscall.SIGTERM)
		}
	}
	if info.ContainerID != "" || info.NetworkName != "" {
		if cli, err := dockerClient(); err == nil {
			defer cli.Close()
			ctx := context.Background()
			if info.ContainerID != "" {
				_ = cli.ContainerRemove(ctx, info.ContainerID, types.ContainerRemoveOptions{Force: true})
			}
			if info.NetworkName != "" {
				_ = cli.NetworkRemove(ctx, info.NetworkName)
			}
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`UPDATE egress_proxies SET status = 'closed', updated_at = ? WHERE id = ?`, now, proxyID)
	return err
}

func (s Service) CloseForSession(sessionID string) error {
	rows, err := s.DB.Query(`SELECT id FROM egress_proxies WHERE session_id = ? AND status = 'running'`, sessionID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var idsToClose []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		idsToClose = append(idsToClose, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range idsToClose {
		if err := s.Close(id); err != nil {
			return err
		}
	}
	return nil
}

func (s Service) AllowHost(host string) error {
	host = normalizeHost(host)
	if host == "" {
		return fmt.Errorf("host is required")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.DB.Exec(`INSERT OR REPLACE INTO egress_allowlist (host, created_at) VALUES (?, ?)`, host, now)
	return err
}

func (s Service) InjectCredential(runID, sessionID string, spec CredentialSpec) error {
	if spec.Name == "" || spec.Host == "" || spec.Value == "" {
		return fmt.Errorf("credential name, host, and value are required")
	}
	if spec.PathPrefix == "" {
		spec.PathPrefix = "/"
	}
	if spec.HeaderName == "" {
		spec.HeaderName = "Authorization"
	}
	secretRef := ids.New("secret")
	if err := os.MkdirAll(s.Paths.Secrets, 0o700); err != nil {
		return err
	}
	secretPath := filepath.Join(s.Paths.Secrets, secretRef)
	if err := os.WriteFile(secretPath, []byte(spec.Value), 0o600); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.DB.Exec(`INSERT INTO egress_credentials (id, name, host, path_prefix, header_name, secret_ref, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, ids.New("cred"), spec.Name, normalizeHost(spec.Host), spec.PathPrefix, spec.HeaderName, secretRef, now)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{
		"credential_name": spec.Name,
		"host":            normalizeHost(spec.Host),
		"path_prefix":     spec.PathPrefix,
		"header_name":     spec.HeaderName,
		"result_ref":      "secret:" + secretRef,
		"redacted":        true,
	})
	_, err = s.DB.Exec(`INSERT INTO events (id, run_id, session_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, 'credential_proxy', 'credential_inject', ?, ?)`, ids.New("evt"), runID, sessionID, string(payload), now)
	return err
}

func (s Service) Serve(proxyID string) error {
	return s.ServeAt(proxyID, "")
}

func (s Service) ServeAt(proxyID, listenAddr string) error {
	info, err := s.Inspect(proxyID)
	if err != nil {
		return err
	}
	if listenAddr == "" {
		listenAddr = "0.0.0.0:" + strconv.Itoa(info.HostPort)
	}
	server := &http.Server{
		Addr:    listenAddr,
		Handler: http.HandlerFunc(Service{DB: s.DB, Paths: s.Paths, DefaultRunID: info.RunID, DefaultSessionID: info.SessionID}.handleProxy),
	}
	return server.ListenAndServe()
}

func (s Service) Check(runID, sessionID, dstIP, host string) (security.DecisionRecord, error) {
	payload := map[string]any{"dst_ip": dstIP, "host": host}
	raw, _ := json.Marshal(payload)
	return security.EvaluateAndPersist(s.DB, security.Event{
		Source:    "egress_proxy",
		EventType: "network_connect",
		RunID:     runID,
		SessionID: sessionID,
		DstIP:     dstIP,
		Args:      []string{host},
	}, string(raw))
}

func (s Service) handleProxy(w http.ResponseWriter, r *http.Request) {
	runID := r.Header.Get("X-ACF-Run-ID")
	sessionID := r.Header.Get("X-ACF-Session-ID")
	toolCallID := r.Header.Get("X-ACF-Tool-Call-ID")
	if runID == "" {
		runID = s.DefaultRunID
	}
	if sessionID == "" {
		sessionID = s.DefaultSessionID
	}
	if toolCallID == "" {
		toolCallID = s.DefaultToolCallID
	}
	targetHost := proxyRequestHost(r)
	decision, statusCode, reason := s.authorize(runID, sessionID, toolCallID, targetHost)
	if decision.Decision != "allow" {
		http.Error(w, reason, statusCode)
		return
	}
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r, targetHost)
		return
	}
	s.handleHTTP(w, r, targetHost)
}

func (s Service) authorize(runID, sessionID, toolCallID, targetHost string) (security.DecisionRecord, int, string) {
	host := normalizeHost(targetHost)
	dstIP := host
	if net.ParseIP(host) == nil {
		if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
			dstIP = ips[0].String()
		}
	}
	allowlisted := s.hostAllowed(host)
	policyDecision := security.DefaultEngine().Evaluate(security.Event{DstIP: dstIP, Args: []string{host}})
	eventType := "network_connect"
	if !allowlisted || policyDecision.Decision != "allow" {
		eventType = "network_deny"
	}
	payload, _ := json.Marshal(map[string]any{
		"host":     host,
		"dst_ip":   dstIP,
		"redacted": true,
	})
	event := security.Event{
		Source:     "egress_proxy",
		EventType:  eventType,
		RunID:      runID,
		SessionID:  sessionID,
		ToolCallID: toolCallID,
		DstIP:      dstIP,
		Args:       []string{host},
	}
	var record security.DecisionRecord
	var err error
	if policyDecision.Decision != "allow" {
		record, err = security.PersistDecision(s.DB, event, string(payload), policyDecision)
	} else if !allowlisted {
		record, err = security.PersistDecision(s.DB, event, string(payload), security.Decision{Decision: "deny", Reason: "host not in allowlist"})
	} else {
		record, err = security.PersistDecision(s.DB, event, string(payload), policyDecision)
	}
	if err != nil {
		return security.DecisionRecord{Decision: "deny", Reason: err.Error()}, http.StatusBadGateway, err.Error()
	}
	if record.Decision != "allow" {
		return record, http.StatusForbidden, record.Reason
	}
	return record, http.StatusOK, "allow"
}

func (s Service) handleHTTP(w http.ResponseWriter, r *http.Request, targetHost string) {
	target := r.URL
	if !target.IsAbs() {
		target = &url.URL{Scheme: "http", Host: targetHost, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Header = r.Header.Clone()
	removeProxyHeaders(req.Header)
	_ = s.injectCredential(req, normalizeHost(target.Host))
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s Service) handleConnect(w http.ResponseWriter, r *http.Request, targetHost string) {
	dest, err := net.DialTimeout("tcp", targetHost, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = dest.Close()
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		_ = dest.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go proxyCopy(dest, client)
	go proxyCopy(client, dest)
}

func (s Service) injectCredential(req *http.Request, host string) error {
	rows, err := s.DB.Query(`SELECT name, path_prefix, header_name, secret_ref FROM egress_credentials WHERE host = ? ORDER BY created_at DESC`, host)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, pathPrefix, headerName, secretRef string
		if err := rows.Scan(&name, &pathPrefix, &headerName, &secretRef); err != nil {
			return err
		}
		if !strings.HasPrefix(req.URL.Path, pathPrefix) {
			continue
		}
		value, err := os.ReadFile(filepath.Join(s.Paths.Secrets, secretRef))
		if err != nil {
			return err
		}
		req.Header.Set(headerName, strings.TrimSpace(string(value)))
		return nil
	}
	return rows.Err()
}

func (s Service) hostAllowed(host string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	var count int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM egress_allowlist`).Scan(&count)
	if count == 0 {
		return true
	}
	var allowed int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM egress_allowlist WHERE host = ?`, host).Scan(&allowed)
	return allowed > 0
}

func (s Service) runningProxy(runID, sessionID string) (ProxyInfo, error) {
	var info ProxyInfo
	query := `SELECT id, COALESCE(run_id, ''), COALESCE(session_id, ''), host_port, proxy_url, container_proxy_url, COALESCE(mode, 'host'), COALESCE(network_name, ''), COALESCE(container_id, ''), pid, status, created_at, updated_at
		FROM egress_proxies WHERE status = 'running'`
	args := []any{}
	if sessionID != "" {
		query += ` AND session_id = ?`
		args = append(args, sessionID)
	} else {
		query += ` AND session_id = ''`
	}
	query += ` ORDER BY created_at DESC LIMIT 1`
	err := s.DB.QueryRow(query, args...).
		Scan(&info.ID, &info.RunID, &info.SessionID, &info.HostPort, &info.ProxyURL, &info.ContainerProxyURL, &info.Mode, &info.NetworkName, &info.ContainerID, &info.PID, &info.Status, &info.CreatedAt, &info.UpdatedAt)
	if err != nil {
		return ProxyInfo{}, err
	}
	if info.ContainerID != "" {
		if cli, err := dockerClient(); err == nil {
			defer cli.Close()
			if inspect, err := cli.ContainerInspect(context.Background(), info.ContainerID); err == nil && inspect.State != nil && inspect.State.Running {
				return info, nil
			}
		}
		return ProxyInfo{}, fmt.Errorf("no running egress proxy")
	}
	if info.PID > 0 {
		if process, err := os.FindProcess(info.PID); err == nil {
			if err := process.Signal(syscall.Signal(0)); err == nil {
				return info, nil
			}
		}
	}
	return ProxyInfo{}, fmt.Errorf("no running egress proxy")
}

func (s Service) ensureLinuxProxyBinary(ctx context.Context, cli *client.Client) (string, error) {
	version, err := cli.ServerVersion(ctx)
	if err != nil {
		return "", err
	}
	arch := dockerGoArch(version.Arch)
	out := filepath.Join(s.Paths.Artifacts, "acfctl-linux-"+arch)
	if st, err := os.Stat(out); err == nil && st.Size() > 0 {
		return out, nil
	}
	root, err := repoRoot()
	if err != nil {
		return "", err
	}
	cmd := exec.Command("go", "build", "-o", out, "./cmd/acfctl")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build linux egress proxy binary: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if err := os.Chmod(out, 0o755); err != nil {
		return "", err
	}
	return out, nil
}

func dockerClient() (*client.Client, error) {
	opts := []client.Opt{client.FromEnv, client.WithAPIVersionNegotiation()}
	if os.Getenv("DOCKER_HOST") == "" {
		if home, err := os.UserHomeDir(); err == nil {
			desktopSocket := filepath.Join(home, ".docker", "run", "docker.sock")
			if _, err := os.Stat(desktopSocket); err == nil {
				opts = append(opts, client.WithHost("unix://"+desktopSocket))
			}
		}
	}
	return client.NewClientWithOpts(opts...)
}

func dockerGoArch(arch string) string {
	arch = strings.ToLower(arch)
	switch {
	case strings.Contains(arch, "arm64"), strings.Contains(arch, "aarch64"):
		return "arm64"
	case strings.Contains(arch, "arm"):
		return "arm"
	case strings.Contains(arch, "386"):
		return "386"
	default:
		return "amd64"
	}
}

func repoRoot() (string, error) {
	candidates := []string{}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, cwd)
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(exe))
	}
	for _, candidate := range candidates {
		for {
			if isRepoRoot(candidate) {
				return candidate, nil
			}
			next := filepath.Dir(candidate)
			if next == candidate {
				break
			}
			candidate = next
		}
	}
	return "", fmt.Errorf("could not locate repository root for linux proxy build on %s/%s", runtime.GOOS, runtime.GOARCH)
}

func isRepoRoot(path string) bool {
	data, err := os.ReadFile(filepath.Join(path, "go.mod"))
	return err == nil && strings.Contains(string(data), "module github.com/byteyellow/agent-computer-fleet")
}

func isNoSuchImage(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "No such image") || strings.Contains(msg, "not found")
}

func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func proxyRequestHost(r *http.Request) string {
	if r.Method == http.MethodConnect {
		return r.Host
	}
	if r.URL.Host != "" {
		return r.URL.Host
	}
	return r.Host
}

func normalizeHost(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil {
			value = parsed.Host
		}
	}
	host, _, err := net.SplitHostPort(value)
	if err == nil {
		return host
	}
	return strings.Trim(value, "[]")
}

func removeProxyHeaders(header http.Header) {
	for _, key := range []string{"Proxy-Connection", "Proxy-Authorization", "X-ACF-Run-ID", "X-ACF-Session-ID", "X-ACF-Tool-Call-ID"} {
		header.Del(key)
	}
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func proxyCopy(dst net.Conn, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
}
