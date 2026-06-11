package node

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/pkg/stdcopy"
)

type DockerRuntime struct {
	Client *client.Client
}

func NewDockerRuntime() (*DockerRuntime, error) {
	opts := []client.Opt{client.FromEnv, client.WithAPIVersionNegotiation()}
	if os.Getenv("DOCKER_HOST") == "" {
		if home, err := os.UserHomeDir(); err == nil {
			desktopSocket := filepath.Join(home, ".docker", "run", "docker.sock")
			if _, err := os.Stat(desktopSocket); err == nil {
				opts = append(opts, client.WithHost("unix://"+desktopSocket))
			}
		}
	}
	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, err
	}
	return &DockerRuntime{Client: cli}, nil
}

func (r *DockerRuntime) CreateSession(req CreateSessionRequest) (string, error) {
	ctx := context.Background()
	if req.Image == "" {
		return "", fmt.Errorf("task image is required")
	}
	hostCfg := &container.HostConfig{
		Mounts: []mount.Mount{{
			Type:   mount.TypeBind,
			Source: req.WorkspaceHostPath,
			Target: "/workspace",
		}},
	}
	if req.DockerNetworkName != "" {
		hostCfg.NetworkMode = container.NetworkMode(req.DockerNetworkName)
	}
	if req.MemoryMB > 0 {
		hostCfg.Resources.Memory = req.MemoryMB * 1024 * 1024
	}
	cfg := &container.Config{
		Image:      req.Image,
		WorkingDir: "/workspace",
		Tty:        false,
		OpenStdin:  true,
		Cmd:        []string{"sleep", "infinity"},
		Env:        proxyEnv(req.ProxyURL, req.NoProxy),
		Labels: map[string]string{
			"acf.session_id": req.SessionID,
			"acf.lease_id":   req.LeaseID,
			"acf.run_id":     req.RunID,
		},
	}
	resp, err := r.Client.ContainerCreate(ctx, cfg, hostCfg, nil, nil, "acf-"+req.SessionID)
	if err != nil {
		if !isNoSuchImage(err) {
			return "", err
		}
		pull, pullErr := r.Client.ImagePull(ctx, req.Image, types.ImagePullOptions{})
		if pullErr != nil {
			return "", pullErr
		}
		_, _ = io.Copy(io.Discard, pull)
		_ = pull.Close()
		resp, err = r.Client.ContainerCreate(ctx, cfg, hostCfg, nil, nil, "acf-"+req.SessionID)
		if err != nil {
			return "", err
		}
	}
	if err := r.Client.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		return "", err
	}
	return resp.ID, nil
}

func (r *DockerRuntime) Exec(containerID string, command []string, stream bool) (ExecResult, error) {
	stdout := io.Discard
	stderr := io.Discard
	if stream {
		stdout = os.Stdout
		stderr = os.Stderr
	}
	return r.ExecWithWriters(containerID, command, stdout, stderr)
}

func (r *DockerRuntime) ExecWithWriters(containerID string, command []string, stdout, stderr io.Writer) (ExecResult, error) {
	ctx := context.Background()
	resp, err := r.Client.ContainerExecCreate(ctx, containerID, types.ExecConfig{
		Cmd:          command,
		AttachStdout: true,
		AttachStderr: true,
		WorkingDir:   "/workspace",
	})
	if err != nil {
		return ExecResult{}, err
	}
	attach, err := r.Client.ContainerExecAttach(ctx, resp.ID, types.ExecStartCheck{})
	if err != nil {
		return ExecResult{ExecID: resp.ID}, err
	}
	defer attach.Close()
	if stdout != nil || stderr != nil {
		if stdout == nil {
			stdout = io.Discard
		}
		if stderr == nil {
			stderr = io.Discard
		}
		_, err = stdcopy.StdCopy(stdout, stderr, attach.Reader)
	} else {
		_, err = io.Copy(io.Discard, attach.Reader)
	}
	if err != nil {
		return ExecResult{ExecID: resp.ID}, err
	}
	inspect, err := r.Client.ContainerExecInspect(ctx, resp.ID)
	if err != nil {
		return ExecResult{ExecID: resp.ID}, err
	}
	result := ExecResult{ExecID: resp.ID, ExitCode: inspect.ExitCode}
	if inspect.ExitCode != 0 {
		return result, fmt.Errorf("exec exited with code %d", inspect.ExitCode)
	}
	return result, nil
}

func (r *DockerRuntime) Interrupt(containerID string) error {
	return r.Client.ContainerKill(context.Background(), containerID, "SIGTERM")
}

func (r *DockerRuntime) SetCPUWeight(ctx context.Context, containerID string, weight int64) error {
	if weight < 2 {
		weight = 2
	}
	if weight > 262144 {
		weight = 262144
	}
	_, err := r.Client.ContainerUpdate(ctx, containerID, container.UpdateConfig{
		Resources: container.Resources{
			CPUShares: weight,
		},
	})
	return err
}

func (r *DockerRuntime) Stop(containerID string) error {
	err := r.Client.ContainerStop(context.Background(), containerID, container.StopOptions{})
	if errdefs.IsNotFound(err) {
		return nil
	}
	return err
}

func (r *DockerRuntime) Remove(containerID string) error {
	err := r.Client.ContainerRemove(context.Background(), containerID, types.ContainerRemoveOptions{Force: true})
	if errdefs.IsNotFound(err) {
		return nil
	}
	return err
}

func proxyEnv(proxyURL, noProxy string) []string {
	if proxyURL == "" {
		return nil
	}
	if noProxy == "" {
		noProxy = "localhost,127.0.0.1,::1"
	}
	return []string{
		"HTTP_PROXY=" + proxyURL,
		"http_proxy=" + proxyURL,
		"HTTPS_PROXY=" + proxyURL,
		"https_proxy=" + proxyURL,
		"ALL_PROXY=" + proxyURL,
		"all_proxy=" + proxyURL,
		"NO_PROXY=" + noProxy,
		"no_proxy=" + noProxy,
		"ACF_EGRESS_PROXY=" + proxyURL,
	}
}

func isNoSuchImage(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "No such image") || strings.Contains(msg, "not found")
}
