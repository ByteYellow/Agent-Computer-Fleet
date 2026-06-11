package runtime

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"strings"

	"github.com/byteyellow/agent-computer-fleet/internal/node"
	"github.com/byteyellow/agent-computer-fleet/internal/state"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
)

type DockerDriver struct {
	Runtime *node.DockerRuntime
	Paths   store.Paths
	Version string
}

func NewDockerDriver(paths store.Paths) (*DockerDriver, error) {
	rt, err := node.NewDockerRuntime()
	if err != nil {
		return nil, err
	}
	_, version := dockerStatus()
	return &DockerDriver{Runtime: rt, Paths: paths, Version: version}, nil
}

func (d *DockerDriver) Available() bool {
	return d != nil && d.Runtime != nil
}

func (d *DockerDriver) Name() string { return "docker" }

func (d *DockerDriver) Capabilities() Capabilities { return dockerCapabilities() }

func (d *DockerDriver) CreateSession(ctx context.Context, req CreateSessionRequest) (string, error) {
	return d.Runtime.CreateSession(node.CreateSessionRequest{
		SessionID:         req.SessionID,
		LeaseID:           req.LeaseID,
		RunID:             req.RunID,
		Image:             req.Image,
		WorkspaceHostPath: req.WorkspaceHostPath,
		MemoryMB:          req.MemoryMB,
		CPURequest:        req.CPURequest,
		NetworkMode:       req.NetworkMode,
		ProxyURL:          req.ProxyURL,
		NoProxy:           req.NoProxy,
		DockerNetworkName: req.DockerNetworkName,
	})
}

func (d *DockerDriver) Exec(ctx context.Context, containerID string, command []string, stream bool) (ExecResult, error) {
	return d.Runtime.Exec(containerID, command, stream)
}

func (d *DockerDriver) ExecStream(ctx context.Context, containerID string, command []string, stdout, stderr io.Writer) (ExecResult, error) {
	return d.Runtime.ExecWithWriters(containerID, command, stdout, stderr)
}

func (d *DockerDriver) Interrupt(ctx context.Context, containerID string) error {
	return d.Runtime.Interrupt(containerID)
}

func (d *DockerDriver) Stop(ctx context.Context, containerID string) error {
	return d.Runtime.Stop(containerID)
}

func (d *DockerDriver) Remove(ctx context.Context, containerID string) error {
	return d.Runtime.Remove(containerID)
}

func (d *DockerDriver) CreateDirectorySnapshot(ctx context.Context, src, dst string) (state.Manifest, error) {
	if err := state.CopyDir(src, dst); err != nil {
		return state.Manifest{}, err
	}
	return state.BuildManifest(dst)
}

func (d *DockerDriver) ForkDirectorySnapshot(ctx context.Context, src, dst string) (state.Manifest, error) {
	if err := state.CopyDir(src, dst); err != nil {
		return state.Manifest{}, err
	}
	return state.BuildManifest(dst)
}

func (d *DockerDriver) ResumeDirectorySnapshot(ctx context.Context, src, dst string) (state.Manifest, error) {
	if err := state.CopyDir(src, dst); err != nil {
		return state.Manifest{}, err
	}
	return state.BuildManifest(dst)
}

func (d *DockerDriver) SetCPUWeight(ctx context.Context, containerID string, weight int64) error {
	return d.Runtime.SetCPUWeight(ctx, containerID, weight)
}

func dockerStatus() (bool, string) {
	cmd := exec.Command("docker", "version", "--format", "{{.Server.Version}}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return false, msg
	}
	version := strings.TrimSpace(string(out))
	if version == "" {
		version = "available"
	}
	return true, version
}
