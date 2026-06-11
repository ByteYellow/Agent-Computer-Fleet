package runtime

import (
	"context"
	"fmt"
	"io"

	"github.com/byteyellow/agent-computer-fleet/internal/node"
	"github.com/byteyellow/agent-computer-fleet/internal/state"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
)

type Capabilities struct {
	Exec               bool
	Stop               bool
	Pause              bool
	Resume             bool
	Snapshot           bool
	Fork               bool
	MemorySnapshot     bool
	CPUWeight          bool
	FilesystemSnapshot string
	MemorySnapshotType string
	ResumeLatencyClass string
	IsolationLevel     string
	QuotaSupport       string
	NetworkPolicy      string
	TelemetryBinding   []string
}

type Backend struct {
	Name         string
	Status       string
	Available    bool
	Selected     bool
	Capabilities Capabilities
	Exec         string
	Snapshot     string
	Network      string
	Isolation    string
	Telemetry    string
	Notes        string
}

type CreateSessionRequest struct {
	SessionID         string
	LeaseID           string
	RunID             string
	Image             string
	WorkspaceHostPath string
	MemoryMB          int64
	CPURequest        float64
	NetworkMode       string
	ProxyURL          string
	NoProxy           string
	DockerNetworkName string
}

type ExecResult = node.ExecResult

type Driver interface {
	Name() string
	Capabilities() Capabilities
	CreateSession(context.Context, CreateSessionRequest) (string, error)
	Exec(context.Context, string, []string, bool) (ExecResult, error)
	ExecStream(context.Context, string, []string, io.Writer, io.Writer) (ExecResult, error)
	Interrupt(context.Context, string) error
	Stop(context.Context, string) error
	Remove(context.Context, string) error
	CreateDirectorySnapshot(context.Context, string, string) (state.Manifest, error)
	ForkDirectorySnapshot(context.Context, string, string) (state.Manifest, error)
	ResumeDirectorySnapshot(context.Context, string, string) (state.Manifest, error)
	SetCPUWeight(context.Context, string, int64) error
}

func NewDriver(name string, paths store.Paths) (Driver, error) {
	switch name {
	case "", "docker":
		return NewDockerDriver(paths)
	case "gvisor", "firecracker", "bubblewrap":
		return StubDriver{NameValue: name}, nil
	default:
		return nil, fmt.Errorf("runtime backend %q is not registered", name)
	}
}

func List(paths store.Paths) []Backend {
	dockerDriver, dockerErr := NewDockerDriver(paths)
	dockerAvailable := dockerErr == nil && dockerDriver.Available()
	dockerNotes := "available"
	if dockerErr != nil {
		dockerNotes = dockerErr.Error()
	}
	if dockerAvailable && dockerDriver.Version != "" {
		dockerNotes = "server=" + dockerDriver.Version
	}
	return []Backend{
		{
			Name:         "docker",
			Status:       status(dockerAvailable),
			Available:    dockerAvailable,
			Selected:     true,
			Capabilities: dockerCapabilities(),
			Exec:         "docker exec",
			Snapshot:     "directory snapshot/fork/resume",
			Network:      "session internal bridge + egress sidecar",
			Isolation:    "container namespace/cgroup/seccomp baseline",
			Telemetry:    "labels, exec metadata, wrapper events, docker stats",
			Notes:        dockerNotes,
		},
		stubBackend("gvisor", "runsc adapter planned; capability-gated false"),
		stubBackend("firecracker", "microVM adapter planned; memory snapshot not implemented"),
		stubBackend("bubblewrap", "process sandbox adapter planned; capability-gated false"),
	}
}

func Inspect(paths store.Paths, name string) (Backend, error) {
	for _, backend := range List(paths) {
		if backend.Name == name {
			return backend, nil
		}
	}
	return Backend{}, fmt.Errorf("runtime backend %q is not registered", name)
}

func dockerCapabilities() Capabilities {
	return Capabilities{
		Exec:               true,
		Stop:               true,
		Pause:              false,
		Snapshot:           true,
		Fork:               true,
		Resume:             true,
		MemorySnapshot:     false,
		CPUWeight:          true,
		FilesystemSnapshot: "copy",
		MemorySnapshotType: "none",
		ResumeLatencyClass: "cold",
		IsolationLevel:     "container",
		QuotaSupport:       "cgroup",
		NetworkPolicy:      "proxy",
		TelemetryBinding:   []string{"label", "container_id"},
	}
}

func stubBackend(name, notes string) Backend {
	return Backend{
		Name:      name,
		Status:    "planned",
		Available: false,
		Capabilities: Capabilities{
			Exec:               false,
			Stop:               false,
			Pause:              false,
			Snapshot:           false,
			Fork:               false,
			Resume:             false,
			MemorySnapshot:     false,
			CPUWeight:          false,
			FilesystemSnapshot: "none",
			MemorySnapshotType: "none",
			ResumeLatencyClass: "none",
			IsolationLevel:     "unknown",
			QuotaSupport:       "none",
			NetworkPolicy:      "none",
			TelemetryBinding:   nil,
		},
		Notes: notes,
	}
}

func status(available bool) string {
	if available {
		return "available"
	}
	return "unavailable"
}

type StubDriver struct {
	NameValue string
}

func (d StubDriver) Name() string { return d.NameValue }
func (d StubDriver) Capabilities() Capabilities {
	return Capabilities{}
}
func (d StubDriver) CreateSession(context.Context, CreateSessionRequest) (string, error) {
	return "", fmt.Errorf("runtime backend %q is not implemented", d.NameValue)
}
func (d StubDriver) Exec(context.Context, string, []string, bool) (ExecResult, error) {
	return ExecResult{}, fmt.Errorf("runtime backend %q is not implemented", d.NameValue)
}
func (d StubDriver) ExecStream(context.Context, string, []string, io.Writer, io.Writer) (ExecResult, error) {
	return ExecResult{}, fmt.Errorf("runtime backend %q is not implemented", d.NameValue)
}
func (d StubDriver) Interrupt(context.Context, string) error {
	return fmt.Errorf("runtime backend %q is not implemented", d.NameValue)
}
func (d StubDriver) Stop(context.Context, string) error {
	return fmt.Errorf("runtime backend %q is not implemented", d.NameValue)
}
func (d StubDriver) Remove(context.Context, string) error {
	return fmt.Errorf("runtime backend %q is not implemented", d.NameValue)
}
func (d StubDriver) CreateDirectorySnapshot(context.Context, string, string) (state.Manifest, error) {
	return state.Manifest{}, fmt.Errorf("runtime backend %q does not support directory snapshots", d.NameValue)
}
func (d StubDriver) ForkDirectorySnapshot(context.Context, string, string) (state.Manifest, error) {
	return state.Manifest{}, fmt.Errorf("runtime backend %q does not support fork", d.NameValue)
}
func (d StubDriver) ResumeDirectorySnapshot(context.Context, string, string) (state.Manifest, error) {
	return state.Manifest{}, fmt.Errorf("runtime backend %q does not support resume", d.NameValue)
}
func (d StubDriver) SetCPUWeight(context.Context, string, int64) error {
	return fmt.Errorf("runtime backend %q does not support CPU weight control", d.NameValue)
}
