package runtime

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

type Backend struct {
	Name      string
	Status    string
	Available bool
	Selected  bool
	Exec      string
	Snapshot  string
	Network   string
	Isolation string
	Telemetry string
	Notes     string
}

func List() []Backend {
	dockerAvailable, dockerNotes := dockerStatus()
	return []Backend{
		{
			Name:      "docker",
			Status:    status(dockerAvailable),
			Available: dockerAvailable,
			Selected:  true,
			Exec:      "docker exec",
			Snapshot:  "directory workspace snapshot",
			Network:   "docker network mode + local preview proxy",
			Isolation: "container namespace/cgroup/seccomp baseline",
			Telemetry: "labels, exec metadata, wrapper events, docker stats",
			Notes:     dockerNotes,
		},
		{
			Name:      "gvisor",
			Status:    "planned",
			Available: false,
			Exec:      "runsc exec",
			Snapshot:  "directory snapshot first, runtime snapshot later",
			Network:   "sandboxed netstack + egress proxy",
			Isolation: "user-space kernel sandbox",
			Telemetry: "runtime events + policy correlation",
			Notes:     "registered extension point; adapter not implemented in v1",
		},
		{
			Name:      "firecracker",
			Status:    "planned",
			Available: false,
			Exec:      "agent process inside microVM",
			Snapshot:  "disk snapshot first, memory snapshot later",
			Network:   "tap/egress proxy",
			Isolation: "KVM microVM",
			Telemetry: "node agent + VM boundary events",
			Notes:     "registered extension point; adapter not implemented in v1",
		},
		{
			Name:      "bubblewrap",
			Status:    "planned",
			Available: false,
			Exec:      "bwrap process exec",
			Snapshot:  "directory snapshot",
			Network:   "host/network namespace policy",
			Isolation: "Linux namespaces + bind mounts",
			Telemetry: "wrapper events + process accounting",
			Notes:     "registered extension point; adapter not implemented in v1",
		},
	}
}

func Inspect(name string) (Backend, error) {
	for _, backend := range List() {
		if backend.Name == name {
			return backend, nil
		}
	}
	return Backend{}, fmt.Errorf("runtime backend %q is not registered", name)
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
	return true, "server=" + version
}

func status(available bool) string {
	if available {
		return "available"
	}
	return "unavailable"
}
