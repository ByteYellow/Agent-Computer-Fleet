package launch

import (
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// sensorProcess is the privileged system-side half of a launch run: a child
// `agentprov sensor stream` that loads the eBPF probes and ingests+correlates
// kernel events into the same store, keyed by the agent's cgroup. Running it as
// a subprocess (rather than in-process) gives launch a clean lifecycle -- it is
// stopped with SIGTERM at seal time -- and reuses the exact supervised-capture
// path the sensor already ships.
type sensorProcess struct {
	cmd     *exec.Cmd
	done    chan struct{}
	stopped bool
}

// startSensor launches the kernel sensor when the host can run it and returns
// the process (or nil), the resolved system tier ("kernel"|"none"), and an
// honest reason when it degrades. The reason is what the operator sees, so it
// names the actual blocker (wrong OS, missing CAP_BPF) rather than a generic
// failure.
func startSensor(selfExe, dataDir string, stderr io.Writer) (*sensorProcess, string, string) {
	if runtime.GOOS != "linux" {
		return nil, "none", fmt.Sprintf("kernel telemetry requires Linux (this host is %s)", runtime.GOOS)
	}

	args := []string{"sensor", "stream"}
	if dataDir != "" {
		args = append([]string{"--data-dir", dataDir}, args...)
	}
	cmd := exec.Command(selfExe, args...)
	// New process group so a Ctrl-C on the launch group does not race our own
	// SIGTERM; we own this child's lifecycle explicitly.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, "none", "cannot capture sensor stderr: " + err.Error()
	}
	if err := cmd.Start(); err != nil {
		return nil, "none", "sensor failed to start: " + err.Error()
	}

	var sink strings.Builder
	ready := make(chan struct{}, 1)
	go scanReady(stderrPipe, ready, &sink)

	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()

	// Readiness: the probes attach synchronously in the child; either the ready
	// banner appears, or the child exits early (no CAP_BPF/root) -- in which
	// case we degrade with its captured stderr. The timeout is a backstop.
	sp := &sensorProcess{cmd: cmd, done: done}
	select {
	case <-ready:
		return sp, "kernel", ""
	case <-done:
		reason := strings.TrimSpace(sink.String())
		reason = lastLine(reason)
		if reason == "" {
			reason = "sensor exited before attaching (needs root or CAP_BPF+CAP_PERFMON)"
		}
		return nil, "none", "no kernel telemetry: " + reason
	case <-time.After(3 * time.Second):
		// Still alive but no banner: probes likely attached; proceed. A truly
		// stuck sensor is stopped at seal time regardless.
		return sp, "kernel", ""
	}
}

func (s *sensorProcess) stop() {
	if s == nil || s.stopped {
		return
	}
	s.stopped = true
	if s.cmd.Process != nil {
		// SIGTERM: the sensor traps it, closes its ringbuf, flushes, and exits.
		_ = s.cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		if s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
		}
	}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" {
			return t
		}
	}
	return ""
}
