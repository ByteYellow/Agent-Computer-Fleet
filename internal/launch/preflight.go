package launch

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// CheckStatus is the operator-facing state of one launch preflight check.
type CheckStatus string

const (
	CheckPass CheckStatus = "pass"
	CheckWarn CheckStatus = "warn"
	CheckFail CheckStatus = "fail"
	CheckSkip CheckStatus = "skip"
)

// Check is one launch prerequisite or degradation check.
type Check struct {
	Name   string      `json:"name"`
	Status CheckStatus `json:"status"`
	Detail string      `json:"detail"`
	Fix    string      `json:"fix,omitempty"`
}

// PreflightReport is the structured launch readiness report.
type PreflightReport struct {
	Command       []string `json:"command,omitempty"`
	SelfExe       string   `json:"self_exe,omitempty"`
	DashboardAddr string   `json:"dashboard_addr,omitempty"`
	SensorMode    string   `json:"sensor_mode,omitempty"`
	Checks        []Check  `json:"checks"`
}

// Preflight inspects whether launch can observe the requested command before it
// starts long-lived children. It is intentionally side-effect-light: the only
// filesystem probe creates and removes a temporary cgroup leaf when Linux cgroup
// v2 appears writable, matching the operation record will need later.
func Preflight(opts Options) PreflightReport {
	if opts.SelfExe == "" {
		if exe, err := os.Executable(); err == nil {
			opts.SelfExe = exe
		}
	}
	if opts.DashboardAddr == "" {
		opts.DashboardAddr = "127.0.0.1:7396"
	}
	if opts.Sensor == "" {
		opts.Sensor = "auto"
	}
	r := PreflightReport{
		Command:       append([]string(nil), opts.Command...),
		SelfExe:       opts.SelfExe,
		DashboardAddr: opts.DashboardAddr,
		SensorMode:    opts.Sensor,
	}
	r.Checks = append(r.Checks, checkCommand(opts.Command))
	r.Checks = append(r.Checks, checkClaudeHooks(opts.Command))
	r.Checks = append(r.Checks, checkDashboardAddr(opts.Dashboard, opts.DashboardAddr))
	r.Checks = append(r.Checks, checkCgroup())
	r.Checks = append(r.Checks, checkSensor(opts.Sensor, opts.SelfExe))
	return r
}

func (r PreflightReport) HasFailures() bool {
	for _, c := range r.Checks {
		if c.Status == CheckFail {
			return true
		}
	}
	return false
}

func checkCommand(command []string) Check {
	if len(command) == 0 {
		return Check{Name: "agent command", Status: CheckSkip, Detail: "no command supplied; pass one after -- to check the agent binary"}
	}
	prog := command[0]
	if strings.ContainsRune(prog, os.PathSeparator) {
		info, err := os.Stat(prog)
		if err != nil {
			return Check{Name: "agent command", Status: CheckFail, Detail: prog + " is not accessible", Fix: err.Error()}
		}
		if info.IsDir() || info.Mode()&0o111 == 0 {
			return Check{Name: "agent command", Status: CheckFail, Detail: prog + " is not executable"}
		}
		return Check{Name: "agent command", Status: CheckPass, Detail: prog + " is executable"}
	}
	path, err := exec.LookPath(prog)
	if err != nil {
		return Check{Name: "agent command", Status: CheckFail, Detail: prog + " not found on PATH", Fix: "install it or pass an absolute path"}
	}
	return Check{Name: "agent command", Status: CheckPass, Detail: path}
}

func checkClaudeHooks(command []string) Check {
	if len(command) == 0 {
		return Check{Name: "Claude hooks", Status: CheckSkip, Detail: "no agent command supplied"}
	}
	recipe := detectRecipe(command)
	if !recipe.injectHooks {
		return Check{Name: "Claude hooks", Status: CheckSkip, Detail: recipe.detail}
	}
	for _, a := range command[1:] {
		if a == "--settings" || strings.HasPrefix(a, "--settings=") {
			return Check{
				Name:   "Claude hooks",
				Status: CheckWarn,
				Detail: "command already passes --settings, so launch will not override it",
				Fix:    "remove --settings for per-run hook capture, or run record-only intentionally",
			}
		}
	}
	return Check{Name: "Claude hooks", Status: CheckPass, Detail: recipe.detail}
}

func checkDashboardAddr(enabled bool, addr string) Check {
	if !enabled {
		return Check{Name: "dashboard port", Status: CheckSkip, Detail: "dashboard disabled"}
	}
	if addr == "" {
		addr = "127.0.0.1:7396"
	}
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		_ = ln.Close()
		return Check{Name: "dashboard port", Status: CheckPass, Detail: addr + " is available"}
	}
	return Check{
		Name:   "dashboard port",
		Status: CheckWarn,
		Detail: addr + " is not available; launch will fall back to an ephemeral port",
		Fix:    err.Error(),
	}
}

func checkCgroup() Check {
	if runtime.GOOS != "linux" {
		return Check{Name: "cgroup v2", Status: CheckSkip, Detail: fmt.Sprintf("not available on %s; record uses a logical scope id", runtime.GOOS)}
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return Check{Name: "cgroup v2", Status: CheckWarn, Detail: "unified cgroup v2 not detected; kernel correlation falls back to pid/time", Fix: err.Error()}
	}
	parent := firstNonEmpty(os.Getenv("AGENTPROV_CGROUP_PARENT"), "/sys/fs/cgroup/agentprov")
	dir := filepath.Join(parent, ".agentprov-preflight-"+strconv.Itoa(os.Getpid()))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Check{
			Name:   "cgroup v2",
			Status: CheckWarn,
			Detail: parent + " is not writable/delegated; record will use synthetic cgroup ids",
			Fix:    "create and delegate AGENTPROV_CGROUP_PARENT, or run with sufficient cgroup privileges: " + err.Error(),
		}
	}
	_ = os.Remove(dir)
	return Check{Name: "cgroup v2", Status: CheckPass, Detail: parent + " can host per-run scopes"}
}

func checkSensor(mode, selfExe string) Check {
	if mode == "off" {
		return Check{Name: "kernel sensor", Status: CheckSkip, Detail: "disabled via --sensor=off"}
	}
	if runtime.GOOS != "linux" {
		return Check{Name: "kernel sensor", Status: CheckSkip, Detail: fmt.Sprintf("requires Linux; this host is %s", runtime.GOOS)}
	}
	if selfExe == "" {
		return Check{Name: "kernel sensor", Status: CheckWarn, Detail: "cannot locate agentprov binary for sensor subprocess"}
	}
	if _, err := os.Stat(selfExe); err != nil {
		return Check{Name: "kernel sensor", Status: CheckWarn, Detail: "agentprov binary is not accessible", Fix: err.Error()}
	}
	if os.Geteuid() == 0 || hasEffectiveCap(38) && hasEffectiveCap(39) {
		return Check{Name: "kernel sensor", Status: CheckPass, Detail: "Linux host has root or CAP_PERFMON+CAP_BPF"}
	}
	return Check{
		Name:   "kernel sensor",
		Status: CheckWarn,
		Detail: "Linux host lacks root/CAP_PERFMON+CAP_BPF; launch will degrade to app/record evidence",
		Fix:    "run as root or grant capabilities to the agentprov binary (for example: sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+ep " + selfExe + ")",
	}
}

func hasEffectiveCap(bit uint) bool {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return false
			}
			v, err := strconv.ParseUint(fields[1], 16, 64)
			if err != nil {
				return false
			}
			return v&(uint64(1)<<bit) != 0
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
