//go:build linux

package producer

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// SelfCgroupID returns this process's cgroup v2 id -- the cgroup directory inode,
// which is exactly the value the eBPF sensor emits (bpf_get_current_cgroup_id).
// Inside a sandbox every process shares the sandbox's cgroup, so this is the key
// that ties the sandbox's kernel telemetry to a scope. Returns "" when it cannot
// be determined (not cgroup v2, or unreadable), in which case passive cgroup
// binding is simply skipped.
func SelfCgroupID() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	var rel string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		// cgroup v2 unified line: "0::<path>".
		fields := strings.SplitN(line, ":", 3)
		if len(fields) == 3 && fields[0] == "0" {
			rel = fields[2]
			break
		}
	}
	if rel == "" {
		return ""
	}
	info, err := os.Stat("/sys/fs/cgroup" + rel)
	if err != nil {
		return ""
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return strconv.FormatUint(st.Ino, 10)
}
