package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestHostCgroupPathCannotEscapeRoot(t *testing.T) {
	tests := map[string]string{
		"/kubepods.slice/pod-a":        "/sys/fs/cgroup/kubepods.slice/pod-a",
		"../../kubepods.slice/pod-b":   "/sys/fs/cgroup/kubepods.slice/pod-b",
		"../../../sys/fs/cgroup/pod-c": "/sys/fs/cgroup/sys/fs/cgroup/pod-c",
	}
	for input, want := range tests {
		if got := hostCgroupPath(input); got != want {
			t.Errorf("hostCgroupPath(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestProcScopeResolverIndexesContainerCgroups(t *testing.T) {
	const containerID = "1975174628cc0b9585d08bae7dfc65d661e8d307fa01f9d905685139cc0135ab"
	root := t.TempDir()
	dir := filepath.Join(root, "kubepods.slice", "cri-containerd-"+containerID+".scope")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no syscall.Stat_t")
	}
	r := &procScopeResolver{root: root, byContainer: map[string]string{}, refreshEvery: time.Second}
	got, err := r.resolveContainer("containerd://" + containerID)
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("%d", stat.Ino); got != want {
		t.Fatalf("cgroup id = %q, want %q", got, want)
	}
}
