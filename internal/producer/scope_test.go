package producer

import (
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestRecordCgroupScopeBindingUsesPassiveTier(t *testing.T) {
	paths, err := store.Init(filepath.Join(t.TempDir(), ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := recordCgroupScopeBinding(db, "424242", RunScope{
		RunID: "run-1", SessionID: "sess-1", ToolCallID: "tool-1", ProcessID: "proc-1",
		StartedAt: "2026-07-07T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	got, err := correlation.ListBindings(db, correlation.BindingFilter{RunID: "run-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(got))
	}
	b := got[0]
	if b.BindingSource != correlation.BindingSourceK8sCgroup {
		t.Errorf("binding source = %q, want %q", b.BindingSource, correlation.BindingSourceK8sCgroup)
	}
	if b.Confidence != 0.8 {
		t.Errorf("confidence = %v, want 0.8 (passive k8s_cgroup tier)", b.Confidence)
	}
	if b.CgroupID != "424242" || b.ToolCallID != "tool-1" || b.ProcessID != "proc-1" {
		t.Errorf("scope not carried through: %+v", b)
	}
}

func TestBindSelfCgroupNeverErrors(t *testing.T) {
	// Platform-agnostic: off Linux SelfCgroupID is "" -> bound=false; on Linux it
	// may bind. Either way it must not error, and a bound result must persist.
	paths, err := store.Init(filepath.Join(t.TempDir(), ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id, bound, err := BindSelfCgroup(db, RunScope{RunID: "run-self"})
	if err != nil {
		t.Fatalf("BindSelfCgroup errored: %v", err)
	}
	if bound && id == "" {
		t.Fatal("bound=true but empty bind id")
	}
}

func TestParseCgroupScope(t *testing.T) {
	cid := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	cases := []struct {
		name    string
		path    string
		runtime string
		cid     string
		podUID  string
		ok      bool
	}{
		{
			name:    "k8s systemd cri-containerd",
			path:    "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod12345678_1234_1234_1234_123456789012.slice/cri-containerd-" + cid + ".scope",
			runtime: "containerd",
			cid:     cid,
			podUID:  "12345678-1234-1234-1234-123456789012",
			ok:      true,
		},
		{
			name:    "k8s cgroupfs dashed pod uid",
			path:    "/kubepods/besteffort/pod12345678-1234-1234-1234-123456789012/" + cid,
			runtime: "",
			cid:     cid,
			podUID:  "12345678-1234-1234-1234-123456789012",
			ok:      true,
		},
		{
			name:    "plain docker scope",
			path:    "/system.slice/docker-" + cid + ".scope",
			runtime: "docker",
			cid:     cid,
			podUID:  "",
			ok:      true,
		},
		{
			name: "no identity",
			path: "/system.slice/agentprov.service",
			ok:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseCgroupScope(tc.path)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (got %+v)", ok, tc.ok, got)
			}
			if !tc.ok {
				return
			}
			if got.Runtime != tc.runtime {
				t.Errorf("runtime = %q, want %q", got.Runtime, tc.runtime)
			}
			if got.ContainerID != tc.cid {
				t.Errorf("container id = %q, want %q", got.ContainerID, tc.cid)
			}
			if got.PodUID != tc.podUID {
				t.Errorf("pod uid = %q, want %q", got.PodUID, tc.podUID)
			}
		})
	}
}

func TestCgroupScopeBindingUsesPassiveSource(t *testing.T) {
	scope := CgroupScope{ContainerID: "cid", PodUID: "pod-uid"}
	b := scope.Binding("run1", "sess1", "cgroup42", 4242)
	if b.BindingSource != correlation.BindingSourceK8sCgroup {
		t.Fatalf("binding source = %q, want %q", b.BindingSource, correlation.BindingSourceK8sCgroup)
	}
	if b.ContainerID != "cid" || b.CgroupID != "cgroup42" || b.PID != 4242 || b.RunID != "run1" {
		t.Fatalf("binding fields not carried through: %+v", b)
	}
	// Passive attribution must stay below a record/control-plane scope.
	if got := correlation.DefaultBindingConfidence(b.BindingSource); got != 0.8 {
		t.Fatalf("k8s_cgroup confidence = %v, want 0.8", got)
	}
}
