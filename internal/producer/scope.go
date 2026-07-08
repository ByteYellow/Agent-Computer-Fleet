// Package producer models evidence-producer deployment: where a sensor runs,
// how scope is resolved, how events ship, and which collection layers a given
// environment can actually deliver. It adds no core graph or schema behaviour;
// scope bindings are written through the existing correlation.RecordBinding /
// execution_context_bindings path.
package producer

import (
	"database/sql"
	"regexp"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/correlation"
)

// CgroupScope is the pod/container identity parsed from a cgroup path. It lets a
// node sensor bind kernel events to a scope for externally-scheduled workloads
// (K8s pods) that were never launched through `record`.
type CgroupScope struct {
	Runtime     string // "docker", "containerd", "crio", or "" when unknown
	ContainerID string // 64-hex container id, empty when none is present
	PodUID      string // Kubernetes pod UID in canonical dashed form, empty when not a pod cgroup
}

var (
	containerIDRe = regexp.MustCompile(`[0-9a-f]{64}`)
	// The pod UID appears as pod<uid> in kubepods cgroup paths. The systemd
	// cgroup driver escapes the dashes to underscores
	// (kubepods-besteffort-pod<uid>.slice); the cgroupfs driver keeps dashes
	// (kubepods/besteffort/pod<uid>/...). Both dashed-UUID and 32-hex forms occur.
	podUIDRe = regexp.MustCompile(`pod([0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12}|[0-9a-fA-F]{32})`)
)

// ParseCgroupScope extracts pod/container identity from a cgroup path (v1 or v2,
// systemd or cgroupfs driver). ok is false when nothing identifiable is found.
func ParseCgroupScope(cgroupPath string) (CgroupScope, bool) {
	s := CgroupScope{}
	lower := strings.ToLower(cgroupPath)
	switch {
	case strings.Contains(lower, "containerd"):
		s.Runtime = "containerd"
	case strings.Contains(lower, "crio") || strings.Contains(lower, "cri-o"):
		s.Runtime = "crio"
	case strings.Contains(lower, "docker"):
		s.Runtime = "docker"
	}
	if m := containerIDRe.FindString(lower); m != "" {
		s.ContainerID = m
	}
	if m := podUIDRe.FindStringSubmatch(cgroupPath); m != nil {
		s.PodUID = canonicalPodUID(m[1])
	}
	return s, s.ContainerID != "" || s.PodUID != ""
}

func canonicalPodUID(uid string) string {
	uid = strings.ToLower(strings.ReplaceAll(uid, "_", "-"))
	if len(uid) == 32 && !strings.Contains(uid, "-") {
		return uid[:8] + "-" + uid[8:12] + "-" + uid[12:16] + "-" + uid[16:20] + "-" + uid[20:]
	}
	return uid
}

// Binding turns a parsed cgroup scope into a passive-attribution binding for the
// given run/session. The caller supplies the run/session (e.g. a pod-UID →
// session mapping); this fills the kernel-observed identity and tags the source
// as k8s_cgroup, so correlation.RecordBinding assigns the mid confidence tier
// (kernel-witnessed cgroup, but not a record-launched scope). No pod UID column
// is written - pod identity rides in the caller's session/registry, keeping the
// schema unchanged.
func (s CgroupScope) Binding(runID, sessionID, cgroupID string, pid int64) correlation.Binding {
	return correlation.Binding{
		RunID:         runID,
		SessionID:     sessionID,
		ContainerID:   s.ContainerID,
		CgroupID:      cgroupID,
		PID:           pid,
		BindingSource: correlation.BindingSourceK8sCgroup,
	}
}

// RunScope names a run's scope for a passive telemetry binding. Its zero fields
// are allowed; only the cgroup + run tie is required for correlation, the rest
// enriches the graph edges the telemetry ingest can build.
type RunScope struct {
	RunID      string
	SessionID  string
	AttemptID  string
	ToolCallID string
	ProcessID  string
	// StartedAt opens the binding window; it must be at/before the earliest
	// event the sensor emits for this sandbox, or those events fall outside the
	// window and read as uncorrelated. Empty means "now" (correlation.RecordBinding default).
	StartedAt string
}

// recordCgroupScopeBinding writes a passive k8s_cgroup binding tying a cgroup id
// to a run's scope. Confidence is left at the k8s_cgroup default tier (0.8):
// kernel-witnessed, but not a record-launched scope. Split out from BindSelfCgroup
// so the binding write is unit-testable without a live cgroup.
func recordCgroupScopeBinding(db *sql.DB, cgroupID string, scope RunScope) (string, error) {
	return correlation.RecordBinding(db, correlation.Binding{
		RunID:         scope.RunID,
		SessionID:     scope.SessionID,
		AttemptID:     scope.AttemptID,
		ToolCallID:    scope.ToolCallID,
		ProcessID:     scope.ProcessID,
		CgroupID:      cgroupID,
		StartedAt:     scope.StartedAt,
		BindingSource: correlation.BindingSourceK8sCgroup,
	})
}

// BindCgroupScope records a passive k8s_cgroup binding for an explicit cgroup id
// (e.g. a pod's cgroup observed from the node, not the caller's own). Used by the
// node/DaemonSet path where the sensor watches externally-scheduled pods.
func BindCgroupScope(db *sql.DB, cgroupID string, scope RunScope) (string, error) {
	return recordCgroupScopeBinding(db, cgroupID, scope)
}

// BindSelfCgroup resolves this sandbox's own cgroup and, when available, records
// a passive k8s_cgroup scope binding so kernel telemetry from the sandbox
// correlates to the run even when record could not establish a kernel-verified
// cgroup scope (externally-scheduled pod, or a container without cgroup
// delegation). Returns bound=false (no error) off Linux or when the cgroup can't
// be resolved - the run then keeps whatever scope record established.
func BindSelfCgroup(db *sql.DB, scope RunScope) (bindID string, bound bool, err error) {
	cgroupID := SelfCgroupID()
	if cgroupID == "" {
		return "", false, nil
	}
	id, err := recordCgroupScopeBinding(db, cgroupID, scope)
	if err != nil {
		return "", false, err
	}
	return id, true, nil
}
