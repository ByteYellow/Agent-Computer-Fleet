package producer

import "github.com/byteyellow/agentprovenance/internal/correlation"

// Layer is one of the three collection axes. Coverage is declared per layer per
// profile so a missing or degraded layer is honest capability data rather than a
// gap hidden behind "profile available".
type Layer string

const (
	LayerSystemTelemetry Layer = "system_telemetry"
	LayerModelIntent     Layer = "model_intent"
	LayerAppContext      Layer = "app_context"
)

// Coverage is how completely a layer is collected in a given profile.
type Coverage string

const (
	CoverageFull    Coverage = "full"
	CoveragePartial Coverage = "partial"
	CoverageNone    Coverage = "none"
)

// LayerCapability declares a layer's coverage in a profile plus a human note
// explaining any limit (e.g. "OpenSSL only").
type LayerCapability struct {
	Coverage Coverage `json:"coverage"`
	Note     string   `json:"note,omitempty"`
}

// Scope modes. record is kernel-verified (we launched the scope); cgroup is
// passive attribution of an externally-scheduled workload.
const (
	ScopeModeRecord = "record"
	ScopeModeCgroup = "cgroup"
)

// Profile declares where an evidence producer runs, how it resolves scope, and
// which of the three collection layers it can deliver in that environment. It is
// a capability declaration only: it does not change the core graph or schema.
type Profile struct {
	Name            string                    `json:"name"`
	SensorPlacement string                    `json:"sensor_placement"`
	ScopeMode       string                    `json:"scope_mode"`
	Layers          map[Layer]LayerCapability `json:"layers"`
}

// ScopeConfidence is the confidence tier this profile's scope mode maps to,
// consistent with correlation binding sources.
func (p Profile) ScopeConfidence() float64 {
	if p.ScopeMode == ScopeModeCgroup {
		return correlation.DefaultBindingConfidence(correlation.BindingSourceK8sCgroup)
	}
	return correlation.DefaultBindingConfidence("record")
}

// LocalRecord is the baseline profile: the current local/VM path. record wraps
// the workload for a kernel-verified scope and all three layers are collected.
func LocalRecord() Profile {
	return Profile{
		Name:            "local-record",
		SensorPlacement: "local host",
		ScopeMode:       ScopeModeRecord,
		Layers: map[Layer]LayerCapability{
			LayerSystemTelemetry: {Coverage: CoverageFull},
			LayerModelIntent:     {Coverage: CoverageFull, Note: "OpenSSL dynamic-link only"},
			LayerAppContext:      {Coverage: CoverageFull, Note: "adapted harness (hooks) required for tool-call intent"},
		},
	}
}

// K8sDaemonset runs one sensor per node (DaemonSet). It shares the node kernel,
// so system telemetry is full; scope is passive cgroup→pod attribution unless the
// pod entrypoint opts into record. Model intent is pending libssl resolution
// across each pod's container rootfs.
func K8sDaemonset() Profile {
	return Profile{
		Name:            "k8s-daemonset",
		SensorPlacement: "node DaemonSet (privileged / hostPID / CAP_BPF)",
		ScopeMode:       ScopeModeCgroup,
		Layers: map[Layer]LayerCapability{
			LayerSystemTelemetry: {Coverage: CoverageFull},
			LayerModelIntent:     {Coverage: CoveragePartial, Note: "pending libssl-in-container-rootfs uprobe resolution"},
			LayerAppContext:      {Coverage: CoverageFull, Note: "via command-match; adapted harness required for tool-call intent"},
		},
	}
}

// MicrovmGuestInit runs the full stack inside the guest (the guest is a complete
// Linux), matching the local/VM path, and exports a signed forensics bundle on
// teardown so short-lived VMs do not lose evidence.
func MicrovmGuestInit() Profile {
	return Profile{
		Name:            "microvm-guest-init",
		SensorPlacement: "in-guest init service",
		ScopeMode:       ScopeModeRecord,
		Layers: map[Layer]LayerCapability{
			LayerSystemTelemetry: {Coverage: CoverageFull},
			LayerModelIntent:     {Coverage: CoverageFull, Note: "OpenSSL dynamic-link only"},
			LayerAppContext:      {Coverage: CoverageFull, Note: "adapted harness (hooks) required for tool-call intent"},
		},
	}
}

// Profiles is the built-in profile registry, used to render the capability report.
func Profiles() []Profile {
	return []Profile{LocalRecord(), K8sDaemonset(), MicrovmGuestInit()}
}
