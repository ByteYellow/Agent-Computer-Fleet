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

// ProfileStatus separates capability targets from environments that have
// passed a live acceptance gate. Planned profiles remain discoverable without
// being mistaken for available evidence producers.
type ProfileStatus string

const (
	ProfileValidated ProfileStatus = "validated"
	ProfilePlanned   ProfileStatus = "planned"
)

// LayerCapability declares a layer's coverage in a profile plus a human note
// explaining any limit (e.g. "OpenSSL dynamic-link only").
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
	Status          ProfileStatus             `json:"status"`
	SensorPlacement string                    `json:"sensor_placement"`
	ScopeMode       string                    `json:"scope_mode"`
	Layers          map[Layer]LayerCapability `json:"layers"`
}

// CapabilityReport is the public, machine-readable view of a Producer Profile.
// Scope confidence is derived from validation status rather than duplicated in
// profile definitions, so a planned profile cannot accidentally advertise a
// trusted attribution tier.
type CapabilityReport struct {
	Profile
	ScopeConfidence float64 `json:"scope_confidence"`
}

// ScopeConfidence is the confidence tier this profile's scope mode maps to,
// consistent with correlation binding sources.
func (p Profile) ScopeConfidence() float64 {
	if p.Status != ProfileValidated {
		return 0
	}
	if p.ScopeMode == ScopeModeCgroup {
		return correlation.DefaultBindingConfidence(correlation.BindingSourceK8sCgroup)
	}
	return correlation.DefaultBindingConfidence("record")
}

// LocalRecord is the baseline profile: the current local/VM path. record wraps
// the workload for a kernel-verified scope. The kernel and hook layers are full;
// model intent is strong for dynamically-linked OpenSSL clients, but still not a
// universal TLS-stack capture.
func LocalRecord() Profile {
	return Profile{
		Name:            "local-record",
		Status:          ProfileValidated,
		SensorPlacement: "local host",
		ScopeMode:       ScopeModeRecord,
		Layers: map[Layer]LayerCapability{
			LayerSystemTelemetry: {Coverage: CoverageFull},
			LayerModelIntent:     {Coverage: CoveragePartial, Note: "dynamic OpenSSL plus partial unstripped Go crypto/tls request/write capture; HTTP/1.1 + HTTP/2/HPACK parsed"},
			LayerAppContext:      {Coverage: CoverageFull, Note: "adapted harness (hooks) required for tool-call intent"},
		},
	}
}

// K8sDaemonset runs one sensor per node (DaemonSet). It shares the node kernel,
// so system telemetry is full; scope is passive pod/container metadata -> host
// cgroup inode attribution unless the pod entrypoint opts into record. Model intent is limited by whether the node
// sensor can resolve the workload's dynamic libssl in the container rootfs.
func K8sDaemonset() Profile {
	return Profile{
		Name:            "k8s-daemonset",
		Status:          ProfileValidated,
		SensorPlacement: "node DaemonSet (privileged / hostPID / CAP_BPF)",
		ScopeMode:       ScopeModeCgroup,
		Layers: map[Layer]LayerCapability{
			LayerSystemTelemetry: {Coverage: CoverageFull},
			LayerModelIntent:     {Coverage: CoveragePartial, Note: "dynamic OpenSSL or partial unstripped Go crypto/tls request/write when symbols are resolvable from the node/rootfs; HTTP/1.1 + HTTP/2/HPACK parsed"},
			LayerAppContext:      {Coverage: CoverageFull, Note: "via command-match; adapted harness required for tool-call intent"},
		},
	}
}

// MicrovmGuestInit describes the intended in-guest shape. It stays visible as a
// planned profile, but reports no available coverage or scope confidence until
// a guest-init runner and live KVM acceptance exist.
func MicrovmGuestInit() Profile {
	return Profile{
		Name:            "microvm-guest-init",
		Status:          ProfilePlanned,
		SensorPlacement: "future in-guest init service",
		ScopeMode:       ScopeModeRecord,
		Layers: map[Layer]LayerCapability{
			LayerSystemTelemetry: {Coverage: CoverageNone, Note: "planned; no guest-init runner or live KVM acceptance"},
			LayerModelIntent:     {Coverage: CoverageNone, Note: "planned; depends on the guest TLS stack after the profile is implemented"},
			LayerAppContext:      {Coverage: CoverageNone, Note: "planned; no validated in-guest adapter lifecycle"},
		},
	}
}

// Profiles is the built-in profile registry, used to render the capability report.
func Profiles() []Profile {
	return []Profile{LocalRecord(), K8sDaemonset(), MicrovmGuestInit()}
}

func CapabilityReports() []CapabilityReport {
	profiles := Profiles()
	reports := make([]CapabilityReport, 0, len(profiles))
	for _, profile := range profiles {
		reports = append(reports, CapabilityReport{Profile: profile, ScopeConfidence: profile.ScopeConfidence()})
	}
	return reports
}
