//go:build !linux

package producer

// SelfCgroupID is unavailable off Linux (no cgroup v2 / no eBPF sensor).
// Passive cgroup binding is skipped; the darwin dev host keeps building.
func SelfCgroupID() string { return "" }
