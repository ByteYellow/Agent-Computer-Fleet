//go:build !linux

// Package sensor is the self-owned system-telemetry sensor. On Linux it loads
// eBPF probes (execve/connect/file_open) and emits normalized telemetry events;
// on other platforms it is a stub so the module still builds.
package sensor

import (
	"fmt"
	"io"
)

// Options mirrors the Linux build's sensor options so callers compile on any
// platform (see sensor_linux.go for the real fields).
type Options struct {
	SSLLib   string
	GoTLSBin string
	LibcLib  string
	OnReady  func()
}

// RunWithOptions is unavailable off Linux (eBPF requires a Linux kernel).
func RunWithOptions(_ io.Writer, _ Options) error {
	return fmt.Errorf("agentprov sensor requires linux (eBPF)")
}
