// Command agentprov-sensor is the self-owned eBPF system-telemetry sensor. It
// attaches kernel probes and emits normalized telemetry events as JSONL on
// stdout, which `agentprov telemetry ingest`-style consumers feed into the
// correlation engine. Linux-only; requires root/CAP_BPF.
package main

import (
	"fmt"
	"os"

	"github.com/byteyellow/agentprovenance/internal/sensor"
)

func main() {
	// AGENTPROV_SSL_LIB=/path/to/libssl.so.3 enables OpenSSL TLS plaintext
	// capture via SSL_write/read and SSL_write_ex/read_ex uprobes.
	opts := sensor.Options{
		SSLLib:   os.Getenv("AGENTPROV_SSL_LIB"),
		GoTLSBin: os.Getenv("AGENTPROV_GO_TLS_BIN"),
		LibcLib:  os.Getenv("AGENTPROV_LIBC_LIB"),
	}
	if err := sensor.RunWithOptions(os.Stdout, opts); err != nil {
		fmt.Fprintln(os.Stderr, "agentprov-sensor:", err)
		os.Exit(1)
	}
}
