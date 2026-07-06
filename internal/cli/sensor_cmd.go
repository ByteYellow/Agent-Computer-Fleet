package cli

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/sensor"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
	"github.com/spf13/cobra"
)

func sensorCmd(dataDir *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sensor",
		Short: "run the self-owned eBPF system sensor (Linux, needs root/CAP_BPF)",
	}
	cmd.AddCommand(sensorStreamCmd(dataDir))
	return cmd
}

// sensorStreamCmd is the per-node privileged half of supervised capture. It runs
// the eBPF sensor and streams every event straight into the local store, where
// each is correlated to whichever ToolCallScope owns its cgroup. Run ONE per
// host: every record/rollout whose process cgroup the kernel sees is then joined
// automatically at cgroup fidelity (0.98), with no per-scope sensor and no
// manual `agentprov-sensor | telemetry ingest-jsonl` pipe (which is how the demo
// wired it by hand). Runs until SIGINT/SIGTERM.
func sensorStreamCmd(dataDir *string) *cobra.Command {
	var sslLib string
	var noPolicy bool
	var keepUncorrelated bool
	stream := &cobra.Command{
		Use:   "stream",
		Short: "per-node supervisor: run the eBPF sensor and ingest+correlate its events into the local store until interrupted",
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := store.Init(*dataDir)
			if err != nil {
				return err
			}
			db, err := store.Open(paths)
			if err != nil {
				return err
			}
			defer db.Close()
			daemon.WarnIfDaemonActive(*dataDir, cmd.ErrOrStderr())

			// Keep the sensor from observing (and re-ingesting, and thereby
			// amplifying) AgentProvenance's OWN I/O: its data-dir snapshot copies
			// and store DB writes. Without this, a record snapshot alone floods
			// the stream with thousands of file_writes to data-dir/snapshots that
			// bury and drop real scope events (observed on the lab VM). Two guards:
			// (1) drop file events whose path is under the data-dir; (2) drop any
			// event from the supervisor's own cgroup.
			ingOpts := telemetry.JSONLIngestOptions{Format: "native", Path: "sensor:stream", DropUncorrelated: !keepUncorrelated}
			if abs, err := filepath.Abs(*dataDir); err == nil {
				ingOpts.ExcludePathPrefixes = []string{abs}
			}
			if own := ownCgroupID(); own != "" {
				ingOpts.ExcludeCgroupIDs = []string{own}
			}

			// Sensor writes JSONL to the pipe; the ingest reader drains it live,
			// line by line, ingesting+correlating each event as it arrives. The
			// sensor traps SIGINT/SIGTERM itself and closes its ringbuf on exit;
			// we then close the pipe so the reader unblocks and returns.
			pr, pw := io.Pipe()
			errCh := make(chan error, 1)
			// Emit a machine-readable readiness line only AFTER every probe has
			// attached (via OnReady), so a supervisor (launch) gating its exec on
			// this never races a fast workload past a not-yet-attached sensor. The
			// pre-attach "capturing" banner is human-facing only.
			stderr := cmd.ErrOrStderr()
			go func() {
				sensorErr := sensor.RunWithOptions(pw, sensor.Options{
					SSLLib:  sslLib,
					OnReady: func() { fmt.Fprintln(stderr, "agentprov sensor stream: ready probes-attached") },
				})
				_ = pw.CloseWithError(sensorErr)
				errCh <- sensorErr
			}()

			fmt.Fprintln(stderr, "agentprov sensor stream: capturing kernel telemetry -> store (ctrl-c to stop)")
			result, ingErr := telemetry.IngestJSONLReader(db, ingOpts, pr)
			sensorErr := <-errCh
			if sensorErr != nil {
				return sensorErr
			}
			if ingErr != nil {
				return ingErr
			}
			if !noPolicy {
				evaluateTelemetryPolicy(db, &result)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "stopped read=%d ingested=%d excluded=%d dropped_uncorrelated=%d skipped=%d failed=%d policy_decisions=%d\n",
				result.Read, result.Ingested, result.Excluded, result.Dropped, result.Skipped, result.Failed, result.PolicyDecisions)
			return nil
		},
	}
	stream.Flags().StringVar(&sslLib, "ssl-lib", "", "attach the TLS-plaintext uprobe to this libssl path (optional)")
	stream.Flags().BoolVar(&noPolicy, "no-policy", false, "skip the end-of-run policy sweep")
	stream.Flags().BoolVar(&keepUncorrelated, "keep-uncorrelated", false, "retain host-wide events that belong to no tracked scope (default: drop them; they fail per-run verify)")
	return stream
}
