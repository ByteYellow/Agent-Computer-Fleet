package cli

import (
	"encoding/json"
	"os"

	"github.com/byteyellow/agentprovenance/internal/launch"
	"github.com/spf13/cobra"
)

// launchCmd is the porcelain one-command entry point:
//
//	agentprov launch -- claude          # or codex, or any agent command
//
// It wraps an agent in a full provenance run -- run scope, live dashboard,
// per-run hooks overlay (no changes to the agent's own settings), kernel sensor
// when the host allows it, cgroup-isolated exec, and a signed evidence bundle
// with a one-line verdict on exit. Evidence degrades honestly on hosts that
// cannot run the sensor (e.g. macOS) or agents with no hooks recipe.
func launchCmd(dataDir *string) *cobra.Command {
	var (
		workdir  string
		noDash   bool
		dashAddr string
		sensor   string
		signKey  string
		fileDiff bool
		jsonOut  bool
	)
	cmd := &cobra.Command{
		Use:   "launch [flags] -- <agent command...>",
		Short: "run an agent under full provenance capture in one command",
		Long: "Wrap any agent command in a complete AgentProvenance run: create a run " +
			"scope, serve the read-only dashboard, inject a per-run hooks overlay " +
			"(Claude Code today; the user's settings are never modified), start the " +
			"kernel sensor when the host can, exec the agent in a dedicated cgroup, " +
			"and on exit seal + sign the evidence graph and print a one-line verdict.\n\n" +
			"Evidence level is two honest axes printed up front: application side " +
			"(hooks vs record-only) and system side (kernel telemetry vs none).",
		Args:               cobra.MinimumNArgs(1),
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := launch.Run(launch.Options{
				DataDir:       *dataDir,
				Command:       args,
				Workdir:       workdir,
				Dashboard:     !noDash,
				DashboardAddr: dashAddr,
				Sensor:        sensor,
				SignKeyPath:   signKey,
				FileDiff:      fileDiff,
				Stdout:        cmd.OutOrStdout(),
				Stderr:        cmd.ErrOrStderr(),
			})
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				_ = enc.Encode(report)
			}
			// Propagate the agent's exit code so `launch` is a faithful wrapper.
			if report.ExitCode != 0 {
				os.Exit(report.ExitCode)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&workdir, "workdir", "", "agent working directory; defaults to the current directory")
	cmd.Flags().BoolVar(&noDash, "no-dashboard", false, "do not serve the live dashboard")
	cmd.Flags().StringVar(&dashAddr, "dashboard-addr", "127.0.0.1:7396", "dashboard listen address (falls back to an ephemeral port if busy)")
	cmd.Flags().StringVar(&sensor, "sensor", "auto", "kernel sensor: auto (Linux + capable) or off")
	cmd.Flags().StringVar(&signKey, "sign-key", "", "hex ed25519 private key file; when set, the sealed bundle is signed")
	cmd.Flags().BoolVar(&fileDiff, "file-diff", false, "capture the working-tree file diff (off by default: copies the whole tree; kernel file_write covers changes on Linux)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "also emit the machine-readable launch report")
	return cmd
}
