package cli

import (
	"encoding/json"
	"os"

	"github.com/byteyellow/agentprovenance/internal/launch"
	"github.com/spf13/cobra"
)

func doctorCmd(dataDir *string) *cobra.Command {
	var (
		workdir  string
		dashAddr string
		sensor   string
		jsonOut  bool
	)
	cmd := &cobra.Command{
		Use:   "doctor [flags] [-- <agent command...>]",
		Short: "preflight launch readiness without running the agent",
		Long: "Check the host and requested agent command before `agentprov launch`: " +
			"agent binary, Claude Code hook injection, dashboard port, cgroup v2 " +
			"scope support, and kernel sensor capability. The checks are the same " +
			"ones launch prints before capture.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			selfExe, _ := os.Executable()
			report := launch.Preflight(launch.Options{
				DataDir:       *dataDir,
				Command:       args,
				Workdir:       workdir,
				Dashboard:     true,
				DashboardAddr: dashAddr,
				Sensor:        sensor,
				SelfExe:       selfExe,
			})
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			launch.PrintPreflight(cmd.OutOrStdout(), report)
			return nil
		},
	}
	cmd.Flags().StringVar(&workdir, "workdir", "", "agent working directory to check; defaults to current directory")
	cmd.Flags().StringVar(&dashAddr, "dashboard-addr", "127.0.0.1:7396", "dashboard listen address to test")
	cmd.Flags().StringVar(&sensor, "sensor", "auto", "kernel sensor mode to check: auto or off")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit machine-readable preflight report")
	return cmd
}
