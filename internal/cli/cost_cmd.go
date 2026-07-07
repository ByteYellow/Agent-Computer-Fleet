package cli

import (
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/cost"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func costCmd(dataDir *string) *cobra.Command {
	show := &cobra.Command{
		Use:   "show <run_id>",
		Short: "show resource and cost evidence for a run",
		Args:  cobra.ExactArgs(1),
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
			return cost.ShowCost(db, args[0], cmd.OutOrStdout())
		},
	}
	sample := &cobra.Command{
		Use:   "sample <session_id>",
		Short: "sample Docker stats into resource evidence",
		Args:  cobra.ExactArgs(1),
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
			sample, err := cost.SampleDockerStats(db, args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "session_id=%s run_id=%s cpu_percent=%.3f ewma_active_cpu=%.3f active_cpu_seconds=%.3f idle_seconds=%.3f memory_usage_bytes=%d memory_limit_bytes=%d throttling=%s memory_pressure=%s\n",
				sample.SessionID, sample.RunID, sample.CPUPerc, sample.EWMAActiveCPU, sample.ActiveCPUSeconds, sample.IdleSeconds, sample.MemoryUsageBytes, sample.MemoryLimitBytes, sample.Throttling, sample.MemoryPressure)
			return nil
		},
	}
	cmd := &cobra.Command{Use: "cost", Short: "resource and cost evidence commands"}
	cmd.AddCommand(show)
	cmd.AddCommand(sample)
	return cmd
}
