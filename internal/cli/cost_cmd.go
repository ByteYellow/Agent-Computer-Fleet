package cli

import (
	"fmt"
	"github.com/byteyellow/agent-computer-fleet/internal/economics"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
)

func costCmd(dataDir *string) *cobra.Command {
	show := &cobra.Command{
		Use:   "show <run_id>",
		Short: "show run cost metrics",
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
			return economics.ShowCost(db, args[0], cmd.OutOrStdout())
		},
	}
	sample := &cobra.Command{
		Use:   "sample <session_id>",
		Short: "sample Docker stats into run cost metrics",
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
			sample, err := economics.SampleDockerStats(db, args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "session_id=%s run_id=%s cpu_percent=%.3f active_cpu_seconds=%.3f idle_seconds=%.3f memory_usage_bytes=%d memory_limit_bytes=%d throttling=%s memory_pressure=%s\n",
				sample.SessionID, sample.RunID, sample.CPUPerc, sample.ActiveCPUSeconds, sample.IdleSeconds, sample.MemoryUsageBytes, sample.MemoryLimitBytes, sample.Throttling, sample.MemoryPressure)
			return nil
		},
	}
	cmd := &cobra.Command{Use: "cost", Short: "cost operations"}
	cmd.AddCommand(show)
	cmd.AddCommand(sample)
	return cmd
}

func benchCmd() *cobra.Command {
	var sessions int
	var idleRatio, cpuPerSession, physicalCPU, overcommitRatio, idleDiscount float64
	var memoryPerSessionMB, memoryTotalMB int64
	overcommit := &cobra.Command{
		Use:   "overcommit",
		Short: "simulate active-CPU-aware overcommit admission",
		RunE: func(cmd *cobra.Command, args []string) error {
			result := economics.SimulateOvercommit(sessions, idleRatio, cpuPerSession, physicalCPU, overcommitRatio, idleDiscount, memoryPerSessionMB, memoryTotalMB)
			fmt.Fprintf(cmd.OutOrStdout(), "sessions=%d idle_ratio=%.2f admitted=%d rejected=%d weighted_cpu=%.3f capacity_cpu=%.3f\n",
				result.Sessions, result.IdleRatio, result.Admitted, result.Rejected, result.WeightedCPU, result.CapacityCPU)
			return nil
		},
	}
	overcommit.Flags().IntVar(&sessions, "sessions", 20, "number of simulated sessions")
	overcommit.Flags().Float64Var(&idleRatio, "idle-ratio", 0.8, "fraction of each session treated as idle")
	overcommit.Flags().Float64Var(&cpuPerSession, "cpu-per-session", 1, "CPU request per simulated session")
	overcommit.Flags().Float64Var(&physicalCPU, "physical-cpu", 8, "physical CPU capacity")
	overcommit.Flags().Float64Var(&overcommitRatio, "overcommit-ratio", 2, "CPU overcommit ratio")
	overcommit.Flags().Float64Var(&idleDiscount, "idle-discount", 0.1, "idle CPU discount")
	overcommit.Flags().Int64Var(&memoryPerSessionMB, "memory-per-session-mb", 256, "memory request per simulated session")
	overcommit.Flags().Int64Var(&memoryTotalMB, "memory-total-mb", 8192, "node memory capacity")
	cmd := &cobra.Command{Use: "bench", Short: "benchmark and simulation commands"}
	cmd.AddCommand(overcommit)
	return cmd
}
