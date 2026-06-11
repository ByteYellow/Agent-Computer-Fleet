package cli

import (
	"fmt"

	"github.com/byteyellow/agent-computer-fleet/internal/scheduler"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
)

func schedulerCmd(dataDir, daemonURL *string) *cobra.Command {
	var snapshot string
	status := &cobra.Command{
		Use:   "status",
		Short: "show local scheduler node signals",
		RunE: func(cmd *cobra.Command, args []string) error {
			var node scheduler.NodeState
			var err error
			if client, ok := daemonClient(*daemonURL); ok {
				node, err = client.SchedulerStatus(snapshot)
			} else {
				paths, initErr := store.Init(*dataDir)
				if initErr != nil {
					return initErr
				}
				db, openErr := store.Open(paths)
				if openErr != nil {
					return openErr
				}
				defer db.Close()
				node, err = (scheduler.Scheduler{DB: db}).NodeState(snapshot)
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "node_id=%s physical_cpu=%.2f overcommit_ratio=%.2f idle_discount=%.2f running_sessions=%d ewma_active_cpu=%.3f throttling_count=%d active_cpu_debt=%.3f tool_phase_inflight=%d burst_inflight=%d burst_reserved_cpu=%.3f burst_debt=%.3f burst_max_inflight=%d burst_reject_count=%d telemetry_pressure=%s memory_allocated_mb=%d memory_total_mb=%d warm_pool_ready=%d snapshot_local=%t queue_pressure=%s\n",
				node.NodeID, node.PhysicalCPU, node.OvercommitRatio, node.IdleDiscount, node.RunningSessions, node.EWMAActiveCPU, node.ThrottlingCount, node.ActiveCPUDebt, node.ToolPhaseInflight, node.BurstInflight, node.BurstReservedCPU, node.BurstDebt, node.BurstMaxInflight, node.BurstRejectCount, node.TelemetryPressure, node.MemoryAllocatedMB, node.MemoryTotalMB, node.WarmPoolReady, node.SnapshotLocal, node.QueuePressure)
			return nil
		},
	}
	status.Flags().StringVar(&snapshot, "snapshot", "", "snapshot name or id for locality check")
	cmd := &cobra.Command{Use: "scheduler", Short: "scheduler signal commands"}
	cmd.AddCommand(status)
	return cmd
}
