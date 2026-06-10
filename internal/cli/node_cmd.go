package cli

import (
	"fmt"
	"github.com/byteyellow/agent-computer-fleet/internal/fleet"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
	"text/tabwriter"
)

func nodeCmd(dataDir *string) *cobra.Command {
	var address, runtime, labels string
	var cpu, debt float64
	var memoryMB, warmHits int64
	register := &cobra.Command{
		Use:   "register",
		Short: "register a node agent with capacity metadata",
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
			node, err := fleet.Register(db, address, runtime, labels, cpu, memoryMB)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "node_id=%s address=%s runtime=%s cpu=%.2f memory_mb=%d status=%s\n", node.ID, node.Address, node.Runtime, node.CPUCapacity, node.MemoryMB, node.Status)
			return nil
		},
	}
	register.Flags().StringVar(&address, "address", "localhost", "node address")
	register.Flags().StringVar(&runtime, "runtime", "docker", "runtime backend")
	register.Flags().StringVar(&labels, "labels", "local=true", "node labels")
	register.Flags().Float64Var(&cpu, "cpu", 1, "CPU capacity")
	register.Flags().Int64Var(&memoryMB, "memory-mb", 1024, "memory capacity")

	list := &cobra.Command{
		Use:   "list",
		Short: "list registered nodes",
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
			nodes, err := fleet.List(db)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tADDRESS\tRUNTIME\tCPU\tMEMORY_MB\tACTIVE_CPU_DEBT\tWARM_HITS\tSTATUS\tLABELS")
			for _, node := range nodes {
				fmt.Fprintf(w, "%s\t%s\t%s\t%.2f\t%d\t%.3f\t%d\t%s\t%s\n", node.ID, node.Address, node.Runtime, node.CPUCapacity, node.MemoryMB, node.ActiveCPUDebt, node.WarmHitCount, node.Status, node.Labels)
			}
			return w.Flush()
		},
	}

	inspect := &cobra.Command{
		Use:   "inspect <node_id>",
		Short: "inspect node placement metadata",
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
			node, err := fleet.Inspect(db, args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "id=%s\naddress=%s\nruntime=%s\nlabels=%s\ncpu_capacity=%.2f\nmemory_mb=%d\nactive_cpu_debt=%.3f\nwarm_hit_count=%d\nstatus=%s\nupdated_at=%s\n",
				node.ID, node.Address, node.Runtime, node.Labels, node.CPUCapacity, node.MemoryMB, node.ActiveCPUDebt, node.WarmHitCount, node.Status, node.UpdatedAt)
			return nil
		},
	}

	heartbeat := &cobra.Command{
		Use:   "heartbeat <node_id>",
		Short: "update node heartbeat and scheduling signals",
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
			if err := fleet.Heartbeat(db, args[0], debt, warmHits); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "heartbeat=ok")
			return nil
		},
	}
	heartbeat.Flags().Float64Var(&debt, "active-cpu-debt", 0, "active CPU debt")
	heartbeat.Flags().Int64Var(&warmHits, "warm-hits", 0, "warm hit increment")

	cmd := &cobra.Command{Use: "node", Short: "fleet node commands"}
	cmd.AddCommand(register)
	cmd.AddCommand(list)
	cmd.AddCommand(inspect)
	cmd.AddCommand(heartbeat)
	return cmd
}
