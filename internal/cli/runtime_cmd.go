package cli

import (
	"fmt"
	runtimeplane "github.com/byteyellow/agent-computer-fleet/internal/runtime"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
	"text/tabwriter"
)

func runtimeCmd(dataDir *string) *cobra.Command {
	list := &cobra.Command{
		Use:   "list",
		Short: "list registered sandbox runtime backends",
		RunE: func(cmd *cobra.Command, args []string) error {
			paths := store.ResolvePaths(*dataDir)
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tSTATUS\tSELECTED\tEXEC\tSTOP\tSNAPSHOT\tFORK\tRESUME\tMEMORY_SNAPSHOT\tNETWORK\tISOLATION")
			for _, backend := range runtimeplane.List(paths) {
				selected := ""
				if backend.Selected {
					selected = "yes"
				}
				c := backend.Capabilities
				fmt.Fprintf(w, "%s\t%s\t%s\t%t\t%t\t%t\t%t\t%t\t%t\t%s\t%s\n", backend.Name, backend.Status, selected, c.Exec, c.Stop, c.Snapshot, c.Fork, c.Resume, c.MemorySnapshot, backend.Network, backend.Isolation)
			}
			return w.Flush()
		},
	}
	inspect := &cobra.Command{
		Use:   "inspect <backend>",
		Short: "inspect a sandbox runtime backend",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			paths := store.ResolvePaths(*dataDir)
			backend, err := runtimeplane.Inspect(paths, args[0])
			if err != nil {
				return err
			}
			c := backend.Capabilities
			fmt.Fprintf(cmd.OutOrStdout(), "name=%s\nstatus=%s\navailable=%t\nselected=%t\ncap_exec=%t\ncap_stop=%t\ncap_snapshot=%t\ncap_fork=%t\ncap_resume=%t\ncap_memory_snapshot=%t\nexec=%s\nsnapshot=%s\nnetwork=%s\nisolation=%s\ntelemetry=%s\nnotes=%s\n",
				backend.Name, backend.Status, backend.Available, backend.Selected, c.Exec, c.Stop, c.Snapshot, c.Fork, c.Resume, c.MemorySnapshot, backend.Exec, backend.Snapshot, backend.Network, backend.Isolation, backend.Telemetry, backend.Notes)
			return nil
		},
	}
	cmd := &cobra.Command{Use: "runtime", Short: "runtime backend registry"}
	cmd.AddCommand(list)
	cmd.AddCommand(inspect)
	return cmd
}
