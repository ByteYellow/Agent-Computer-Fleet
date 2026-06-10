package cli

import (
	"fmt"
	runtimeplane "github.com/byteyellow/agent-computer-fleet/internal/runtime"
	"github.com/spf13/cobra"
	"text/tabwriter"
)

func runtimeCmd() *cobra.Command {
	list := &cobra.Command{
		Use:   "list",
		Short: "list registered sandbox runtime backends",
		RunE: func(cmd *cobra.Command, args []string) error {
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tSTATUS\tSELECTED\tEXEC\tSNAPSHOT\tNETWORK\tISOLATION\tTELEMETRY")
			for _, backend := range runtimeplane.List() {
				selected := ""
				if backend.Selected {
					selected = "yes"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", backend.Name, backend.Status, selected, backend.Exec, backend.Snapshot, backend.Network, backend.Isolation, backend.Telemetry)
			}
			return w.Flush()
		},
	}
	inspect := &cobra.Command{
		Use:   "inspect <backend>",
		Short: "inspect a sandbox runtime backend",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			backend, err := runtimeplane.Inspect(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "name=%s\nstatus=%s\navailable=%t\nselected=%t\nexec=%s\nsnapshot=%s\nnetwork=%s\nisolation=%s\ntelemetry=%s\nnotes=%s\n",
				backend.Name, backend.Status, backend.Available, backend.Selected, backend.Exec, backend.Snapshot, backend.Network, backend.Isolation, backend.Telemetry, backend.Notes)
			return nil
		},
	}
	cmd := &cobra.Command{Use: "runtime", Short: "runtime backend registry"}
	cmd.AddCommand(list)
	cmd.AddCommand(inspect)
	return cmd
}
