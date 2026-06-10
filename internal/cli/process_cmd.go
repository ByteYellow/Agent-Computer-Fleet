package cli

import (
	"fmt"
	"github.com/spf13/cobra"
)

func processCmd(dataDir *string) *cobra.Command {
	interrupt := &cobra.Command{
		Use:   "interrupt <process_id>",
		Short: "interrupt a running process",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := controlSvc(*dataDir)
			if err != nil {
				return err
			}
			defer closeFn()
			if err := svc.Interrupt(args[0]); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "interrupted")
			return nil
		},
	}
	cmd := &cobra.Command{Use: "process", Short: "process operations"}
	cmd.AddCommand(interrupt)
	return cmd
}
