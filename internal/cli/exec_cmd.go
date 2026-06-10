package cli

import (
	"fmt"
	"github.com/spf13/cobra"
)

func execCmd(dataDir *string) *cobra.Command {
	var stream bool
	cmd := &cobra.Command{
		Use:   "exec <session_id> -- <command...>",
		Short: "execute a command in a sandbox session",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := controlSvc(*dataDir)
			if err != nil {
				return err
			}
			defer closeFn()
			processID, err := svc.Exec(args[0], args[1:], stream)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), processID)
			return nil
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			stream, _ = cmd.Flags().GetBool("stream")
		},
	}
	cmd.Flags().Bool("stream", false, "stream stdout/stderr")
	return cmd
}
