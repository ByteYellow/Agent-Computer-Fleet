package cli

import (
	"fmt"
	"github.com/byteyellow/agent-computer-fleet/internal/egress"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
)

func egressCmd(dataDir *string) *cobra.Command {
	var runID, sessionID, dstIP, host string
	check := &cobra.Command{
		Use:   "check",
		Short: "evaluate an egress proxy network event",
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
			decision, err := egress.Check(db, runID, sessionID, dstIP, host)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "decision=%s reason=%s event_id=%s\n", decision.Decision, decision.Reason, decision.EventID)
			return nil
		},
	}
	check.Flags().StringVar(&runID, "run", "", "run id")
	check.Flags().StringVar(&sessionID, "session", "", "session id")
	check.Flags().StringVar(&dstIP, "dst-ip", "", "destination IP")
	check.Flags().StringVar(&host, "host", "", "destination host")
	_ = check.MarkFlagRequired("run")
	_ = check.MarkFlagRequired("dst-ip")
	cmd := &cobra.Command{Use: "egress", Short: "egress proxy commands"}
	cmd.AddCommand(check)
	return cmd
}
