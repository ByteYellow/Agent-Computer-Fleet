package cli

import (
	"fmt"
	"github.com/byteyellow/agent-computer-fleet/internal/attempt"
	"github.com/byteyellow/agent-computer-fleet/internal/state"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
	"text/tabwriter"
)

func attemptCmd(dataDir *string) *cobra.Command {
	var snapshot string
	var strategies []string
	bestOf := &cobra.Command{
		Use:   "best-of",
		Short: "fork attempts from one snapshot, execute strategies, and choose a winner",
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
			service := attempt.Service{DB: db, State: state.Service{DB: db, Paths: paths}}
			results, winner, err := service.BestOf(snapshot, strategies)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ATTEMPT\tSTRATEGY\tSTATUS\tEXIT\tWALL_MS\tSCORE\tWINNER\tOUTPUT")
			for _, result := range results {
				winnerMark := ""
				if result.IsWinner {
					winnerMark = "yes"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%.3f\t%s\t%s\n", result.AttemptID, result.Strategy, result.Status, result.ExitCode, result.WallMS, result.Score, winnerMark, result.OutputSummary)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "winner=%s strategy=%s workspace=%s score=%.3f\n", winner.AttemptID, winner.Strategy, winner.WorkspacePath, winner.Score)
			return nil
		},
	}
	bestOf.Flags().StringVar(&snapshot, "snapshot", "", "snapshot name or id")
	bestOf.Flags().StringArrayVar(&strategies, "strategy", nil, "strategy in name::command form; repeat for multiple attempts")
	_ = bestOf.MarkFlagRequired("snapshot")
	_ = bestOf.MarkFlagRequired("strategy")
	cmd := &cobra.Command{Use: "attempt", Short: "attempt execution and selection commands"}
	cmd.AddCommand(bestOf)
	return cmd
}
