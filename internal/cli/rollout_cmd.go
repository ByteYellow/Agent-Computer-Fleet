package cli

import (
	"fmt"
	"text/tabwriter"

	"github.com/byteyellow/agent-computer-fleet/internal/rollout"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
)

func rolloutCmd(dataDir *string) *cobra.Command {
	cmd := &cobra.Command{Use: "rollout", Short: "agent rollout control commands"}
	cmd.AddCommand(rolloutStartCmd(dataDir))
	cmd.AddCommand(rolloutStatusCmd(dataDir))
	cmd.AddCommand(rolloutAttemptsCmd(dataDir))
	cmd.AddCommand(rolloutWinnerCmd(dataDir))
	cmd.AddCommand(rolloutTaintCmd(dataDir))
	return cmd
}

func rolloutStartCmd(dataDir *string) *cobra.Command {
	var req rollout.StartRequest
	c := &cobra.Command{
		Use:   "start",
		Short: "fan out attempts from a snapshot, score them, and promote a winner",
		RunE: func(cmd *cobra.Command, args []string) error {
			service, cleanup, err := rolloutSvc(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			item, results, winner, promotion, err := service.Start(req)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "rollout_id=%s run_id=%s status=%s base_snapshot=%s fanout=%d winner=%s promotion=%s risk=%s cost=%.6f\n",
				item.ID, item.RunID, item.Status, item.BaseSnapshotID, item.Fanout, winner.AttemptID, promotion.ID, promotion.RiskStatus, item.CostEstimate)
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ATTEMPT\tTOOL_CALL\tSTRATEGY\tSTATUS\tEXIT\tWALL_MS\tSCORE\tCOST\tWINNER\tWORKSPACE")
			for _, result := range results {
				winnerMark := ""
				if result.IsWinner {
					winnerMark = "yes"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%.3f\t%.6f\t%s\t%s\n",
					result.AttemptID, result.ToolCallID, result.Strategy, result.Status, result.ExitCode, result.WallMS, result.Score, result.CostEstimate, winnerMark, result.WorkspacePath)
			}
			return w.Flush()
		},
	}
	c.Flags().StringVar(&req.RunID, "run", "", "run id; generated when omitted")
	c.Flags().StringVar(&req.TaskPath, "task", "", "task yaml path for rollout metadata")
	c.Flags().StringVar(&req.Snapshot, "snapshot", "", "base snapshot name or id")
	c.Flags().StringArrayVar(&req.Strategies, "strategy", nil, "strategy in name::command form; repeat for multiple attempts")
	c.Flags().IntVar(&req.Fanout, "fanout", 0, "maximum attempts to run; defaults to strategy count")
	c.Flags().IntVar(&req.BudgetSeconds, "budget-seconds", 0, "rollout budget in seconds for accounting")
	c.Flags().Float64Var(&req.MaxCost, "max-cost", 0, "maximum fanout cost budget before stopping")
	c.Flags().BoolVar(&req.EarlyStop, "early-stop", false, "stop when a high-scoring passing attempt is found")
	_ = c.MarkFlagRequired("snapshot")
	_ = c.MarkFlagRequired("strategy")
	return c
}

func rolloutStatusCmd(dataDir *string) *cobra.Command {
	return &cobra.Command{
		Use:   "status <rollout_id_or_run_id>",
		Short: "show rollout status",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			service, cleanup, err := rolloutSvc(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			item, err := service.Inspect(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "rollout_id=%s run_id=%s status=%s base_snapshot=%s fanout=%d budget_seconds=%d max_cost=%.6f winner=%s promotion=%s risk=%s cost=%.6f created_at=%s updated_at=%s\n",
				item.ID, item.RunID, item.Status, item.BaseSnapshotID, item.Fanout, item.BudgetSeconds, item.MaxCost, item.WinnerAttemptID, item.PromotionID, item.RiskStatus, item.CostEstimate, item.CreatedAt, item.UpdatedAt)
			return nil
		},
	}
}

func rolloutAttemptsCmd(dataDir *string) *cobra.Command {
	return &cobra.Command{
		Use:   "attempts <rollout_id>",
		Short: "list attempts for a rollout",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			service, cleanup, err := rolloutSvc(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			items, err := service.Attempts(args[0])
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ATTEMPT\tTOOL_CALL\tSTRATEGY\tSTATUS\tEXIT\tWALL_MS\tSCORE\tCOST\tSAVED\tWINNER\tWORKSPACE")
			for _, item := range items {
				exitCode := ""
				if item.ExitCode.Valid {
					exitCode = fmt.Sprintf("%d", item.ExitCode.Int64)
				}
				winner := ""
				if item.IsWinner {
					winner = "yes"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%.3f\t%.6f\t%.6f\t%s\t%s\n",
					item.ID, item.ToolCallID, item.Strategy, item.Status, exitCode, item.WallMS, item.Score, item.CostEstimate, item.SavedCost, winner, item.WorkspacePath)
			}
			return w.Flush()
		},
	}
}

func rolloutWinnerCmd(dataDir *string) *cobra.Command {
	return &cobra.Command{
		Use:   "winner <rollout_id_or_run_id>",
		Short: "show rollout winner and promotion barrier result",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			service, cleanup, err := rolloutSvc(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			winner, promotion, err := service.Winner(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "winner=%s tool_call=%s strategy=%s status=%s score=%.3f cost=%.6f workspace=%s promotion=%s promotion_status=%s risk=%s watermark=%s reason=%q\n",
				winner.ID, winner.ToolCallID, winner.Strategy, winner.Status, winner.Score, winner.CostEstimate, winner.WorkspacePath, promotion.ID, promotion.Status, promotion.RiskStatus, promotion.TelemetryWatermark, promotion.Reason)
			return nil
		},
	}
}

func rolloutTaintCmd(dataDir *string) *cobra.Command {
	var reason string
	c := &cobra.Command{
		Use:   "taint <attempt_id>",
		Short: "simulate a late high-risk telemetry event and taint attempt lineage",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			service, cleanup, err := rolloutSvc(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			if err := service.TaintAttempt(args[0], reason); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "attempt_id=%s tainted=true reason=%q\n", args[0], reason)
			return nil
		},
	}
	c.Flags().StringVar(&reason, "reason", "late high-risk telemetry event", "taint reason")
	return c
}

func rolloutSvc(dataDir string) (rollout.Service, func(), error) {
	paths, err := store.Init(dataDir)
	if err != nil {
		return rollout.Service{}, nil, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return rollout.Service{}, nil, err
	}
	return rollout.Service{DB: db, Paths: paths}, func() { db.Close() }, nil
}
