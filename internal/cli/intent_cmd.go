package cli

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/byteyellow/agentprovenance/internal/intent"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

// intentCmd computes and shows the Intent-Runtime Diff: for each captured
// contract (tool call / peer message / refusal) versus the runtime effects
// attributed to its scope, whether they matched, a boundary was violated, a
// refusal was bypassed, or intent was simply not captured.
func intentCmd(dataDir *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "intent",
		Short: "reconcile declared agent intent against observed runtime effects",
	}
	cmd.AddCommand(intentDiffCmd(dataDir))
	return cmd
}

func intentDiffCmd(dataDir *string) *cobra.Command {
	var runID string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "materialize the Intent-Runtime Diff for a run and show findings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if runID == "" {
				return fmt.Errorf("--run is required")
			}
			paths, err := store.Init(*dataDir)
			if err != nil {
				return err
			}
			db, err := store.Open(paths)
			if err != nil {
				return err
			}
			defer db.Close()

			res, err := intent.Materialize(db, runID)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "run=%s effects=%d contracts=%d diffs=%d mismatches=%d coverage_gaps=%d\n",
				res.RunID, res.Effects, res.Contracts, res.Diffs, res.Mismatches, res.CoverageGaps)
			return printIntentDiffs(cmd, db, runID)
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the machine-readable materialize summary")
	return cmd
}

func printIntentDiffs(cmd *cobra.Command, db *sql.DB, runID string) error {
	rows, err := db.Query(`SELECT status, finding, contract_kind, operation, agent_id, round(confidence,2), mismatch_reason
		FROM intent_diffs WHERE run_id = ? ORDER BY
		CASE status WHEN 'refused_but_runtime_happened' THEN 0 WHEN 'declared_vs_effect_mismatch' THEN 1
		WHEN 'intent_coverage_gap' THEN 2 ELSE 3 END`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "STATUS\tFINDING\tKIND\tOP\tAGENT\tCONF\tREASON")
	any := false
	for rows.Next() {
		var status, finding, kind, op, agent, reason string
		var conf float64
		if err := rows.Scan(&status, &finding, &kind, &op, &agent, &conf, &reason); err != nil {
			return err
		}
		any = true
		if finding == "" {
			finding = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%.2f\t%s\n", status, finding, kind, op, short(agent), conf, reason)
	}
	if !any {
		fmt.Fprintln(w, "(no diffs)")
	}
	return w.Flush()
}
