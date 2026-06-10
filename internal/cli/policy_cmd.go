package cli

import (
	"fmt"
	"github.com/byteyellow/agent-computer-fleet/internal/security"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
	"text/tabwriter"
)

func policyCmd(dataDir *string) *cobra.Command {
	var rulesPath string
	test := &cobra.Command{
		Use:   "test <events.jsonl>",
		Short: "evaluate JSONL events with the policy engine",
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
			engine, err := security.LoadEngine(rulesPath)
			if err != nil {
				return err
			}
			return security.EvaluateJSONLWithEngine(db, args[0], cmd.OutOrStdout(), engine)
		},
	}
	test.Flags().StringVar(&rulesPath, "rules", "", "YAML policy rules file")
	var runID string
	decisions := &cobra.Command{
		Use:   "decisions",
		Short: "list policy decisions",
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
			records, err := security.ListDecisions(db, runID)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tRUN\tSESSION\tRULE\tDECISION\tREASON\tCREATED_AT")
			for _, record := range records {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", record.ID, record.RunID, record.SessionID, record.RuleID, record.Decision, record.Reason, record.CreatedAt)
			}
			return w.Flush()
		},
	}
	decisions.Flags().StringVar(&runID, "run", "", "filter decisions by run id")
	cmd := &cobra.Command{Use: "policy", Short: "policy operations"}
	cmd.AddCommand(test)
	cmd.AddCommand(decisions)
	return cmd
}
