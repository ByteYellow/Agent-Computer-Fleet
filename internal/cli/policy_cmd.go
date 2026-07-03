package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
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
	var outPath string
	rules := &cobra.Command{
		Use:   "rules",
		Short: "dump the default policy rules as an editable YAML file",
		Long: "Emits the built-in policy (allow/detect/enforce rules) as YAML you can edit and " +
			"load back with `policy test --rules <file>`. Use it to tune, e.g., which credential " +
			"paths count as the agent's own infra (allow, no alert) vs an exfil target (kill).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := security.DefaultRulesYAML()
			if err != nil {
				return err
			}
			if outPath != "" {
				return os.WriteFile(outPath, data, 0o644)
			}
			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	}
	rules.Flags().StringVar(&outPath, "out", "", "write to this path instead of stdout")
	cmd := &cobra.Command{Use: "policy", Short: "policy operations"}
	cmd.AddCommand(test)
	cmd.AddCommand(decisions)
	cmd.AddCommand(rules)
	return cmd
}
