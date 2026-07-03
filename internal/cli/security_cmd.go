package cli

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/byteyellow/agentprovenance/internal/baseline"
	securitymodel "github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func securityCmd(dataDir, daemonURL *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "security",
		Short: "security evidence, deviation, and response commands",
	}
	cmd.AddCommand(securityRisksCmd(dataDir, daemonURL))
	cmd.AddCommand(securityDeviationsCmd(dataDir, daemonURL))
	cmd.AddCommand(securityResponsesCmd(dataDir, daemonURL))
	cmd.AddCommand(securityReevaluateCmd(dataDir))
	return cmd
}

// securityReevaluateCmd re-runs the policy engine over a captured run's stored
// events, regenerating the decision/risk/response/signal layer from the current
// (or a custom --rules) policy. Raw events are untouched. Use it to apply an
// updated policy to already-captured runs without re-running the agent.
func securityReevaluateCmd(dataDir *string) *cobra.Command {
	var runID, rulesPath string
	cmd := &cobra.Command{
		Use:   "reevaluate",
		Short: "re-run policy over a captured run's events (apply updated rules to history)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if runID == "" {
				return fmt.Errorf("--run is required")
			}
			engine, err := securitymodel.LoadEngine(rulesPath)
			if err != nil {
				return err
			}
			db, cleanup, err := openLocalDB(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			evaluated, alerts, err := securitymodel.ReevaluateRun(db, runID, engine)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]any{
				"schema_version":   "agentprovenance.security_reevaluate/v1",
				"run":              runID,
				"events_evaluated": evaluated,
				"alerts":           alerts,
			})
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "run id to re-evaluate")
	cmd.Flags().StringVar(&rulesPath, "rules", "", "YAML policy rules file (default: built-in policy)")
	return cmd
}

func securityRisksCmd(dataDir, daemonURL *string) *cobra.Command {
	var runID string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "risks",
		Short: "list normalized risk signals",
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := securityRisks(*dataDir, *daemonURL, runID)
			if asJSON {
				if err != nil {
					return err
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tRUN\tSESSION\tTOOL_CALL\tPROCESS\tTYPE\tSEVERITY\tACTION\tREASON\tCREATED_AT")
			for _, item := range report.Risks {
				record := item.Risk
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					record.ID, record.RunID, record.SessionID, record.ToolCallID, record.ProcessID,
					record.SignalType, record.Severity, record.RecommendedAction, record.Reason, record.CreatedAt)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "filter by run id")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit structured risk signal JSON")
	return cmd
}

func securityDeviationsCmd(dataDir, daemonURL *string) *cobra.Command {
	var runID string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "deviations",
		Short: "list baseline deviation signals",
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := securityDeviations(*dataDir, *daemonURL, runID)
			if asJSON {
				if err != nil {
					return err
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tRUN\tTEMPLATE\tTYPE\tSTATUS\tEXPECTED\tOBSERVED\tACTION\tCREATED_AT")
			for _, item := range report.Deviations {
				record := item.Deviation
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%.3f\t%.3f\t%s\t%s\n",
					record.ID, record.RunID, record.TemplateName, record.DeviationType, record.Status,
					record.ExpectedValue, record.ObservedValue, record.RecommendedAction, record.CreatedAt)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "filter by run id")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit structured baseline deviation JSON")
	return cmd
}

func securityResponsesCmd(dataDir, daemonURL *string) *cobra.Command {
	var runID string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "responses",
		Short: "list recorded response actions",
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := securityResponses(*dataDir, *daemonURL, runID)
			if asJSON {
				if err != nil {
					return err
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tRUN\tACTION\tTARGET_TYPE\tTARGET_ID\tSTATUS\tRISK\tDECISION\tCREATED_AT")
			for _, item := range report.Responses {
				record := item.Response
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					record.ID, record.RunID, record.ActionType, record.TargetType, record.TargetID,
					record.Status, record.RiskSignalID, record.PolicyDecisionID, record.CreatedAt)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "filter by run id")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit structured response action JSON")
	return cmd
}

func securityRisks(dataDir, daemonURL, runID string) (securitymodel.RiskSignalsReport, error) {
	if client, ok := daemonClient(daemonURL); ok {
		return client.SecurityRisks(runID)
	}
	db, cleanup, err := openLocalDB(dataDir)
	if err != nil {
		return securitymodel.RiskSignalsReport{}, err
	}
	defer cleanup()
	return securitymodel.BuildRiskSignalsReport(db, runID)
}

func securityDeviations(dataDir, daemonURL, runID string) (baseline.DeviationsReport, error) {
	if client, ok := daemonClient(daemonURL); ok {
		return client.SecurityDeviations(runID)
	}
	db, cleanup, err := openLocalDB(dataDir)
	if err != nil {
		return baseline.DeviationsReport{}, err
	}
	defer cleanup()
	return baseline.BuildDeviationsReport(db, runID)
}

func securityResponses(dataDir, daemonURL, runID string) (securitymodel.ResponseActionsReport, error) {
	if client, ok := daemonClient(daemonURL); ok {
		return client.SecurityResponses(runID)
	}
	db, cleanup, err := openLocalDB(dataDir)
	if err != nil {
		return securitymodel.ResponseActionsReport{}, err
	}
	defer cleanup()
	return securitymodel.BuildResponseActionsReport(db, runID)
}

func openLocalDB(dataDir string) (*sql.DB, func(), error) {
	paths, err := store.Init(dataDir)
	if err != nil {
		return nil, nil, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return nil, nil, err
	}
	return db, func() { db.Close() }, nil
}
