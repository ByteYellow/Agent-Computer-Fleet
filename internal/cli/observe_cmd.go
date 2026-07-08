package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/byteyellow/agentprovenance/internal/observability"
	"github.com/spf13/cobra"
)

func observeCmd(dataDir, daemonURL *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "observe",
		Short: "summarize execution observability for agent runs",
	}
	cmd.AddCommand(observeSummaryCmd(dataDir, daemonURL))
	cmd.AddCommand(observeCoverageCmd(dataDir))
	cmd.AddCommand(observeScopesCmd(dataDir))
	cmd.AddCommand(observeEventCmd(dataDir))
	cmd.AddCommand(observeProcessCmd(dataDir))
	cmd.AddCommand(observeFlowCmd(dataDir))
	return cmd
}

func observeSummaryCmd(dataDir, daemonURL *string) *cobra.Command {
	var runID string
	var topN int
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "summary",
		Short: "show run-level observability coverage, risk, and evidence summary",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runID == "" {
				return fmt.Errorf("--run is required")
			}
			summary, err := observeSummary(*dataDir, *daemonURL, runID, topN)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(summary)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "run=%s schema=%s events=%d\n", summary.RunID, summary.SchemaVersion, summary.EventCount)
			fmt.Fprintf(cmd.OutOrStdout(), "application substrate_scopes=%d execution_scopes=%d tool_calls=%d processes=%d artifact_states=%d\n",
				summary.Application.Sessions, summary.Application.Attempts, summary.Application.ToolCalls, summary.Application.Processes, summary.Application.Snapshots)
			fmt.Fprintf(cmd.OutOrStdout(), "runtime events=%d with_substrate_scope=%d with_tool_call=%d with_process=%d tool_call_coverage=%.2f process_coverage=%.2f\n",
				summary.Runtime.Events, summary.Runtime.EventsWithSession, summary.Runtime.EventsWithToolCall, summary.Runtime.EventsWithProcess,
				summary.Runtime.ToolCallCoverageRatio, summary.Runtime.ProcessCoverageRatio)
			fmt.Fprintf(cmd.OutOrStdout(), "risk signals=%d policy_decisions=%d baseline_deviations=%d response_actions=%d\n",
				summary.Risk.Signals, summary.Risk.PolicyDecisions, summary.Baseline.Deviations, summary.Response.Actions)
			printCounts(cmd, "EVENT_TYPE", summary.EventTypes)
			printCounts(cmd, "SOURCE", summary.Sources)
			if len(summary.TopEvidenceRefs) > 0 {
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "REF\tTYPE\tSOURCE\tSUMMARY")
				for _, ref := range summary.TopEvidenceRefs {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", ref.Ref, ref.Type, ref.Source, ref.Summary)
				}
				if err := w.Flush(); err != nil {
					return err
				}
			}
			if len(summary.RecommendedViews) > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "next_views:")
				for _, view := range summary.RecommendedViews {
					fmt.Fprintf(cmd.OutOrStdout(), "  agentprov %s\n", view)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().IntVar(&topN, "top", 8, "maximum evidence refs to show")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

func observeSummary(dataDir, daemonURL, runID string, topN int) (observability.Summary, error) {
	if client, ok := daemonClient(daemonURL); ok {
		return client.ObserveSummary(runID, topN)
	}
	db, cleanup, err := openLocalDB(dataDir)
	if err != nil {
		return observability.Summary{}, err
	}
	defer cleanup()
	return observability.BuildSummary(db, observability.SummaryOptions{RunID: runID, TopN: topN})
}

func observeCoverageCmd(dataDir *string) *cobra.Command {
	var runID string
	var limit int
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "coverage",
		Short: "show runtime telemetry correlation coverage and gaps",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runID == "" {
				return fmt.Errorf("--run is required")
			}
			db, cleanup, err := openLocalDB(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			report, err := observability.BuildCoverage(db, observability.CoverageOptions{RunID: runID, Limit: limit})
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "run=%s schema=%s runtime_events=%d fully_correlated=%d gaps=%d full_coverage=%.2f tool_call_coverage=%.2f process_coverage=%.2f\n",
				report.RunID, report.SchemaVersion, report.Summary.RuntimeEvents, report.Summary.FullyCorrelated,
				report.Summary.CorrelationGapCount, report.Summary.FullyCorrelatedRatio,
				report.Summary.ToolCallCoverageRatio, report.Summary.ProcessCoverageRatio)
			printCounts(cmd, "MISSING_FIELD", report.MissingFields)
			printCounts(cmd, "SOURCE", report.BySource)
			printCounts(cmd, "TYPE", report.ByType)
			if len(report.Gaps) > 0 {
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "EVENT\tSOURCE\tTYPE\tMISSING\tIDENTITY\tMETHOD\tSUGGESTED_BINDING")
				for _, gap := range report.Gaps {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
						gap.EventID, gap.Source, gap.Type, strings.Join(gap.Missing, ","), gapIdentity(gap), gap.CorrelationMethod, gap.SuggestedBinding)
				}
				if err := w.Flush(); err != nil {
					return err
				}
			}
			if len(report.NextSteps) > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "next_steps:")
				for _, step := range report.NextSteps {
					fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", step)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().IntVar(&limit, "limit", 20, "maximum correlation gaps to show")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

func observeScopesCmd(dataDir *string) *cobra.Command {
	var runID string
	var limit int
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "scopes",
		Short: "summarize observability by tool call scope",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runID == "" {
				return fmt.Errorf("--run is required")
			}
			db, cleanup, err := openLocalDB(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			report, err := observability.BuildScopes(db, observability.ScopesOptions{RunID: runID, Limit: limit})
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "run=%s schema=%s scopes=%d\n", report.RunID, report.SchemaVersion, report.ScopeCount)
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "TOOL_CALL\tSESSION\tATTEMPT\tSTATUS\tPROCESSES\tRUNTIME_EVENTS\tRISKS\tPOLICY\tRESPONSES\tCOMMAND")
			for _, scope := range report.Scopes {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%s\n",
					scope.ToolCallID, scope.SessionID, scope.AttemptID, scope.Status, scope.ProcessCount, scope.RuntimeEvents,
					scope.RiskSignals, scope.PolicyDecisions, scope.ResponseActions, scope.Command)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum tool call scopes to return")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

func observeEventCmd(dataDir *string) *cobra.Command {
	var runID string
	var eventID string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "event",
		Short: "explain one runtime event with correlated agent context",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runID == "" {
				return fmt.Errorf("--run is required")
			}
			if eventID == "" {
				return fmt.Errorf("--event is required")
			}
			db, cleanup, err := openLocalDB(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			report, err := observability.BuildEvent(db, observability.EventOptions{RunID: runID, EventID: eventID})
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "run=%s schema=%s event=%s type=%s source=%s time=%s\n",
				report.RunID, report.SchemaVersion, report.Event.ID, report.Event.Type, report.Event.Source, report.Event.Time)
			fmt.Fprintf(cmd.OutOrStdout(), "context substrate_scope=%s execution_scope=%s tool_call=%s process=%s artifact_state=%s\n",
				report.Context.SessionID, report.Context.AttemptID, report.Context.ToolCallID, report.Context.ProcessID, report.Context.SnapshotID)
			fmt.Fprintf(cmd.OutOrStdout(), "correlation method=%s confidence=%.2f\n", report.Event.CorrelationMethod, report.Event.CorrelationConfidence)
			fmt.Fprintf(cmd.OutOrStdout(), "summary=%q\n", report.Event.Summary)
			printEvidenceSummaries(cmd, "RELATED_RISK", report.RelatedRisks)
			printEvidenceSummaries(cmd, "RELATED_POLICY", report.RelatedPolicies)
			printEvidenceSummaries(cmd, "RELATED_RESPONSE", report.RelatedResponses)
			if len(report.RecommendedViews) > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "next_views:")
				for _, view := range report.RecommendedViews {
					fmt.Fprintf(cmd.OutOrStdout(), "  agentprov %s\n", view)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().StringVar(&eventID, "event", "", "runtime event id")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

func observeProcessCmd(dataDir *string) *cobra.Command {
	var runID string
	var processID string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "process",
		Short: "explain one process with runtime events and agent context",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runID == "" {
				return fmt.Errorf("--run is required")
			}
			if processID == "" {
				return fmt.Errorf("--process is required")
			}
			db, cleanup, err := openLocalDB(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			report, err := observability.BuildProcess(db, observability.ProcessOptions{RunID: runID, ProcessID: processID})
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "run=%s schema=%s process=%s started_at=%s ended_at=%s\n",
				report.RunID, report.SchemaVersion, report.Process.ID, report.Process.StartedAt, report.Process.EndedAt)
			fmt.Fprintf(cmd.OutOrStdout(), "context substrate_scope=%s execution_scope=%s tool_call=%s artifact_state=%s\n",
				report.Context.SessionID, report.Context.AttemptID, report.Context.ToolCallID, report.Context.SnapshotID)
			fmt.Fprintf(cmd.OutOrStdout(), "summary=%q\n", report.Process.Summary)
			printEvidenceSummaries(cmd, "RUNTIME_EVENT", report.RuntimeEvents)
			printEvidenceSummaries(cmd, "RELATED_RISK", report.RelatedRisks)
			printEvidenceSummaries(cmd, "RELATED_POLICY", report.RelatedPolicies)
			printEvidenceSummaries(cmd, "RELATED_RESPONSE", report.RelatedResponses)
			if len(report.RecommendedViews) > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "next_views:")
				for _, view := range report.RecommendedViews {
					fmt.Fprintf(cmd.OutOrStdout(), "  agentprov %s\n", view)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().StringVar(&processID, "process", "", "process id")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

func observeFlowCmd(dataDir *string) *cobra.Command {
	var runID string
	var limit int
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "flow",
		Short: "show runtime event to risk and response flow",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runID == "" {
				return fmt.Errorf("--run is required")
			}
			db, cleanup, err := openLocalDB(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			report, err := observability.BuildFlow(db, observability.FlowOptions{RunID: runID, Limit: limit})
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "run=%s schema=%s flows=%d\n", report.RunID, report.SchemaVersion, report.FlowCount)
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "TIME\tTOOL_CALL\tPROCESS\tEVENT\tTYPE\tRISKS\tPOLICY\tRESPONSES\tSUMMARY")
			for _, item := range report.Flows {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					item.Time, item.ToolCallID, item.ProcessID, item.EventID, item.EventType,
					strings.Join(item.RiskSignals, ","), strings.Join(item.PolicyDecisions, ","), strings.Join(item.ResponseActions, ","), item.Summary)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum flow rows to return")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

func gapIdentity(gap observability.CorrelationGap) string {
	if gap.ContainerID != "" {
		return "container=" + gap.ContainerID
	}
	if gap.CgroupID != "" {
		return "cgroup=" + gap.CgroupID
	}
	if gap.PID != 0 {
		return fmt.Sprintf("pid=%d", gap.PID)
	}
	return ""
}

func printEvidenceSummaries(cmd *cobra.Command, title string, refs []observability.EvidenceSummary) {
	if len(refs) == 0 {
		return
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "%s\tTYPE\tSOURCE\tSUMMARY\n", title)
	for _, ref := range refs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", ref.Ref, ref.Type, ref.Source, ref.Summary)
	}
	_ = w.Flush()
}

func printCounts(cmd *cobra.Command, title string, counts map[string]int) {
	if len(counts) == 0 {
		return
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "%s\tCOUNT\n", title)
	for _, item := range sortedCountItems(counts) {
		fmt.Fprintf(w, "%s\t%d\n", item.Name, item.Count)
	}
	_ = w.Flush()
}

type countItem struct {
	Name  string
	Count int
}

func sortedCountItems(counts map[string]int) []countItem {
	items := make([]countItem, 0, len(counts))
	for name, count := range counts {
		items = append(items, countItem{Name: name, Count: count})
	}
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j].Count > items[i].Count || (items[j].Count == items[i].Count && items[j].Name < items[i].Name) {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
	return items
}
