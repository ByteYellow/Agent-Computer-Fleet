package cli

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/daemon"
	securitymodel "github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
	"github.com/spf13/cobra"
	"os"
	"text/tabwriter"
)

func telemetryCmd(dataDir, daemonURL *string) *cobra.Command {
	var runID, sessionID, eventType, toolCallID string
	var listJSON bool
	var listLimit int
	var listCursor string
	var batchesRunID string
	var batchesJSON bool
	var windowsFilter telemetry.EventWindowFilter
	var windowsJSON bool
	var correlationsRunID string
	var correlationsEventID string
	var correlationsJSON bool
	list := &cobra.Command{
		Use:   "list",
		Short: "list recorded telemetry events",
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
			filter := telemetry.Filter{
				RunID:      runID,
				SessionID:  sessionID,
				Type:       eventType,
				ToolCallID: toolCallID,
			}
			result, err := telemetry.ListEventsPage(db, telemetry.ListOptions{
				Filter: filter,
				Limit:  listLimit,
				Cursor: listCursor,
			})
			if err != nil {
				return err
			}
			if listJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tRUN\tSESSION\tTOOL_CALL\tPROCESS\tSNAPSHOT\tCORRELATION\tCONFIDENCE\tSOURCE\tTYPE\tCREATED_AT")
			for _, event := range result.Events {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%.2f\t%s\t%s\t%s\n", event.ID, event.RunID, event.SessionID, event.ToolCallID, event.ProcessID, event.SnapshotID, event.CorrelationMethod, event.CorrelationConfidence, event.Source, event.EventType, event.CreatedAt)
			}
			if result.NextCursor != "" {
				fmt.Fprintf(w, "next_cursor=%s\n", result.NextCursor)
			}
			return w.Flush()
		},
	}
	list.Flags().StringVar(&runID, "run", "", "filter by run id")
	list.Flags().StringVar(&sessionID, "session", "", "filter by session id")
	list.Flags().StringVar(&eventType, "type", "", "filter by event type")
	list.Flags().StringVar(&toolCallID, "tool-call", "", "filter by tool call id")
	list.Flags().IntVar(&listLimit, "limit", 100, "maximum telemetry events to return")
	list.Flags().StringVar(&listCursor, "cursor", "", "pagination cursor from previous telemetry list output")
	list.Flags().BoolVar(&listJSON, "json", false, "emit structured telemetry event JSON")
	cmd := &cobra.Command{Use: "telemetry", Short: "telemetry inspection commands"}
	cmd.AddCommand(list)
	cmd.AddCommand(telemetryBindCmd(dataDir))
	cmd.AddCommand(telemetryBindingsCmd(dataDir))
	cmd.AddCommand(telemetryIngestCmd(dataDir))
	cmd.AddCommand(telemetryIngestJSONLCmd(dataDir))
	cmd.AddCommand(telemetryIngestFalcoCmd(dataDir))
	cmd.AddCommand(telemetryPruneCmd(dataDir))
	correlations := &cobra.Command{
		Use:   "correlations",
		Short: "explain how runtime telemetry events map to ToolCallScope bindings",
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := telemetryCorrelations(*dataDir, *daemonURL, correlationsRunID, correlationsEventID)
			if err != nil {
				return err
			}
			if correlationsJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "EVENT\tTYPE\tSOURCE\tSTATUS\tMETHOD\tCONFIDENCE\tBINDING\tTOOL_CALL\tPROCESS\tMATCHED_KEYS\tREASON")
			for _, item := range report.Items {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%.2f\t%s\t%s\t%s\t%s\t%s\n",
					item.Event.ID, item.Event.Type, item.Event.Source, item.Match.Status, item.Match.Method, item.Match.Confidence,
					item.Match.BindingID, item.ResolvedContext.ToolCallID, item.ResolvedContext.ProcessID,
					fmt.Sprintf("%v", item.Match.MatchedKeys), item.Match.Reason)
			}
			return w.Flush()
		},
	}
	correlations.Flags().StringVar(&correlationsRunID, "run", "", "filter by run id")
	correlations.Flags().StringVar(&correlationsEventID, "event", "", "explain one event id")
	correlations.Flags().BoolVar(&correlationsJSON, "json", false, "emit structured correlation evidence JSON")
	cmd.AddCommand(correlations)
	batches := &cobra.Command{
		Use:   "batches",
		Short: "list telemetry ingest batch manifests",
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
			items, err := telemetry.ListBatches(db, batchesRunID)
			if err != nil {
				return err
			}
			if batchesJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"schema_version": "agentprovenance.telemetry_batches/v1",
					"run_id":         batchesRunID,
					"batches":        items,
				})
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tRUN\tFORMAT\tREAD\tINGESTED\tSKIPPED\tFAILED\tFILE_SHA256\tEVENT_IDS_SHA256\tPATH\tCREATED_AT")
			for _, item := range items {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s\n",
					item.ID, item.RunID, item.Format, item.Read, item.Ingested, item.Skipped, item.Failed, item.FileSHA256, item.EventIDsSHA256, item.Path, item.CreatedAt)
			}
			return w.Flush()
		},
	}
	batches.Flags().StringVar(&batchesRunID, "run", "", "filter by run id")
	batches.Flags().BoolVar(&batchesJSON, "json", false, "emit JSON batch manifest list")
	cmd.AddCommand(batches)
	windows := &cobra.Command{
		Use:   "windows",
		Short: "list aggregated telemetry event windows",
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
			result, err := telemetry.ListEventWindows(db, windowsFilter)
			if err != nil {
				return err
			}
			if windowsJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "RUN\tSESSION\tTOOL_CALL\tSOURCE\tTYPE\tWINDOW_SECONDS\tWINDOW_START\tEVENTS\tRESOLVED\tUNRESOLVED\tHIGH_RISK")
			for _, item := range result.Windows {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%s\t%d\t%d\t%d\t%d\n",
					item.RunID, item.SessionID, item.ToolCallID, item.Source, item.EventType, item.WindowSeconds, item.WindowStart,
					item.EventCount, item.ResolvedCount, item.UnresolvedCount, item.HighRiskCount)
			}
			return w.Flush()
		},
	}
	windows.Flags().StringVar(&windowsFilter.RunID, "run", "", "filter by run id")
	windows.Flags().StringVar(&windowsFilter.SessionID, "session", "", "filter by session id")
	windows.Flags().StringVar(&windowsFilter.ToolCallID, "tool-call", "", "filter by tool call id")
	windows.Flags().StringVar(&windowsFilter.Type, "type", "", "filter by event type")
	windows.Flags().StringVar(&windowsFilter.Source, "source", "", "filter by telemetry source")
	windows.Flags().IntVar(&windowsFilter.WindowSeconds, "window", 0, "filter by window size in seconds, usually 10 or 60")
	windows.Flags().BoolVar(&windowsJSON, "json", false, "emit structured telemetry event window JSON")
	cmd.AddCommand(windows)
	return cmd
}

func telemetryCorrelations(dataDir, daemonURL, runID, eventID string) (telemetry.CorrelationReport, error) {
	if client, ok := daemonClient(daemonURL); ok {
		return client.TelemetryCorrelations(runID, eventID)
	}
	paths, err := store.Init(dataDir)
	if err != nil {
		return telemetry.CorrelationReport{}, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return telemetry.CorrelationReport{}, err
	}
	defer db.Close()
	return telemetry.BuildCorrelationReport(db, telemetry.CorrelationReportOptions{
		RunID:   runID,
		EventID: eventID,
	})
}

func telemetryPruneCmd(dataDir *string) *cobra.Command {
	var runID string
	var olderThan time.Duration
	var maxDelete int
	var jsonOut bool
	prune := &cobra.Command{
		Use:   "prune",
		Short: "prune old unreferenced raw telemetry events",
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
			result, err := telemetry.PruneRawEvents(db, telemetry.RetentionOptions{RunID: runID, OlderThan: olderThan, MaxDelete: maxDelete})
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "schema=%s run=%s cutoff=%s scanned=%d deleted=%d protected=%d max_delete=%d\n",
				result.SchemaVersion, result.RunID, result.Cutoff, result.Scanned, result.Deleted, result.Protected, result.MaxDelete)
			return nil
		},
	}
	prune.Flags().StringVar(&runID, "run", "", "filter by run id")
	prune.Flags().DurationVar(&olderThan, "older-than", 10*time.Minute, "delete unreferenced telemetry events older than this duration")
	prune.Flags().IntVar(&maxDelete, "max-delete", 1000, "maximum events to delete in one prune run")
	prune.Flags().BoolVar(&jsonOut, "json", false, "emit structured telemetry retention JSON")
	return prune
}

func telemetryIngestFalcoCmd(dataDir *string) *cobra.Command {
	var opts telemetry.FalcoIngestOptions
	var jsonOut bool
	var noPolicy bool
	ingest := &cobra.Command{
		Use:   "ingest-falco",
		Short: "ingest Falco JSON/stdout events and map them into runtime telemetry",
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
			var input *os.File
			if opts.Path == "" || opts.Path == "-" {
				input = os.Stdin
				if opts.Path == "" {
					opts.Path = "stdin"
				}
			} else {
				input, err = os.Open(opts.Path)
				if err != nil {
					return err
				}
				defer input.Close()
			}
			daemon.WarnIfDaemonActive(*dataDir, cmd.ErrOrStderr())
			result, err := telemetry.IngestFalco(db, opts, input)
			if err != nil {
				return err
			}
			if !noPolicy {
				evaluateTelemetryPolicy(db, &result)
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"schema_version":   "agentprovenance.falco_ingest/v1",
					"batch":            result,
					"policy_decisions": result.PolicyDecisions,
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "batch=%s format=falco path=%s file_sha256=%s event_ids_sha256=%s read=%d ingested=%d skipped=%d failed=%d policy_decisions=%d\n",
				result.BatchID, result.Path, result.FileSHA256, result.EventIDsSHA256, result.Read, result.Ingested, result.Skipped, result.Failed, result.PolicyDecisions)
			for _, msg := range result.Errors {
				fmt.Fprintf(cmd.OutOrStdout(), "error=%q\n", msg)
			}
			return nil
		},
	}
	ingest.Flags().StringVar(&opts.Path, "file", "-", "Falco JSON/stdout file path, or - for stdin")
	ingest.Flags().StringVar(&opts.RunID, "run", "", "default run id")
	ingest.Flags().StringVar(&opts.RolloutID, "trajectory", "", "default trajectory id")
	ingest.Flags().StringVar(&opts.RolloutID, "rollout", "", "legacy alias for --trajectory")
	ingest.Flags().StringVar(&opts.AttemptID, "execution-scope", "", "default execution scope id")
	ingest.Flags().StringVar(&opts.AttemptID, "attempt", "", "legacy alias for --execution-scope")
	ingest.Flags().StringVar(&opts.SessionID, "substrate-scope", "", "default substrate scope id")
	ingest.Flags().StringVar(&opts.SessionID, "session", "", "legacy alias for --substrate-scope")
	ingest.Flags().StringVar(&opts.ToolCallID, "tool-call", "", "default tool call id")
	ingest.Flags().StringVar(&opts.ProcessID, "process", "", "default process id")
	ingest.Flags().StringVar(&opts.SnapshotID, "artifact-state", "", "default artifact state id")
	ingest.Flags().StringVar(&opts.SnapshotID, "snapshot", "", "legacy alias for --artifact-state")
	ingest.Flags().BoolVar(&noPolicy, "no-policy", false, "disable automatic policy/risk/response evaluation")
	ingest.Flags().BoolVar(&jsonOut, "json", false, "emit JSON result")
	hideTelemetryLegacyScopeFlags(ingest)
	return ingest
}

func telemetryBindCmd(dataDir *string) *cobra.Command {
	var binding correlation.Binding
	bind := &cobra.Command{
		Use:   "bind",
		Short: "register an execution-scope binding for runtime telemetry correlation",
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
			daemon.WarnIfDaemonActive(*dataDir, cmd.ErrOrStderr())
			id, err := correlation.RecordBinding(db, binding)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "binding_id=%s run=%s substrate_scope=%s execution_scope=%s tool_call=%s process=%s container=%s cgroup=%s pid=%d source=%s confidence=%.2f\n",
				id, binding.RunID, binding.SessionID, binding.AttemptID, binding.ToolCallID, binding.ProcessID, binding.ContainerID, binding.CgroupID, binding.PID, binding.BindingSource, binding.Confidence)
			return nil
		},
	}
	bind.Flags().StringVar(&binding.RunID, "run", "", "run id")
	bind.Flags().StringVar(&binding.SessionID, "substrate-scope", "", "substrate scope id")
	bind.Flags().StringVar(&binding.SessionID, "session", "", "legacy alias for --substrate-scope")
	bind.Flags().StringVar(&binding.AttemptID, "execution-scope", "", "execution scope id")
	bind.Flags().StringVar(&binding.AttemptID, "attempt", "", "legacy alias for --execution-scope")
	bind.Flags().StringVar(&binding.ToolCallID, "tool-call", "", "tool call id")
	bind.Flags().StringVar(&binding.ProcessID, "process", "", "process id")
	bind.Flags().StringVar(&binding.ContainerID, "container-id", "", "container id visible to runtime telemetry")
	bind.Flags().StringVar(&binding.CgroupID, "cgroup-id", "", "cgroup id visible to runtime telemetry")
	bind.Flags().Int64Var(&binding.RootPID, "root-pid", 0, "root pid for the tool scope")
	bind.Flags().Int64Var(&binding.PID, "pid", 0, "pid or child pid visible to runtime telemetry")
	bind.Flags().StringVar(&binding.StartedAt, "started-at", "", "binding start time; defaults to now")
	bind.Flags().StringVar(&binding.EndedAt, "ended-at", "", "binding end time; empty means open")
	bind.Flags().StringVar(&binding.BindingSource, "source", "harness_tool_call_scope", "binding source")
	bind.Flags().Float64Var(&binding.Confidence, "confidence", 1, "binding confidence")
	_ = bind.MarkFlagRequired("run")
	_ = bind.MarkFlagRequired("tool-call")
	_ = bind.Flags().MarkHidden("session")
	_ = bind.Flags().MarkHidden("attempt")
	return bind
}

func telemetryBindingsCmd(dataDir *string) *cobra.Command {
	var filter correlation.BindingFilter
	bindings := &cobra.Command{
		Use:   "bindings",
		Short: "list ToolCallScope bindings",
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
			items, err := correlation.ListBindings(db, filter)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tRUN\tSUBSTRATE_SCOPE\tEXECUTION_SCOPE\tTOOL_CALL\tPROCESS\tCONTAINER\tCGROUP\tROOT_PID\tPID\tSOURCE\tCONFIDENCE\tSTARTED_AT\tENDED_AT")
			for _, item := range items {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%.2f\t%s\t%s\n",
					item.ID, item.RunID, item.SessionID, item.AttemptID, item.ToolCallID, item.ProcessID, item.ContainerID, item.CgroupID, item.RootPID, item.PID, item.BindingSource, item.Confidence, item.StartedAt, item.EndedAt)
			}
			return w.Flush()
		},
	}
	bindings.Flags().StringVar(&filter.RunID, "run", "", "filter by run id")
	bindings.Flags().StringVar(&filter.SessionID, "substrate-scope", "", "filter by substrate scope id")
	bindings.Flags().StringVar(&filter.SessionID, "session", "", "legacy alias for --substrate-scope")
	bindings.Flags().StringVar(&filter.AttemptID, "execution-scope", "", "filter by execution scope id")
	bindings.Flags().StringVar(&filter.AttemptID, "attempt", "", "legacy alias for --execution-scope")
	bindings.Flags().StringVar(&filter.ToolCallID, "tool-call", "", "filter by tool call id")
	bindings.Flags().StringVar(&filter.ProcessID, "process", "", "filter by process id")
	_ = bindings.Flags().MarkHidden("session")
	_ = bindings.Flags().MarkHidden("attempt")
	return bindings
}

func telemetryIngestCmd(dataDir *string) *cobra.Command {
	var event telemetry.IngestEvent
	ingest := &cobra.Command{
		Use:   "ingest",
		Short: "ingest a filtered high-value telemetry event",
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
			id, err := telemetry.IngestFiltered(db, event)
			if err != nil {
				return err
			}
			_, _ = telemetry.RebuildEventWindows(db, event.RunID)
			fmt.Fprintf(cmd.OutOrStdout(), "event_id=%s type=%s source=%s\n", id, event.EventType, event.Source)
			return nil
		},
	}
	ingest.Flags().StringVar(&event.RunID, "run", "", "run id")
	ingest.Flags().StringVar(&event.RolloutID, "trajectory", "", "trajectory id")
	ingest.Flags().StringVar(&event.RolloutID, "rollout", "", "legacy alias for --trajectory")
	ingest.Flags().StringVar(&event.AttemptID, "execution-scope", "", "execution scope id")
	ingest.Flags().StringVar(&event.AttemptID, "attempt", "", "legacy alias for --execution-scope")
	ingest.Flags().StringVar(&event.SessionID, "substrate-scope", "", "substrate scope id")
	ingest.Flags().StringVar(&event.SessionID, "session", "", "legacy alias for --substrate-scope")
	ingest.Flags().StringVar(&event.ToolCallID, "tool-call", "", "tool call id")
	ingest.Flags().StringVar(&event.ProcessID, "process", "", "process id")
	ingest.Flags().StringVar(&event.SnapshotID, "artifact-state", "", "artifact state id")
	ingest.Flags().StringVar(&event.SnapshotID, "snapshot", "", "legacy alias for --artifact-state")
	ingest.Flags().StringVar(&event.RawEventID, "raw-event", "", "raw telemetry event id from the substrate")
	ingest.Flags().StringVar(&event.ContainerID, "container-id", "", "container id observed by runtime telemetry")
	ingest.Flags().StringVar(&event.CgroupID, "cgroup-id", "", "cgroup id observed by runtime telemetry")
	ingest.Flags().Int64Var(&event.PID, "pid", 0, "pid observed by runtime telemetry")
	ingest.Flags().Int64Var(&event.TGID, "tgid", 0, "tgid observed by runtime telemetry")
	ingest.Flags().Int64Var(&event.PPID, "ppid", 0, "parent pid observed by runtime telemetry")
	ingest.Flags().StringVar(&event.Timestamp, "timestamp", "", "runtime event timestamp; defaults to ingest time")
	ingest.Flags().StringVar(&event.Source, "source", "filtered_telemetry", "telemetry source")
	ingest.Flags().StringVar(&event.EventType, "type", "", "filtered event type")
	ingest.Flags().StringVar(&event.Payload, "payload", "{}", "JSON payload")
	_ = ingest.MarkFlagRequired("type")
	hideTelemetryLegacyScopeFlags(ingest)
	return ingest
}

func telemetryIngestJSONLCmd(dataDir *string) *cobra.Command {
	var opts telemetry.JSONLIngestOptions
	var jsonOut bool
	var noPolicy bool
	ingest := &cobra.Command{
		Use:   "ingest-jsonl",
		Short: "ingest filtered substrate telemetry JSONL from Tetragon, Falco, LoongCollector, or the agentprov eBPF sensor",
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
			daemon.WarnIfDaemonActive(*dataDir, cmd.ErrOrStderr())
			result, err := telemetry.IngestJSONL(db, opts)
			if err != nil {
				return err
			}
			if !noPolicy {
				evaluateTelemetryPolicy(db, &result)
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "batch=%s format=%s path=%s file_sha256=%s event_ids_sha256=%s read=%d ingested=%d skipped=%d failed=%d policy_decisions=%d\n",
				result.BatchID, result.Format, result.Path, result.FileSHA256, result.EventIDsSHA256, result.Read, result.Ingested, result.Skipped, result.Failed, result.PolicyDecisions)
			for _, msg := range result.Errors {
				fmt.Fprintf(cmd.OutOrStdout(), "error=%q\n", msg)
			}
			return nil
		},
	}
	ingest.Flags().StringVar(&opts.Format, "format", "auto", "jsonl format: auto, tetragon, falco, loongcollector, or native (agentprov eBPF sensor)")
	ingest.Flags().StringVar(&opts.Path, "file", "", "JSONL file path, or - to read a piped stream from stdin (e.g. the agentprov sensor)")
	ingest.Flags().StringVar(&opts.RunID, "run", "", "default run id")
	ingest.Flags().StringVar(&opts.RolloutID, "trajectory", "", "default trajectory id")
	ingest.Flags().StringVar(&opts.RolloutID, "rollout", "", "legacy alias for --trajectory")
	ingest.Flags().StringVar(&opts.AttemptID, "execution-scope", "", "default execution scope id")
	ingest.Flags().StringVar(&opts.AttemptID, "attempt", "", "legacy alias for --execution-scope")
	ingest.Flags().StringVar(&opts.SessionID, "substrate-scope", "", "default substrate scope id")
	ingest.Flags().StringVar(&opts.SessionID, "session", "", "legacy alias for --substrate-scope")
	ingest.Flags().StringVar(&opts.ToolCallID, "tool-call", "", "default tool call id")
	ingest.Flags().StringVar(&opts.ProcessID, "process", "", "default process id")
	ingest.Flags().StringVar(&opts.SnapshotID, "artifact-state", "", "default artifact state id")
	ingest.Flags().StringVar(&opts.SnapshotID, "snapshot", "", "legacy alias for --artifact-state")
	ingest.Flags().BoolVar(&noPolicy, "no-policy", false, "disable automatic policy/risk/response evaluation")
	ingest.Flags().BoolVar(&jsonOut, "json", false, "emit JSON result")
	_ = ingest.MarkFlagRequired("file")
	hideTelemetryLegacyScopeFlags(ingest)
	return ingest
}

func hideTelemetryLegacyScopeFlags(cmd *cobra.Command) {
	for _, name := range []string{"rollout", "attempt", "session", "snapshot"} {
		_ = cmd.Flags().MarkHidden(name)
	}
}

func evaluateTelemetryPolicy(db *sql.DB, result *telemetry.JSONLIngestResult) {
	if result == nil {
		return
	}
	for _, eventID := range result.EventIDs {
		record, persisted, err := securitymodel.EvaluateRuntimeEvent(db, eventID)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("event %s: policy failed: %v", eventID, err))
			result.Failed++
			continue
		}
		if persisted {
			result.PolicyDecisions++
			result.PolicyDecisionIDs = append(result.PolicyDecisionIDs, record.ID)
		}
	}
}
