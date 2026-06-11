package cli

import (
	"fmt"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/byteyellow/agent-computer-fleet/internal/telemetry"
	"github.com/spf13/cobra"
	"text/tabwriter"
)

func telemetryCmd(dataDir *string) *cobra.Command {
	var runID, sessionID, eventType, toolCallID string
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
			events, err := telemetry.ListEventsFiltered(db, telemetry.Filter{
				RunID:      runID,
				SessionID:  sessionID,
				Type:       eventType,
				ToolCallID: toolCallID,
			})
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tRUN\tSESSION\tTOOL_CALL\tPROCESS\tSNAPSHOT\tSOURCE\tTYPE\tCREATED_AT")
			for _, event := range events {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", event.ID, event.RunID, event.SessionID, event.ToolCallID, event.ProcessID, event.SnapshotID, event.Source, event.EventType, event.CreatedAt)
			}
			return w.Flush()
		},
	}
	list.Flags().StringVar(&runID, "run", "", "filter by run id")
	list.Flags().StringVar(&sessionID, "session", "", "filter by session id")
	list.Flags().StringVar(&eventType, "type", "", "filter by event type")
	list.Flags().StringVar(&toolCallID, "tool-call", "", "filter by tool call id")
	cmd := &cobra.Command{Use: "telemetry", Short: "telemetry inspection commands"}
	cmd.AddCommand(list)
	cmd.AddCommand(telemetryIngestCmd(dataDir))
	return cmd
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
			fmt.Fprintf(cmd.OutOrStdout(), "event_id=%s type=%s source=%s\n", id, event.EventType, event.Source)
			return nil
		},
	}
	ingest.Flags().StringVar(&event.RunID, "run", "", "run id")
	ingest.Flags().StringVar(&event.RolloutID, "rollout", "", "rollout id")
	ingest.Flags().StringVar(&event.AttemptID, "attempt", "", "attempt id")
	ingest.Flags().StringVar(&event.SessionID, "session", "", "session id")
	ingest.Flags().StringVar(&event.ToolCallID, "tool-call", "", "tool call id")
	ingest.Flags().StringVar(&event.ProcessID, "process", "", "process id")
	ingest.Flags().StringVar(&event.SnapshotID, "snapshot", "", "snapshot id")
	ingest.Flags().StringVar(&event.Source, "source", "filtered_telemetry", "telemetry source")
	ingest.Flags().StringVar(&event.EventType, "type", "", "filtered event type")
	ingest.Flags().StringVar(&event.Payload, "payload", "{}", "JSON payload")
	_ = ingest.MarkFlagRequired("type")
	return ingest
}
