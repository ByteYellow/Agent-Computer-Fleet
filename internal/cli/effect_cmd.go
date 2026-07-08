package cli

import (
	"database/sql"
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/effects"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func effectCmd(dataDir *string) *cobra.Command {
	var input effects.CreateInput
	record := &cobra.Command{
		Use:   "record",
		Short: "record an external side-effect intent or gate result",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, cleanup, err := effectDB(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			record, err := effects.RecordEffect(db, input)
			if err != nil {
				return err
			}
			effects.Print([]effects.Record{record}, cmd.OutOrStdout())
			return nil
		},
	}
	record.Flags().StringVar(&input.RunID, "run", "", "run id")
	record.Flags().StringVar(&input.RolloutID, "trajectory", "", "trajectory id")
	record.Flags().StringVar(&input.RolloutID, "rollout", "", "legacy alias for --trajectory")
	record.Flags().StringVar(&input.AttemptID, "execution-scope", "", "execution scope id")
	record.Flags().StringVar(&input.AttemptID, "attempt", "", "legacy alias for --execution-scope")
	record.Flags().StringVar(&input.SessionID, "substrate-scope", "", "substrate scope id")
	record.Flags().StringVar(&input.SessionID, "session", "", "legacy alias for --substrate-scope")
	record.Flags().StringVar(&input.ToolCallID, "tool-call", "", "tool call id")
	record.Flags().StringVar(&input.ProcessID, "process", "", "process id")
	record.Flags().StringVar(&input.EffectType, "type", "", "external effect type, for example api_call, db_write, message_send")
	record.Flags().StringVar(&input.Target, "target", "", "external target, for example host/path, table, queue, or room")
	record.Flags().StringVar(&input.Mode, "mode", "dry-run", "dry-run, mock, allowlist, or compensation")
	record.Flags().StringVar(&input.Decision, "decision", "audit", "allow, deny, or audit")
	record.Flags().StringVar(&input.CompensationRef, "compensation", "", "optional compensation hook or ticket reference")
	record.Flags().StringVar(&input.Payload, "payload", "{}", "redacted structured payload")
	_ = record.Flags().MarkHidden("rollout")
	_ = record.Flags().MarkHidden("attempt")
	_ = record.Flags().MarkHidden("session")

	var filter effects.Filter
	list := &cobra.Command{
		Use:   "list",
		Short: "list recorded external effect records",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, cleanup, err := effectDB(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			if filter.RunID == "" && filter.AttemptID == "" && filter.ToolCallID == "" {
				return fmt.Errorf("one of --run, --execution-scope/--attempt, or --tool-call is required")
			}
			records, err := effects.List(db, filter)
			if err != nil {
				return err
			}
			effects.Print(records, cmd.OutOrStdout())
			return nil
		},
	}
	list.Flags().StringVar(&filter.RunID, "run", "", "run id")
	list.Flags().StringVar(&filter.AttemptID, "execution-scope", "", "execution scope id")
	list.Flags().StringVar(&filter.AttemptID, "attempt", "", "legacy alias for --execution-scope")
	list.Flags().StringVar(&filter.ToolCallID, "tool-call", "", "tool call id")
	_ = list.Flags().MarkHidden("attempt")

	cmd := &cobra.Command{Use: "effect", Short: "external effect provenance records"}
	cmd.AddCommand(record)
	cmd.AddCommand(list)
	return cmd
}

func effectDB(dataDir string) (*sql.DB, func(), error) {
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
