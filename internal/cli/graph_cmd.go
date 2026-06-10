package cli

import (
	"github.com/byteyellow/agent-computer-fleet/internal/provenance"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
)

func graphCmd(dataDir *string) *cobra.Command {
	var runID string
	trace := &cobra.Command{
		Use:   "trace",
		Short: "trace run provenance across sessions, processes, snapshots, and policy decisions",
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
			return provenance.TraceRun(db, runID, cmd.OutOrStdout())
		},
	}
	trace.Flags().StringVar(&runID, "run", "", "run id")
	_ = trace.MarkFlagRequired("run")
	cmd := &cobra.Command{Use: "graph", Short: "provenance graph commands"}
	cmd.AddCommand(trace)
	return cmd
}
