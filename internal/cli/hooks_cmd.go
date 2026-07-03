package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/byteyellow/agentprovenance/internal/hooksbridge"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

// hooksCmd folds a harness hook log into the provenance graph: agent nodes,
// delegation spawn edges, peer SendMessage edges (body objectified as evidence), and a
// gate-scored tool_call per agent action (unsafe proposals become refused nodes).
func hooksCmd(dataDir *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hooks",
		Short: "Bridge harness orchestration hooks into the provenance graph",
	}
	cmd.AddCommand(hooksBridgeCmd(dataDir))
	return cmd
}

func hooksBridgeCmd(dataDir *string) *cobra.Command {
	var runID, file string
	var correlate bool
	cmd := &cobra.Command{
		Use:   "bridge",
		Short: "ingest a hook JSONL log into RUN's orchestration graph",
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

			r := cmd.InOrStdin()
			if file != "" && file != "-" {
				f, err := os.Open(file)
				if err != nil {
					return err
				}
				defer f.Close()
				r = f
			}
			sum, err := hooksbridge.Ingest(db, r, hooksbridge.Options{
				RunID:   runID,
				Objects: provenance.ObjectStore{DB: db, Paths: paths},
			})
			if err != nil {
				return err
			}
			syscalls := 0
			if correlate {
				syscalls, err = hooksbridge.CorrelateSyscalls(db, runID)
				if err != nil {
					return err
				}
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]any{
				"schema_version":      "agentprovenance.hooks_bridge/v1",
				"run":                 runID,
				"summary":             sum,
				"syscalls_attributed": syscalls,
			})
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "run id to attach the orchestration graph to")
	cmd.Flags().StringVar(&file, "file", "-", "hook JSONL file (default stdin)")
	cmd.Flags().BoolVar(&correlate, "correlate", true, "attribute sensor syscall events to the acting agent by command-match")
	return cmd
}
