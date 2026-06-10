package cli

import (
	"fmt"
	"github.com/byteyellow/agent-computer-fleet/internal/forensics"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
)

func forensicsCmd(dataDir *string) *cobra.Command {
	export := &cobra.Command{
		Use:   "export <run_id>",
		Short: "export a forensics bundle for a run",
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
			bundle, err := (forensics.Service{DB: db, Paths: paths}).ExportBundle(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "bundle_id=%s path=%s sha256=%s size_bytes=%d\n", bundle.ID, bundle.Path, bundle.SHA256, bundle.SizeBytes)
			return nil
		},
	}
	cmd := &cobra.Command{Use: "forensics", Short: "forensics bundle commands"}
	cmd.AddCommand(export)
	return cmd
}
