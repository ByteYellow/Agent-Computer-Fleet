package cli

import (
	"fmt"
	"github.com/byteyellow/agent-computer-fleet/internal/egress"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
)

func credentialCmd(dataDir *string) *cobra.Command {
	var runID, sessionID, name, host string
	inject := &cobra.Command{
		Use:   "inject",
		Short: "record proxy-side credential injection without exposing raw secret",
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
			if err := egress.InjectCredential(db, runID, sessionID, name, host); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "credential=%s host=%s injection=proxy_header raw_secret=redacted\n", name, host)
			return nil
		},
	}
	inject.Flags().StringVar(&runID, "run", "", "run id")
	inject.Flags().StringVar(&sessionID, "session", "", "session id")
	inject.Flags().StringVar(&name, "name", "", "credential name")
	inject.Flags().StringVar(&host, "host", "", "target host")
	_ = inject.MarkFlagRequired("run")
	_ = inject.MarkFlagRequired("name")
	_ = inject.MarkFlagRequired("host")
	cmd := &cobra.Command{Use: "credential", Short: "credential proxy commands"}
	cmd.AddCommand(inject)
	return cmd
}
