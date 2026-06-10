package cli

import (
	"fmt"
	"os"

	"github.com/byteyellow/agent-computer-fleet/internal/egress"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
)

func credentialCmd(dataDir *string) *cobra.Command {
	var runID, sessionID, name, host, value, headerName, pathPrefix string
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
			if value == "" {
				value = os.Getenv("ACF_CREDENTIAL_VALUE")
			}
			if err := (egress.Service{DB: db, Paths: paths}).InjectCredential(runID, sessionID, egress.CredentialSpec{
				Name:       name,
				Host:       host,
				PathPrefix: pathPrefix,
				HeaderName: headerName,
				Value:      value,
			}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "credential=%s host=%s header=%s injection=proxy_header raw_secret=redacted\n", name, host, headerName)
			return nil
		},
	}
	inject.Flags().StringVar(&runID, "run", "", "run id")
	inject.Flags().StringVar(&sessionID, "session", "", "session id")
	inject.Flags().StringVar(&name, "name", "", "credential name")
	inject.Flags().StringVar(&host, "host", "", "target host")
	inject.Flags().StringVar(&value, "value", "", "credential value; alternatively use ACF_CREDENTIAL_VALUE")
	inject.Flags().StringVar(&headerName, "header", "Authorization", "header name injected by the proxy")
	inject.Flags().StringVar(&pathPrefix, "path-prefix", "/", "URL path prefix for injection")
	_ = inject.MarkFlagRequired("run")
	_ = inject.MarkFlagRequired("name")
	_ = inject.MarkFlagRequired("host")
	cmd := &cobra.Command{Use: "credential", Short: "credential proxy commands"}
	cmd.AddCommand(inject)
	return cmd
}
