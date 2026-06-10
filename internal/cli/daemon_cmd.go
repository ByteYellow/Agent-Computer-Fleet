package cli

import (
	"fmt"
	"net/http"

	"github.com/byteyellow/agent-computer-fleet/internal/daemon"
	"github.com/spf13/cobra"
)

func daemonCmd(dataDir *string) *cobra.Command {
	var listen string
	serve := &cobra.Command{
		Use:   "serve",
		Short: "run the local Agent Computer daemon/API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			server, closeFn, err := daemon.NewServer(*dataDir)
			if err != nil {
				return err
			}
			defer closeFn()
			fmt.Fprintf(cmd.ErrOrStderr(), "acf daemon listening on http://%s\n", listen)
			return http.ListenAndServe(listen, server.Handler())
		},
	}
	serve.Flags().StringVar(&listen, "listen", "127.0.0.1:8574", "daemon listen address")
	cmd := &cobra.Command{Use: "daemon", Short: "local daemon/API server commands"}
	cmd.AddCommand(serve)
	return cmd
}
