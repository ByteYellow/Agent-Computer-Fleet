package cli

import (
	"fmt"
	"text/tabwriter"

	"github.com/byteyellow/agent-computer-fleet/internal/egress"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
)

func egressCmd(dataDir *string) *cobra.Command {
	var runID, sessionID, dstIP, host string
	start := &cobra.Command{
		Use:   "start",
		Short: "start or reuse the local egress proxy",
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
			info, err := (egress.Service{DB: db, Paths: paths}).EnsureProxy()
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "proxy_id=%s mode=%s proxy_url=%s container_proxy_url=%s network=%s pid=%d status=%s\n", info.ID, info.Mode, info.ProxyURL, info.ContainerProxyURL, info.NetworkName, info.PID, info.Status)
			return nil
		},
	}
	status := &cobra.Command{
		Use:   "status",
		Short: "list egress proxy processes",
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
			proxies, err := (egress.Service{DB: db, Paths: paths}).Status()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tRUN\tSESSION\tMODE\tSTATUS\tPID\tHOST_PORT\tNETWORK\tURL\tCONTAINER_URL")
			for _, proxy := range proxies {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\n", proxy.ID, proxy.RunID, proxy.SessionID, proxy.Mode, proxy.Status, proxy.PID, proxy.HostPort, proxy.NetworkName, proxy.ProxyURL, proxy.ContainerProxyURL)
			}
			return w.Flush()
		},
	}
	closeCmd := &cobra.Command{
		Use:   "close <proxy_id>",
		Short: "close an egress proxy process",
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
			if err := (egress.Service{DB: db, Paths: paths}).Close(args[0]); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "closed")
			return nil
		},
	}
	allow := &cobra.Command{
		Use:   "allow <host>",
		Short: "add a host to the egress allowlist",
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
			if err := (egress.Service{DB: db, Paths: paths}).AllowHost(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "allowed=%s\n", args[0])
			return nil
		},
	}
	check := &cobra.Command{
		Use:   "check",
		Short: "evaluate an egress proxy network event",
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
			decision, err := (egress.Service{DB: db, Paths: paths}).Check(runID, sessionID, dstIP, host)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "decision=%s reason=%s event_id=%s\n", decision.Decision, decision.Reason, decision.EventID)
			return nil
		},
	}
	check.Flags().StringVar(&runID, "run", "", "run id")
	check.Flags().StringVar(&sessionID, "session", "", "session id")
	check.Flags().StringVar(&dstIP, "dst-ip", "", "destination IP")
	check.Flags().StringVar(&host, "host", "", "destination host")
	_ = check.MarkFlagRequired("run")
	_ = check.MarkFlagRequired("dst-ip")
	var listenAddr string
	serve := &cobra.Command{
		Use:    "serve <proxy_id>",
		Short:  "run the local egress proxy server",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
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
			return (egress.Service{DB: db, Paths: paths}).ServeAt(args[0], listenAddr)
		},
	}
	serve.Flags().StringVar(&listenAddr, "listen", "", "listen address override")
	cmd := &cobra.Command{Use: "egress", Short: "egress proxy commands"}
	cmd.AddCommand(start)
	cmd.AddCommand(status)
	cmd.AddCommand(closeCmd)
	cmd.AddCommand(allow)
	cmd.AddCommand(check)
	cmd.AddCommand(serve)
	return cmd
}
