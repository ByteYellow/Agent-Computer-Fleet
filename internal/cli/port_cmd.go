package cli

import (
	"fmt"
	"github.com/byteyellow/agent-computer-fleet/internal/ports"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
	"text/tabwriter"
)

func portCmd(dataDir *string) *cobra.Command {
	expose := &cobra.Command{
		Use:   "expose <session_id> <port>",
		Short: "expose a sandbox HTTP port through a local preview proxy",
		Args:  cobra.ExactArgs(2),
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
			var port int
			if _, err := fmt.Sscanf(args[1], "%d", &port); err != nil {
				return err
			}
			info, err := (ports.Service{DB: db, Paths: paths}).Expose(args[0], port)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "port_id=%s preview_url=%s host_port=%d container_port=%d pid=%d status=%s\n", info.ID, info.PreviewURL, info.HostPort, info.ContainerPort, info.PID, info.Status)
			return nil
		},
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "list preview port proxies",
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
			items, err := (ports.Service{DB: db, Paths: paths}).List()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSESSION\tRUN\tCONTAINER_PORT\tHOST_PORT\tSTATUS\tPID\tURL")
			for _, item := range items {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%s\t%d\t%s\n", item.ID, item.SessionID, item.RunID, item.ContainerPort, item.HostPort, item.Status, item.PID, item.PreviewURL)
			}
			return w.Flush()
		},
	}
	closeCmd := &cobra.Command{
		Use:   "close <port_id>",
		Short: "close a preview port proxy",
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
			if err := (ports.Service{DB: db, Paths: paths}).Close(args[0]); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "closed")
			return nil
		},
	}
	serve := &cobra.Command{
		Use:    "serve <port_id>",
		Short:  "run the local preview proxy server",
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
			return (ports.Service{DB: db, Paths: paths}).Serve(args[0])
		},
	}
	cmd := &cobra.Command{Use: "port", Short: "port operations"}
	cmd.AddCommand(expose)
	cmd.AddCommand(list)
	cmd.AddCommand(closeCmd)
	cmd.AddCommand(serve)
	return cmd
}
