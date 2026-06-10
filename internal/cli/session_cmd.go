package cli

import (
	"fmt"
	"github.com/byteyellow/agent-computer-fleet/internal/control"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
	"text/tabwriter"
)

func sessionCmd(dataDir *string) *cobra.Command {
	var leaseID string
	create := &cobra.Command{
		Use:   "create",
		Short: "create a Docker-backed sandbox session",
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := controlSvc(*dataDir)
			if err != nil {
				return err
			}
			defer closeFn()
			id, err := svc.CreateSession(leaseID)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), id)
			return nil
		},
	}
	create.Flags().StringVar(&leaseID, "lease", "", "lease id")
	_ = create.MarkFlagRequired("lease")
	list := &cobra.Command{
		Use:   "list",
		Short: "list sandbox sessions",
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
			sessions, err := control.Service{DB: db, Paths: paths}.ListSessions()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSTATUS\tRUN\tCONTAINER\tWORKSPACE\tSTARTUP_MS")
			for _, session := range sessions {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\n", session.ID, session.Status, session.RunID, short(session.ContainerID), session.WorkspacePath, session.StartupColdMS)
			}
			return w.Flush()
		},
	}
	inspect := &cobra.Command{
		Use:   "inspect <session_id>",
		Short: "inspect a sandbox session",
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
			session, err := control.Service{DB: db, Paths: paths}.InspectSession(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "id=%s\nlease_id=%s\nrun_id=%s\ncontainer_id=%s\nworkspace=%s\nstatus=%s\nstartup_cold_ms=%d\ncreated_at=%s\nupdated_at=%s\n",
				session.ID, session.LeaseID, session.RunID, session.ContainerID, session.WorkspacePath, session.Status, session.StartupColdMS, session.CreatedAt, session.UpdatedAt)
			return nil
		},
	}
	stop := &cobra.Command{
		Use:   "stop <session_id>",
		Short: "stop a sandbox session container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := controlSvc(*dataDir)
			if err != nil {
				return err
			}
			defer closeFn()
			if err := svc.StopSession(args[0]); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "stopped")
			return nil
		},
	}
	remove := &cobra.Command{
		Use:     "rm <session_id>",
		Aliases: []string{"remove"},
		Short:   "remove a sandbox session container",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := controlSvc(*dataDir)
			if err != nil {
				return err
			}
			defer closeFn()
			if err := svc.RemoveSession(args[0]); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "removed")
			return nil
		},
	}
	cmd := &cobra.Command{Use: "session", Short: "session operations"}
	cmd.AddCommand(create)
	cmd.AddCommand(list)
	cmd.AddCommand(inspect)
	cmd.AddCommand(stop)
	cmd.AddCommand(remove)
	return cmd
}
