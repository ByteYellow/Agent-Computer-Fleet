package cli

import (
	"fmt"
	"github.com/byteyellow/agent-computer-fleet/internal/control"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
	"text/tabwriter"
)

func sessionCmd(dataDir, daemonURL *string) *cobra.Command {
	var leaseID string
	create := &cobra.Command{
		Use:   "create",
		Short: "create a Docker-backed sandbox session",
		RunE: func(cmd *cobra.Command, args []string) error {
			if client, ok := daemonClient(*daemonURL); ok {
				id, err := client.CreateSession(leaseID)
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), id)
				return nil
			}
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
			sessions, err := listSessions(*dataDir, *daemonURL)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSTATUS\tRUN\tRUNTIME\tCONTAINER\tRESUMED_FROM\tWORKSPACE\tSTARTUP_MS")
			for _, session := range sessions {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\n", session.ID, session.Status, session.RunID, session.RuntimeName, short(session.ContainerID), short(session.ResumedFromSnapshotID), session.WorkspacePath, session.StartupColdMS)
			}
			return w.Flush()
		},
	}
	inspect := &cobra.Command{
		Use:   "inspect <session_id>",
		Short: "inspect a sandbox session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			session, err := inspectSession(*dataDir, *daemonURL, args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "id=%s\nlease_id=%s\nrun_id=%s\nruntime=%s\ncontainer_id=%s\nworkspace=%s\nstatus=%s\nparent_snapshot_id=%s\nresumed_from_snapshot_id=%s\nstartup_cold_ms=%d\ncreated_at=%s\nupdated_at=%s\n",
				session.ID, session.LeaseID, session.RunID, session.RuntimeName, session.ContainerID, session.WorkspacePath, session.Status, session.ParentSnapshotID, session.ResumedFromSnapshotID, session.StartupColdMS, session.CreatedAt, session.UpdatedAt)
			return nil
		},
	}
	stop := &cobra.Command{
		Use:   "stop <session_id>",
		Short: "stop a sandbox session container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if client, ok := daemonClient(*daemonURL); ok {
				if err := client.StopSession(args[0]); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "stopped")
				return nil
			}
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
	var cpuProfile string
	profile := &cobra.Command{
		Use:   "cpu-profile <session_id>",
		Short: "set sandbox CPU profile for think/tool phases",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if client, ok := daemonClient(*daemonURL); ok {
				if err := client.SetSessionCPUProfile(args[0], cpuProfile); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "session_id=%s cpu_profile=%s\n", args[0], cpuProfile)
				return nil
			}
			svc, closeFn, err := controlSvc(*dataDir)
			if err != nil {
				return err
			}
			defer closeFn()
			if err := svc.SetSessionCPUProfile(args[0], cpuProfile); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "session_id=%s cpu_profile=%s\n", args[0], cpuProfile)
			return nil
		},
	}
	profile.Flags().StringVar(&cpuProfile, "profile", "think", "CPU profile: think or tool")
	remove := &cobra.Command{
		Use:     "rm <session_id>",
		Aliases: []string{"remove"},
		Short:   "remove a sandbox session container",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if client, ok := daemonClient(*daemonURL); ok {
				if err := client.RemoveSession(args[0]); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "removed")
				return nil
			}
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
	cmd.AddCommand(profile)
	cmd.AddCommand(remove)
	return cmd
}

func listSessions(dataDir, daemonURL string) ([]control.SessionInfo, error) {
	if client, ok := daemonClient(daemonURL); ok {
		return client.ListSessions()
	}
	paths, err := store.Init(dataDir)
	if err != nil {
		return nil, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return control.Service{DB: db, Paths: paths}.ListSessions()
}

func inspectSession(dataDir, daemonURL, sessionID string) (control.SessionInfo, error) {
	if client, ok := daemonClient(daemonURL); ok {
		return client.InspectSession(sessionID)
	}
	paths, err := store.Init(dataDir)
	if err != nil {
		return control.SessionInfo{}, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return control.SessionInfo{}, err
	}
	defer db.Close()
	return control.Service{DB: db, Paths: paths}.InspectSession(sessionID)
}
