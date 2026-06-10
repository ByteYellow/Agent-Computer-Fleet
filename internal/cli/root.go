package cli

import (
	"fmt"
	"text/tabwriter"

	"github.com/byteyellow/agent-computer-fleet/internal/attempt"
	"github.com/byteyellow/agent-computer-fleet/internal/control"
	"github.com/byteyellow/agent-computer-fleet/internal/economics"
	"github.com/byteyellow/agent-computer-fleet/internal/node"
	"github.com/byteyellow/agent-computer-fleet/internal/security"
	"github.com/byteyellow/agent-computer-fleet/internal/state"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
)

func NewRootCommand() *cobra.Command {
	var dataDir string
	root := &cobra.Command{
		Use:   "acfctl",
		Short: "Agent Computer Fleet control CLI",
	}
	root.PersistentFlags().StringVar(&dataDir, "data-dir", store.DefaultDataDir, "local acf data directory")

	root.AddCommand(initCmd(&dataDir))
	root.AddCommand(leaseCmd(&dataDir))
	root.AddCommand(sessionCmd(&dataDir))
	root.AddCommand(execCmd(&dataDir))
	root.AddCommand(processCmd(&dataDir))
	root.AddCommand(portCmd(&dataDir))
	root.AddCommand(snapshotCmd(&dataDir))
	root.AddCommand(forkCmd(&dataDir))
	root.AddCommand(attemptCmd(&dataDir))
	root.AddCommand(policyCmd(&dataDir))
	root.AddCommand(costCmd(&dataDir))
	root.AddCommand(benchCmd())
	return root
}

func controlSvc(dataDir string) (control.Service, func(), error) {
	paths, err := store.Init(dataDir)
	if err != nil {
		return control.Service{}, nil, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return control.Service{}, nil, err
	}
	rt, err := node.NewDockerRuntime()
	if err != nil {
		db.Close()
		return control.Service{}, nil, err
	}
	return control.Service{DB: db, Paths: paths, Runtime: rt}, func() { db.Close() }, nil
}

func initCmd(dataDir *string) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "initialize local acf state",
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := store.Init(*dataDir)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "initialized %s\n", paths.Root)
			return nil
		},
	}
}

func leaseCmd(dataDir *string) *cobra.Command {
	var taskPath string
	create := &cobra.Command{
		Use:   "create",
		Short: "create a sandbox lease",
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
			id, err := control.Service{DB: db, Paths: paths}.CreateLease(taskPath)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), id)
			return nil
		},
	}
	create.Flags().StringVar(&taskPath, "task", "", "task yaml path")
	_ = create.MarkFlagRequired("task")
	cmd := &cobra.Command{Use: "lease", Short: "lease operations"}
	cmd.AddCommand(create)
	return cmd
}

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

func execCmd(dataDir *string) *cobra.Command {
	var stream bool
	cmd := &cobra.Command{
		Use:   "exec <session_id> -- <command...>",
		Short: "execute a command in a sandbox session",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := controlSvc(*dataDir)
			if err != nil {
				return err
			}
			defer closeFn()
			processID, err := svc.Exec(args[0], args[1:], stream)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), processID)
			return nil
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			stream, _ = cmd.Flags().GetBool("stream")
		},
	}
	cmd.Flags().Bool("stream", false, "stream stdout/stderr")
	return cmd
}

func processCmd(dataDir *string) *cobra.Command {
	interrupt := &cobra.Command{
		Use:   "interrupt <process_id>",
		Short: "interrupt a running process",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := controlSvc(*dataDir)
			if err != nil {
				return err
			}
			defer closeFn()
			if err := svc.Interrupt(args[0]); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "interrupted")
			return nil
		},
	}
	cmd := &cobra.Command{Use: "process", Short: "process operations"}
	cmd.AddCommand(interrupt)
	return cmd
}

func portCmd(dataDir *string) *cobra.Command {
	expose := &cobra.Command{
		Use:   "expose <session_id> <port>",
		Short: "record a preview URL for a session port",
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
			url, err := control.Service{DB: db, Paths: paths}.ExposePort(args[0], port)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), url)
			return nil
		},
	}
	cmd := &cobra.Command{Use: "port", Short: "port operations"}
	cmd.AddCommand(expose)
	return cmd
}

func snapshotCmd(dataDir *string) *cobra.Command {
	var typ, path, name string
	create := &cobra.Command{
		Use:   "create <session_id>",
		Short: "create a workspace directory snapshot",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if typ != "directory" {
				return fmt.Errorf("only --type directory is supported")
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
			id, manifest, snapshotCreateMS, err := state.Service{DB: db, Paths: paths}.CreateDirectorySnapshot(args[0], path, name)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s files=%d bytes=%d snapshot_create_ms=%d hash=%s\n", id, manifest.Files, manifest.Bytes, snapshotCreateMS, manifest.Hash)
			return nil
		},
	}
	create.Flags().StringVar(&typ, "type", "directory", "snapshot type")
	create.Flags().StringVar(&path, "path", "/workspace", "path inside sandbox")
	create.Flags().StringVar(&name, "name", "", "snapshot name")
	var taskPath string
	stack := &cobra.Command{
		Use:   "stack",
		Short: "build a template -> ready snapshot -> attempt workspace stack",
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
			result, err := state.Service{DB: db, Paths: paths}.CreateStack(taskPath)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "template_snapshot=%s\nready_snapshot=%s\nattempt_id=%s workspace=%s fork_ms=%d\n", result.TemplateSnapshotID, result.ReadySnapshotID, result.Attempt.AttemptID, result.Attempt.WorkspacePath, result.Attempt.ForkMS)
			return nil
		},
	}
	stack.Flags().StringVar(&taskPath, "task", "", "task yaml path")
	_ = stack.MarkFlagRequired("task")
	list := &cobra.Command{
		Use:   "list",
		Short: "list snapshots with lineage metadata",
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
			snapshots, err := state.Service{DB: db, Paths: paths}.ListSnapshots()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tKIND\tPARENT\tSTATUS\tFILES\tBYTES\tHASH")
			for _, snapshot := range snapshots {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\n", snapshot.ID, snapshot.Name, snapshot.Kind, short(snapshot.ParentID), snapshot.Status, snapshot.FileCount, snapshot.Bytes, short(snapshot.ManifestHash))
			}
			return w.Flush()
		},
	}
	inspect := &cobra.Command{
		Use:   "inspect <snapshot_name_or_id>",
		Short: "inspect snapshot manifest, taint status, and lineage",
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
			snapshot, lineage, err := state.Service{DB: db, Paths: paths}.InspectSnapshot(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "id=%s\nname=%s\nkind=%s\nsource=%s\nparent_id=%s\nsession_id=%s\nstatus=%s\nfiles=%d\nbytes=%d\nmanifest_hash=%s\nsnapshot_create_ms=%d\npath=%s\ncreated_at=%s\n",
				snapshot.ID, snapshot.Name, snapshot.Kind, snapshot.Source, snapshot.ParentID, snapshot.SessionID, snapshot.Status, snapshot.FileCount, snapshot.Bytes, snapshot.ManifestHash, snapshot.SnapshotCreateMS, snapshot.Path, snapshot.CreatedAt)
			fmt.Fprintln(cmd.OutOrStdout(), "lineage:")
			for i, item := range lineage {
				fmt.Fprintf(cmd.OutOrStdout(), "  %d. id=%s kind=%s name=%s status=%s bytes=%d\n", i+1, item.ID, item.Kind, item.Name, item.Status, item.Bytes)
			}
			return nil
		},
	}
	cmd := &cobra.Command{Use: "snapshot", Short: "snapshot operations"}
	cmd.AddCommand(create)
	cmd.AddCommand(stack)
	cmd.AddCommand(list)
	cmd.AddCommand(inspect)
	return cmd
}

func forkCmd(dataDir *string) *cobra.Command {
	var count int
	cmd := &cobra.Command{
		Use:   "fork <snapshot_name_or_id>",
		Short: "fork prepared workspaces from a snapshot",
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
			results, err := state.Service{DB: db, Paths: paths}.Fork(args[0], count)
			if err != nil {
				return err
			}
			for _, result := range results {
				fmt.Fprintf(cmd.OutOrStdout(), "attempt_id=%s workspace=%s fork_ms=%d\n", result.AttemptID, result.WorkspacePath, result.ForkMS)
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&count, "count", 1, "number of prepared workspaces")
	return cmd
}

func attemptCmd(dataDir *string) *cobra.Command {
	var snapshot string
	var strategies []string
	bestOf := &cobra.Command{
		Use:   "best-of",
		Short: "fork attempts from one snapshot, execute strategies, and choose a winner",
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
			service := attempt.Service{DB: db, State: state.Service{DB: db, Paths: paths}}
			results, winner, err := service.BestOf(snapshot, strategies)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ATTEMPT\tSTRATEGY\tSTATUS\tEXIT\tWALL_MS\tSCORE\tWINNER\tOUTPUT")
			for _, result := range results {
				winnerMark := ""
				if result.IsWinner {
					winnerMark = "yes"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%.3f\t%s\t%s\n", result.AttemptID, result.Strategy, result.Status, result.ExitCode, result.WallMS, result.Score, winnerMark, result.OutputSummary)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "winner=%s strategy=%s workspace=%s score=%.3f\n", winner.AttemptID, winner.Strategy, winner.WorkspacePath, winner.Score)
			return nil
		},
	}
	bestOf.Flags().StringVar(&snapshot, "snapshot", "", "snapshot name or id")
	bestOf.Flags().StringArrayVar(&strategies, "strategy", nil, "strategy in name::command form; repeat for multiple attempts")
	_ = bestOf.MarkFlagRequired("snapshot")
	_ = bestOf.MarkFlagRequired("strategy")
	cmd := &cobra.Command{Use: "attempt", Short: "attempt execution and selection commands"}
	cmd.AddCommand(bestOf)
	return cmd
}

func policyCmd(dataDir *string) *cobra.Command {
	test := &cobra.Command{
		Use:   "test <events.jsonl>",
		Short: "evaluate JSONL events with the MVP policy engine",
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
			return security.EvaluateJSONLWithState(db, args[0], cmd.OutOrStdout())
		},
	}
	var runID string
	decisions := &cobra.Command{
		Use:   "decisions",
		Short: "list policy decisions",
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
			records, err := security.ListDecisions(db, runID)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tRUN\tSESSION\tDECISION\tREASON\tCREATED_AT")
			for _, record := range records {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", record.ID, record.RunID, record.SessionID, record.Decision, record.Reason, record.CreatedAt)
			}
			return w.Flush()
		},
	}
	decisions.Flags().StringVar(&runID, "run", "", "filter decisions by run id")
	cmd := &cobra.Command{Use: "policy", Short: "policy operations"}
	cmd.AddCommand(test)
	cmd.AddCommand(decisions)
	return cmd
}

func costCmd(dataDir *string) *cobra.Command {
	show := &cobra.Command{
		Use:   "show <run_id>",
		Short: "show run cost metrics",
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
			return economics.ShowCost(db, args[0], cmd.OutOrStdout())
		},
	}
	cmd := &cobra.Command{Use: "cost", Short: "cost operations"}
	cmd.AddCommand(show)
	return cmd
}

func benchCmd() *cobra.Command {
	var sessions int
	var idleRatio, cpuPerSession, physicalCPU, overcommitRatio, idleDiscount float64
	var memoryPerSessionMB, memoryTotalMB int64
	overcommit := &cobra.Command{
		Use:   "overcommit",
		Short: "simulate active-CPU-aware overcommit admission",
		RunE: func(cmd *cobra.Command, args []string) error {
			result := economics.SimulateOvercommit(sessions, idleRatio, cpuPerSession, physicalCPU, overcommitRatio, idleDiscount, memoryPerSessionMB, memoryTotalMB)
			fmt.Fprintf(cmd.OutOrStdout(), "sessions=%d idle_ratio=%.2f admitted=%d rejected=%d weighted_cpu=%.3f capacity_cpu=%.3f\n",
				result.Sessions, result.IdleRatio, result.Admitted, result.Rejected, result.WeightedCPU, result.CapacityCPU)
			return nil
		},
	}
	overcommit.Flags().IntVar(&sessions, "sessions", 20, "number of simulated sessions")
	overcommit.Flags().Float64Var(&idleRatio, "idle-ratio", 0.8, "fraction of each session treated as idle")
	overcommit.Flags().Float64Var(&cpuPerSession, "cpu-per-session", 1, "CPU request per simulated session")
	overcommit.Flags().Float64Var(&physicalCPU, "physical-cpu", 8, "physical CPU capacity")
	overcommit.Flags().Float64Var(&overcommitRatio, "overcommit-ratio", 2, "CPU overcommit ratio")
	overcommit.Flags().Float64Var(&idleDiscount, "idle-discount", 0.1, "idle CPU discount")
	overcommit.Flags().Int64Var(&memoryPerSessionMB, "memory-per-session-mb", 256, "memory request per simulated session")
	overcommit.Flags().Int64Var(&memoryTotalMB, "memory-total-mb", 8192, "node memory capacity")
	cmd := &cobra.Command{Use: "bench", Short: "benchmark and simulation commands"}
	cmd.AddCommand(overcommit)
	return cmd
}

func short(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}
