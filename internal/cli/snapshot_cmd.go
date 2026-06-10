package cli

import (
	"fmt"
	"github.com/byteyellow/agent-computer-fleet/internal/state"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
	"text/tabwriter"
)

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
	var taskPath, templateName string
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
			var result state.StackResult
			if templateName != "" {
				result, err = (state.Service{DB: db, Paths: paths}).CreateStackFromTemplate(templateName)
			} else if taskPath != "" {
				result, err = (state.Service{DB: db, Paths: paths}).CreateStack(taskPath)
			} else {
				return fmt.Errorf("one of --task or --template is required")
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "template_snapshot=%s\nready_snapshot=%s\nattempt_id=%s workspace=%s fork_ms=%d\n", result.TemplateSnapshotID, result.ReadySnapshotID, result.Attempt.AttemptID, result.Attempt.WorkspacePath, result.Attempt.ForkMS)
			return nil
		},
	}
	stack.Flags().StringVar(&taskPath, "task", "", "task yaml path")
	stack.Flags().StringVar(&templateName, "template", "", "template name or id")
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
			fmt.Fprintln(w, "ID\tNAME\tKIND\tPARENT\tSTATUS\tTAINTED\tFILES\tBYTES\tHASH")
			for _, snapshot := range snapshots {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%t\t%d\t%d\t%s\n", snapshot.ID, snapshot.Name, snapshot.Kind, short(snapshot.ParentID), snapshot.Status, snapshot.Status == "tainted", snapshot.FileCount, snapshot.Bytes, short(snapshot.ManifestHash))
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
			fmt.Fprintf(cmd.OutOrStdout(), "id=%s\nname=%s\nkind=%s\nsource=%s\nparent_id=%s\nsession_id=%s\nstatus=%s\ntainted=%t\nfiles=%d\nbytes=%d\nmanifest_hash=%s\nsnapshot_create_ms=%d\npath=%s\ncreated_at=%s\n",
				snapshot.ID, snapshot.Name, snapshot.Kind, snapshot.Source, snapshot.ParentID, snapshot.SessionID, snapshot.Status, snapshot.Status == "tainted", snapshot.FileCount, snapshot.Bytes, snapshot.ManifestHash, snapshot.SnapshotCreateMS, snapshot.Path, snapshot.CreatedAt)
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
