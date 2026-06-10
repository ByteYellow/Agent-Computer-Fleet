package cli

import (
	"fmt"
	"github.com/byteyellow/agent-computer-fleet/internal/envtemplate"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
	"text/tabwriter"
)

func templateCmd(dataDir *string) *cobra.Command {
	var taskPath, name string
	build := &cobra.Command{
		Use:   "build",
		Short: "build a reusable environment template from a task yaml",
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
			info, err := (envtemplate.Service{DB: db, Paths: paths}).Build(taskPath, name)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "template_id=%s name=%s image=%s risk_tier=%s network_mode=%s bytes=%d manifest_hash=%s\n",
				info.ID, info.Name, info.Image, info.RiskTier, info.NetworkMode, info.Bytes, info.ManifestHash)
			return nil
		},
	}
	build.Flags().StringVar(&taskPath, "task", "", "task yaml path")
	build.Flags().StringVar(&name, "name", "", "template name")
	_ = build.MarkFlagRequired("task")

	list := &cobra.Command{
		Use:   "list",
		Short: "list environment templates",
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
			templates, err := (envtemplate.Service{DB: db, Paths: paths}).List()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tIMAGE\tRISK\tNETWORK\tSTATUS\tBYTES\tHASH")
			for _, item := range templates {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n", item.ID, item.Name, item.Image, item.RiskTier, item.NetworkMode, item.Status, item.Bytes, short(item.ManifestHash))
			}
			return w.Flush()
		},
	}

	inspect := &cobra.Command{
		Use:   "inspect <template_name_or_id>",
		Short: "inspect an environment template bundle",
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
			info, task, err := (envtemplate.Service{DB: db, Paths: paths}).Inspect(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "id=%s\nname=%s\ntask_path=%s\nimage=%s\nrisk_tier=%s\nnetwork_mode=%s\ncpu_request=%.2f\nmemory_mb=%d\ncommand=%v\nstatus=%s\nbytes=%d\nmanifest_hash=%s\ncreated_at=%s\n",
				info.ID, info.Name, info.TaskPath, info.Image, info.RiskTier, info.NetworkMode, task.CPURequest, task.MemoryMB, task.Command, info.Status, info.Bytes, info.ManifestHash, info.CreatedAt)
			return nil
		},
	}

	cmd := &cobra.Command{Use: "template", Short: "environment template operations"}
	cmd.AddCommand(build)
	cmd.AddCommand(list)
	cmd.AddCommand(inspect)
	return cmd
}
