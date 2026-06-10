package cli

import (
	"fmt"

	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/byteyellow/agent-computer-fleet/internal/warm"
	"github.com/spf13/cobra"
	"text/tabwriter"
)

func poolCmd(dataDir *string) *cobra.Command {
	var templateName string
	var size int
	var seedWorkspace string
	var maxSize int
	create := &cobra.Command{
		Use:   "create",
		Short: "create warm pool items for a template",
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
			service := warm.Service{DB: db, Paths: paths}
			items, err := service.CreateFromSeed(templateName, size, seedWorkspace)
			if err != nil {
				return err
			}
			for _, item := range items {
				fmt.Fprintf(cmd.OutOrStdout(), "pool_id=%s template=%s workspace=%s priority=%.3f status=%s\n", item.ID, item.TemplateName, item.WorkspacePath, item.Priority, item.Status)
			}
			if maxSize > 0 {
				if evicted, ok, err := service.EvictIfOverLimit(templateName, maxSize); err != nil {
					return err
				} else if ok {
					fmt.Fprintf(cmd.OutOrStdout(), "evicted pool_id=%s template=%s priority=%.3f reason=%s\n", evicted.ID, evicted.TemplateName, evicted.Priority, evicted.EvictionReason)
				}
			}
			return nil
		},
	}
	create.Flags().StringVar(&templateName, "template", "", "template name")
	create.Flags().IntVar(&size, "size", 1, "warm pool size")
	create.Flags().StringVar(&seedWorkspace, "seed-workspace", "", "copy this workspace into each warm pool item")
	create.Flags().IntVar(&maxSize, "max-size", 0, "evict with GDSF until ready pool items fit this size")
	_ = create.MarkFlagRequired("template")

	status := &cobra.Command{
		Use:   "status",
		Short: "show warm pool status and Greedy-Dual priorities",
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
			items, err := (warm.Service{DB: db, Paths: paths}).Status()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tTEMPLATE\tSTATUS\tFREQ\tHITS\tSAVED_MS\tMEMORY_MB\tDISK_BYTES\tPRIORITY\tEVICTION\tWORKSPACE")
			for _, item := range items {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%.3f\t%s\t%s\n", item.ID, item.TemplateName, item.Status, item.Frequency, item.HitCount, item.ColdStartSavedMS, item.MemoryMB, item.DiskBytes, item.Priority, item.EvictionReason, item.WorkspacePath)
			}
			return w.Flush()
		},
	}
	cmd := &cobra.Command{Use: "pool", Short: "warm pool commands"}
	cmd.AddCommand(create)
	cmd.AddCommand(status)
	return cmd
}
