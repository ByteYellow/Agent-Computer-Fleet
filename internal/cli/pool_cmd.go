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
			items, err := (warm.Service{DB: db, Paths: paths}).Create(templateName, size)
			if err != nil {
				return err
			}
			for _, item := range items {
				fmt.Fprintf(cmd.OutOrStdout(), "pool_id=%s template=%s workspace=%s priority=%.3f status=%s\n", item.ID, item.TemplateName, item.WorkspacePath, item.Priority, item.Status)
			}
			return nil
		},
	}
	create.Flags().StringVar(&templateName, "template", "", "template name")
	create.Flags().IntVar(&size, "size", 1, "warm pool size")
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
			fmt.Fprintln(w, "ID\tTEMPLATE\tSTATUS\tFREQ\tCOLD_P95_MS\tSIZE_SCORE\tPRIORITY\tWORKSPACE")
			for _, item := range items {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%.3f\t%.3f\t%s\n", item.ID, item.TemplateName, item.Status, item.Frequency, item.ColdStartP95MS, item.SizeScore, item.Priority, item.WorkspacePath)
			}
			return w.Flush()
		},
	}
	cmd := &cobra.Command{Use: "pool", Short: "warm pool commands"}
	cmd.AddCommand(create)
	cmd.AddCommand(status)
	return cmd
}
