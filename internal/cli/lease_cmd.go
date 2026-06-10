package cli

import (
	"fmt"
	"github.com/byteyellow/agent-computer-fleet/internal/control"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
)

func leaseCmd(dataDir, daemonURL *string) *cobra.Command {
	var taskPath string
	create := &cobra.Command{
		Use:   "create",
		Short: "create a sandbox lease",
		RunE: func(cmd *cobra.Command, args []string) error {
			if client, ok := daemonClient(*daemonURL); ok {
				id, err := client.CreateLease(taskPath)
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), id)
				return nil
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
