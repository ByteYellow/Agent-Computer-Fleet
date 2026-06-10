package cli

import (
	"fmt"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
)

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
