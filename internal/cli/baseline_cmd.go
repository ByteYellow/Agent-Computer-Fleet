package cli

import (
	"fmt"
	"github.com/byteyellow/agent-computer-fleet/internal/baseline"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
	"strings"
)

func baselineCmd(dataDir *string) *cobra.Command {
	var templateName, runID string
	learn := &cobra.Command{
		Use:   "learn",
		Short: "learn a per-template behavior baseline from a run",
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
			profile, err := baseline.Learn(db, templateName, runID)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "baseline_id=%s template=%s exec_count=%d network_event_count=%d policy_block_count=%d active_cpu_seconds=%.3f status=%s\n",
				profile.ID, profile.TemplateName, profile.ExecCount, profile.NetworkEventCount, profile.PolicyBlockCount, profile.ActiveCPUSeconds, profile.Status)
			return nil
		},
	}
	learn.Flags().StringVar(&templateName, "template", "", "template name")
	learn.Flags().StringVar(&runID, "run", "", "run id")
	_ = learn.MarkFlagRequired("template")
	_ = learn.MarkFlagRequired("run")

	check := &cobra.Command{
		Use:   "check",
		Short: "check a run against the latest template baseline",
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
			status, deviations, err := baseline.Check(db, templateName, runID)
			if err != nil {
				return err
			}
			recommendation := "allow"
			if status == "anomalous" {
				recommendation = "audit"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "status=%s deviations=%s recommendation=%s\n", status, strings.Join(deviations, ","), recommendation)
			return nil
		},
	}
	check.Flags().StringVar(&templateName, "template", "", "template name")
	check.Flags().StringVar(&runID, "run", "", "run id")
	_ = check.MarkFlagRequired("template")
	_ = check.MarkFlagRequired("run")

	cmd := &cobra.Command{Use: "baseline", Short: "behavior baseline commands"}
	cmd.AddCommand(learn)
	cmd.AddCommand(check)
	return cmd
}
