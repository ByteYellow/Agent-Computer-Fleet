package cli

import (
	"fmt"

	"github.com/byteyellow/agent-computer-fleet/internal/evidence"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
)

func evidenceCmd(dataDir *string) *cobra.Command {
	var limit int
	process := &cobra.Command{
		Use:   "process",
		Short: "process queued compact evidence events into materialized graph edges",
		RunE: func(cmd *cobra.Command, args []string) error {
			service, cleanup, err := evidenceSvc(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			result, err := service.ProcessEvidence(limit)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "processed=%d\n", result.Processed)
			return nil
		},
	}
	process.Flags().IntVar(&limit, "limit", 100, "maximum evidence events to process")
	cmd := &cobra.Command{Use: "evidence", Short: "async evidence pipeline commands"}
	cmd.AddCommand(process)
	return cmd
}

func gcCmd(dataDir *string) *cobra.Command {
	var limit int
	run := &cobra.Command{
		Use:   "run",
		Short: "process queued async GC jobs",
		RunE: func(cmd *cobra.Command, args []string) error {
			service, cleanup, err := evidenceSvc(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			result, err := service.RunGC(limit)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "processed=%d failed=%d reclaimed_bytes=%d reclaimed_inodes=%d\n", result.Processed, result.Failed, result.ReclaimedBytes, result.ReclaimedInodes)
			return nil
		},
	}
	run.Flags().IntVar(&limit, "limit", 100, "maximum GC jobs to process")
	status := &cobra.Command{
		Use:   "status",
		Short: "show async GC queue status",
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
			rows, err := db.Query(`SELECT status, COUNT(*), COALESCE(SUM(reclaimed_bytes), 0), COALESCE(SUM(reclaimed_inodes), 0), COALESCE(SUM(gc_latency_ms), 0)
				FROM gc_jobs GROUP BY status ORDER BY status`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var status string
				var count, bytes, inodes, latency int64
				if err := rows.Scan(&status, &count, &bytes, &inodes, &latency); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "status=%s count=%d reclaimed_bytes=%d reclaimed_inodes=%d gc_latency_ms=%d\n", status, count, bytes, inodes, latency)
			}
			return rows.Err()
		},
	}
	cmd := &cobra.Command{Use: "gc", Short: "async workspace GC commands"}
	cmd.AddCommand(run)
	cmd.AddCommand(status)
	return cmd
}

func evidenceSvc(dataDir string) (evidence.Service, func(), error) {
	paths, err := store.Init(dataDir)
	if err != nil {
		return evidence.Service{}, nil, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return evidence.Service{}, nil, err
	}
	return evidence.Service{DB: db, Paths: paths}, func() { db.Close() }, nil
}
