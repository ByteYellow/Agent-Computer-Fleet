package cli

import (
	"fmt"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
	"text/tabwriter"
)

func processCmd(dataDir *string) *cobra.Command {
	var sessionID string
	list := &cobra.Command{
		Use:   "list",
		Short: "list recorded exec processes",
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
			query := `SELECT id, session_id, COALESCE(exec_id, ''), command, status, COALESCE(exit_code, 0), started_at, COALESCE(ended_at, '')
				FROM processes`
			sqlArgs := []any{}
			if sessionID != "" {
				query += ` WHERE session_id = ?`
				sqlArgs = append(sqlArgs, sessionID)
			}
			query += ` ORDER BY started_at DESC`
			rows, err := db.Query(query, sqlArgs...)
			if err != nil {
				return err
			}
			defer rows.Close()
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSESSION\tEXEC_ID\tSTATUS\tEXIT\tWALL_SECONDS\tCOMMAND")
			for rows.Next() {
				var id, sid, execID, command, status, startedAt, endedAt string
				var exitCode int
				if err := rows.Scan(&id, &sid, &execID, &command, &status, &exitCode, &startedAt, &endedAt); err != nil {
					return err
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n", id, sid, short(execID), status, exitCode, wallSecondsText(startedAt, endedAt), command)
			}
			if err := rows.Err(); err != nil {
				return err
			}
			return w.Flush()
		},
	}
	list.Flags().StringVar(&sessionID, "session", "", "filter by session id")
	inspect := &cobra.Command{
		Use:   "inspect <process_id>",
		Short: "inspect a recorded exec process",
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
			var id, sid, containerID, execID, command, status, startedAt, endedAt string
			var exitCode int
			err = db.QueryRow(`SELECT id, session_id, COALESCE(container_id, ''), COALESCE(exec_id, ''), command, status, COALESCE(exit_code, 0), started_at, COALESCE(ended_at, '')
				FROM processes WHERE id = ?`, args[0]).Scan(&id, &sid, &containerID, &execID, &command, &status, &exitCode, &startedAt, &endedAt)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "id=%s\nsession_id=%s\ncontainer_id=%s\nexec_id=%s\ncommand=%s\nstatus=%s\nexit_code=%d\nstarted_at=%s\nended_at=%s\nwall_seconds=%s\n",
				id, sid, containerID, execID, command, status, exitCode, startedAt, endedAt, wallSecondsText(startedAt, endedAt))
			return nil
		},
	}
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
	cmd.AddCommand(list)
	cmd.AddCommand(inspect)
	cmd.AddCommand(interrupt)
	return cmd
}
