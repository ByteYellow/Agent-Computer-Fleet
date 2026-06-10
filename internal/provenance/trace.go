package provenance

import (
	"database/sql"
	"fmt"
	"io"

	"github.com/byteyellow/agent-computer-fleet/internal/security"
	"github.com/byteyellow/agent-computer-fleet/internal/telemetry"
)

func TraceRun(db *sql.DB, runID string, out io.Writer) error {
	if runID == "" {
		return fmt.Errorf("run_id is required")
	}
	fmt.Fprintf(out, "run_id=%s\n", runID)

	rows, err := db.Query(`SELECT id, lease_id, status, workspace_host_path, COALESCE(container_id, '') FROM sessions WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	fmt.Fprintln(out, "sessions:")
	for rows.Next() {
		var id, leaseID, status, workspace, containerID string
		if err := rows.Scan(&id, &leaseID, &status, &workspace, &containerID); err != nil {
			return err
		}
		fmt.Fprintf(out, "  session=%s lease=%s status=%s container=%s workspace=%s\n", id, leaseID, status, containerID, workspace)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	procRows, err := db.Query(`SELECT id, session_id, command, status, COALESCE(exit_code, 0), started_at, COALESCE(ended_at, '') FROM processes
		WHERE session_id IN (SELECT id FROM sessions WHERE run_id = ?) ORDER BY started_at ASC`, runID)
	if err != nil {
		return err
	}
	defer procRows.Close()
	fmt.Fprintln(out, "processes:")
	for procRows.Next() {
		var id, sessionID, command, status, startedAt, endedAt string
		var exitCode int
		if err := procRows.Scan(&id, &sessionID, &command, &status, &exitCode, &startedAt, &endedAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "  process=%s session=%s status=%s exit=%d command=%q started_at=%s ended_at=%s\n", id, sessionID, status, exitCode, command, startedAt, endedAt)
	}
	if err := procRows.Err(); err != nil {
		return err
	}

	snapRows, err := db.Query(`SELECT id, COALESCE(name, ''), COALESCE(parent_id, ''), kind, status, manifest_hash, bytes FROM snapshots
		WHERE session_id IN (SELECT id FROM sessions WHERE run_id = ?) OR id IN (SELECT snapshot_id FROM fork_attempts WHERE snapshot_id IN (SELECT id FROM snapshots))
		ORDER BY created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer snapRows.Close()
	fmt.Fprintln(out, "snapshots:")
	for snapRows.Next() {
		var id, name, parentID, kind, status, hash string
		var bytes int64
		if err := snapRows.Scan(&id, &name, &parentID, &kind, &status, &hash, &bytes); err != nil {
			return err
		}
		fmt.Fprintf(out, "  snapshot=%s name=%s kind=%s status=%s parent=%s bytes=%d hash=%s\n", id, name, kind, status, parentID, bytes, hash)
	}
	if err := snapRows.Err(); err != nil {
		return err
	}

	events, err := telemetry.ListEvents(db, runID, "")
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "events:")
	for _, event := range events {
		fmt.Fprintf(out, "  event=%s type=%s source=%s session=%s process=%s tool_call=%s snapshot=%s payload=%s\n",
			event.ID, event.EventType, event.Source, event.SessionID, event.ProcessID, event.ToolCallID, event.SnapshotID, event.Payload)
	}

	decisions, err := security.ListDecisions(db, runID)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "policy_decisions:")
	for _, decision := range decisions {
		fmt.Fprintf(out, "  decision=%s event=%s session=%s action=%s reason=%s created_at=%s\n",
			decision.ID, decision.EventID, decision.SessionID, decision.Decision, decision.Reason, decision.CreatedAt)
	}

	return nil
}
