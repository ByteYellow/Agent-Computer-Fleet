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

	rolloutRows, err := db.Query(`SELECT id, status, base_snapshot_id, fanout, winner_attempt_id, promotion_id, risk_status, cost_estimate, created_at
		FROM rollouts WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer rolloutRows.Close()
	fmt.Fprintln(out, "rollouts:")
	for rolloutRows.Next() {
		var id, status, baseSnapshotID, winnerAttemptID, promotionID, riskStatus, createdAt string
		var fanout int
		var cost float64
		if err := rolloutRows.Scan(&id, &status, &baseSnapshotID, &fanout, &winnerAttemptID, &promotionID, &riskStatus, &cost, &createdAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "  rollout=%s status=%s base_snapshot=%s fanout=%d winner=%s promotion=%s risk=%s cost=%.6f created_at=%s\n", id, status, baseSnapshotID, fanout, winnerAttemptID, promotionID, riskStatus, cost, createdAt)
	}
	if err := rolloutRows.Err(); err != nil {
		return err
	}

	attemptRows, err := db.Query(`SELECT a.id, a.rollout_id, a.snapshot_id, a.status, a.score, a.cost_estimate, a.is_winner
		FROM fork_attempts a JOIN rollouts r ON a.rollout_id = r.id
		WHERE r.run_id = ? ORDER BY a.created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer attemptRows.Close()
	fmt.Fprintln(out, "attempts:")
	for attemptRows.Next() {
		var id, rolloutID, snapshotID, status string
		var score, cost float64
		var isWinner int
		if err := attemptRows.Scan(&id, &rolloutID, &snapshotID, &status, &score, &cost, &isWinner); err != nil {
			return err
		}
		fmt.Fprintf(out, "  attempt=%s rollout=%s snapshot=%s status=%s score=%.3f cost=%.6f winner=%t\n", id, rolloutID, snapshotID, status, score, cost, isWinner != 0)
	}
	if err := attemptRows.Err(); err != nil {
		return err
	}

	toolRows, err := db.Query(`SELECT id, rollout_id, attempt_id, status, COALESCE(exit_code, 0), wall_ms, cost_estimate, policy_decision, result_ref, command
		FROM tool_calls WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer toolRows.Close()
	fmt.Fprintln(out, "tool_calls:")
	for toolRows.Next() {
		var id, rolloutID, attemptID, status, policyDecision, resultRef, command string
		var exitCode int
		var wallMS int64
		var cost float64
		if err := toolRows.Scan(&id, &rolloutID, &attemptID, &status, &exitCode, &wallMS, &cost, &policyDecision, &resultRef, &command); err != nil {
			return err
		}
		fmt.Fprintf(out, "  tool_call=%s rollout=%s attempt=%s status=%s exit=%d wall_ms=%d cost=%.6f policy=%s result=%s command=%q\n",
			id, rolloutID, attemptID, status, exitCode, wallMS, cost, policyDecision, resultRef, command)
	}
	if err := toolRows.Err(); err != nil {
		return err
	}

	procRows, err := db.Query(`SELECT id, session_id, COALESCE(tool_call_id, ''), command, status, COALESCE(exit_code, 0), started_at, COALESCE(ended_at, '') FROM processes
		WHERE session_id IN (SELECT id FROM sessions WHERE run_id = ?) ORDER BY started_at ASC`, runID)
	if err != nil {
		return err
	}
	defer procRows.Close()
	fmt.Fprintln(out, "processes:")
	for procRows.Next() {
		var id, sessionID, toolCallID, command, status, startedAt, endedAt string
		var exitCode int
		if err := procRows.Scan(&id, &sessionID, &toolCallID, &command, &status, &exitCode, &startedAt, &endedAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "  process=%s session=%s tool_call=%s status=%s exit=%d command=%q started_at=%s ended_at=%s\n", id, sessionID, toolCallID, status, exitCode, command, startedAt, endedAt)
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

	edgeRows, err := db.Query(`SELECT parent_id, child_id, edge_type, plan, COALESCE(plan_reason, ''), COALESCE(planner_score, 0), created_at FROM snapshot_edges ORDER BY created_at ASC`)
	if err != nil {
		return err
	}
	defer edgeRows.Close()
	fmt.Fprintln(out, "snapshot_edges:")
	for edgeRows.Next() {
		var parentID, childID, edgeType, plan, reason, createdAt string
		var score float64
		if err := edgeRows.Scan(&parentID, &childID, &edgeType, &plan, &reason, &score, &createdAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "  parent=%s child=%s type=%s plan=%s score=%.3f reason=%q created_at=%s\n", parentID, childID, edgeType, plan, score, reason, createdAt)
	}
	if err := edgeRows.Err(); err != nil {
		return err
	}

	graphRows, err := db.Query(`SELECT from_id, to_id, edge_type, source_event_id, created_at FROM graph_edges WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer graphRows.Close()
	fmt.Fprintln(out, "graph_edges:")
	for graphRows.Next() {
		var fromID, toID, edgeType, sourceEventID, createdAt string
		if err := graphRows.Scan(&fromID, &toID, &edgeType, &sourceEventID, &createdAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "  from=%s to=%s type=%s source_event=%s created_at=%s\n", fromID, toID, edgeType, sourceEventID, createdAt)
	}
	if err := graphRows.Err(); err != nil {
		return err
	}

	evidenceRows, err := db.Query(`SELECT id, rollout_id, attempt_id, session_id, tool_call_id, snapshot_id, event_type, priority, status, created_at, COALESCE(processed_at, '')
		FROM evidence_events WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer evidenceRows.Close()
	fmt.Fprintln(out, "evidence_events:")
	for evidenceRows.Next() {
		var id, rolloutID, attemptID, sessionID, toolCallID, snapshotID, eventType, priority, status, createdAt, processedAt string
		if err := evidenceRows.Scan(&id, &rolloutID, &attemptID, &sessionID, &toolCallID, &snapshotID, &eventType, &priority, &status, &createdAt, &processedAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "  evidence=%s rollout=%s attempt=%s session=%s tool_call=%s snapshot=%s type=%s priority=%s status=%s created_at=%s processed_at=%s\n", id, rolloutID, attemptID, sessionID, toolCallID, snapshotID, eventType, priority, status, createdAt, processedAt)
	}
	if err := evidenceRows.Err(); err != nil {
		return err
	}

	gcRows, err := db.Query(`SELECT id, rollout_id, attempt_id, status, reclaimed_bytes, reclaimed_inodes, gc_latency_ms, failure_reason
		FROM gc_jobs WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer gcRows.Close()
	fmt.Fprintln(out, "gc_jobs:")
	for gcRows.Next() {
		var id, rolloutID, attemptID, status, failureReason string
		var bytes, inodes, latency int64
		if err := gcRows.Scan(&id, &rolloutID, &attemptID, &status, &bytes, &inodes, &latency, &failureReason); err != nil {
			return err
		}
		fmt.Fprintf(out, "  gc=%s rollout=%s attempt=%s status=%s reclaimed_bytes=%d reclaimed_inodes=%d gc_latency_ms=%d failure=%q\n", id, rolloutID, attemptID, status, bytes, inodes, latency, failureReason)
	}
	if err := gcRows.Err(); err != nil {
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
