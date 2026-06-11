package economics

import (
	"database/sql"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
)

type AdmissionInput struct {
	PhysicalCPU       float64
	OvercommitRatio   float64
	ActiveCPURequest  float64
	IdleCPURequest    float64
	IdleDiscount      float64
	MemoryAllocatedMB int64
	MemoryRequestMB   int64
	MemoryTotalMB     int64
	MemorySafetyRatio float64
}

func Admit(in AdmissionInput) bool {
	if in.OvercommitRatio == 0 {
		in.OvercommitRatio = 1
	}
	if in.IdleDiscount == 0 {
		in.IdleDiscount = 0.1
	}
	if in.MemorySafetyRatio == 0 {
		in.MemorySafetyRatio = 0.9
	}
	weightedCPU := in.ActiveCPURequest + in.IdleCPURequest*in.IdleDiscount
	if weightedCPU > in.PhysicalCPU*in.OvercommitRatio {
		return false
	}
	return float64(in.MemoryAllocatedMB+in.MemoryRequestMB) <= float64(in.MemoryTotalMB)*in.MemorySafetyRatio
}

func ShowCost(db *sql.DB, runID string, out io.Writer) error {
	var active, idle, wallFromSamples float64
	var fanoutCost, savedCost float64
	var snapshotBytes, blocks, quarantines int64
	err := db.QueryRow(`SELECT
		COALESCE(SUM(active_cpu_seconds), 0),
		COALESCE(SUM(idle_seconds), 0)
		FROM session_resource_windows WHERE run_id = ? AND window_seconds = 60`, runID).Scan(&active, &idle)
	if err != nil {
		return err
	}
	err = db.QueryRow(`SELECT
		COALESCE(SUM(wall_seconds), 0),
		COALESCE(SUM(snapshot_bytes), 0),
		COALESCE(SUM(policy_block_count), 0),
		COALESCE(SUM(quarantine_count), 0),
		COALESCE(SUM(fanout_cost), 0),
		COALESCE(SUM(saved_cost), 0)
		FROM cost_samples WHERE run_id = ?`, runID).Scan(&wallFromSamples, &snapshotBytes, &blocks, &quarantines, &fanoutCost, &savedCost)
	if err != nil {
		return err
	}
	wall := wallFromSamples + active + idle
	costPerRun := EstimateCost(active, wall, snapshotBytes, blocks, quarantines)
	overcommitRatio := envFloat("ACF_CPU_OVERCOMMIT_RATIO", 2.0)
	queuePressure := "low"
	if active > 0 && idle == 0 {
		queuePressure = "medium"
	}
	activeDebt := active - wall
	if activeDebt < 0 {
		activeDebt = 0
	}
	_, err = fmt.Fprintf(out, "run_id=%s active_cpu_seconds=%.3f idle_seconds=%.3f wall_seconds=%.3f snapshot_bytes=%d policy_block_count=%d quarantine_count=%d fanout_cost=%.6f saved_cost=%.6f overcommit_ratio=%.2f active_cpu_debt=%.3f queue_pressure=%s cost_per_run=%.6f\n",
		runID, active, idle, wall, snapshotBytes, blocks, quarantines, fanoutCost, savedCost, overcommitRatio, activeDebt, queuePressure, costPerRun)
	if err != nil {
		return err
	}
	sessionRows, err := db.Query(`SELECT
			w.session_id,
			COALESCE(SUM(w.active_cpu_seconds), 0),
			COALESCE(SUM(w.idle_seconds), 0),
			COALESCE(SUM(w.active_cpu_seconds + w.idle_seconds), 0),
			COALESCE((SELECT SUM(snapshot_bytes) FROM cost_samples c WHERE c.run_id = w.run_id AND COALESCE(c.session_id, '') = w.session_id), 0)
		FROM session_resource_windows w
		WHERE w.run_id = ? AND w.window_seconds = 60
		GROUP BY w.session_id
		ORDER BY w.session_id`, runID)
	if err != nil {
		return err
	}
	defer sessionRows.Close()
	for sessionRows.Next() {
		var sessionID string
		var sessionActive, sessionIdle, sessionWall float64
		var sessionSnapshotBytes int64
		if err := sessionRows.Scan(&sessionID, &sessionActive, &sessionIdle, &sessionWall, &sessionSnapshotBytes); err != nil {
			return err
		}
		if sessionID == "" {
			sessionID = "none"
		}
		if _, err := fmt.Fprintf(out, "session_id=%s active_cpu_seconds=%.3f idle_seconds=%.3f wall_seconds=%.3f snapshot_bytes=%d\n", sessionID, sessionActive, sessionIdle, sessionWall, sessionSnapshotBytes); err != nil {
			return err
		}
	}
	if err := sessionRows.Err(); err != nil {
		return err
	}
	rolloutRows, err := db.Query(`SELECT id, status, fanout, winner_attempt_id, cost_estimate, risk_status
		FROM rollouts WHERE run_id = ? ORDER BY created_at`, runID)
	if err != nil {
		return err
	}
	defer rolloutRows.Close()
	for rolloutRows.Next() {
		var rolloutID, status, winnerAttemptID, riskStatus string
		var fanout int
		var rolloutCost float64
		if err := rolloutRows.Scan(&rolloutID, &status, &fanout, &winnerAttemptID, &rolloutCost, &riskStatus); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "rollout_id=%s status=%s fanout=%d winner=%s risk=%s cost=%.6f\n", rolloutID, status, fanout, winnerAttemptID, riskStatus, rolloutCost); err != nil {
			return err
		}
	}
	if err := rolloutRows.Err(); err != nil {
		return err
	}
	attemptRows, err := db.Query(`SELECT a.id, a.rollout_id, a.status, a.score, a.cost_estimate, a.saved_cost, a.is_winner
		FROM fork_attempts a JOIN rollouts r ON a.rollout_id = r.id
		WHERE r.run_id = ? ORDER BY a.created_at`, runID)
	if err != nil {
		return err
	}
	defer attemptRows.Close()
	for attemptRows.Next() {
		var attemptID, rolloutID, status string
		var score, attemptCost, saved float64
		var isWinner int
		if err := attemptRows.Scan(&attemptID, &rolloutID, &status, &score, &attemptCost, &saved, &isWinner); err != nil {
			return err
		}
		winner := "false"
		if isWinner != 0 {
			winner = "true"
		}
		if _, err := fmt.Fprintf(out, "attempt_id=%s rollout_id=%s status=%s score=%.3f cost=%.6f saved_cost=%.6f winner=%s\n", attemptID, rolloutID, status, score, attemptCost, saved, winner); err != nil {
			return err
		}
	}
	if err := attemptRows.Err(); err != nil {
		return err
	}
	toolRows, err := db.Query(`SELECT id, rollout_id, attempt_id, status, COALESCE(exit_code, 0), wall_ms, cost_estimate, policy_decision, result_ref
		FROM tool_calls WHERE run_id = ? ORDER BY created_at`, runID)
	if err != nil {
		return err
	}
	defer toolRows.Close()
	for toolRows.Next() {
		var toolCallID, rolloutID, attemptID, status, policyDecision, resultRef string
		var exitCode int
		var wallMS int64
		var cost float64
		if err := toolRows.Scan(&toolCallID, &rolloutID, &attemptID, &status, &exitCode, &wallMS, &cost, &policyDecision, &resultRef); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "tool_call_id=%s rollout_id=%s attempt_id=%s status=%s exit=%d wall_ms=%d cost=%.6f policy=%s result_ref=%s\n",
			toolCallID, rolloutID, attemptID, status, exitCode, wallMS, cost, policyDecision, resultRef); err != nil {
			return err
		}
	}
	if err := toolRows.Err(); err != nil {
		return err
	}
	snapshotRows, err := db.Query(`SELECT DISTINCT s.id, COALESCE(s.snapshot_semantic_type, 'directory'), COALESCE(s.snapshot_physical_type, 'copy'),
			COALESCE(s.logical_bytes, s.bytes), COALESCE(s.physical_bytes, s.bytes), COALESCE(s.copy_up_risk, 'low'),
			COALESCE(s.metadata_ops_estimate, 0), COALESCE(s.storage_amplification_ratio, 1)
		FROM snapshots s
		JOIN rollouts r ON r.base_snapshot_id = s.id
		WHERE r.run_id = ?
		ORDER BY s.id`, runID)
	if err != nil {
		return err
	}
	defer snapshotRows.Close()
	for snapshotRows.Next() {
		var snapshotID, semanticType, physicalType, copyUpRisk string
		var logicalBytes, physicalBytes, metadataOps int64
		var amp float64
		if err := snapshotRows.Scan(&snapshotID, &semanticType, &physicalType, &logicalBytes, &physicalBytes, &copyUpRisk, &metadataOps, &amp); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "snapshot_id=%s semantic_type=%s physical_type=%s logical_bytes=%d physical_bytes=%d copy_up_risk=%s metadata_ops_estimate=%d storage_amplification_ratio=%.3f\n", snapshotID, semanticType, physicalType, logicalBytes, physicalBytes, copyUpRisk, metadataOps, amp); err != nil {
			return err
		}
	}
	if err := snapshotRows.Err(); err != nil {
		return err
	}
	nodeRows, err := db.Query(`SELECT
			n.node_id,
			COALESCE(SUM(n.active_cpu_seconds), 0),
			COALESCE(SUM(n.idle_seconds), 0),
			COALESCE(SUM(n.active_cpu_seconds + n.idle_seconds), 0)
		FROM node_resource_windows n
		WHERE n.window_seconds = 60
		  AND EXISTS (
			SELECT 1 FROM session_resource_windows s
			WHERE s.run_id = ? AND s.node_id = n.node_id AND s.window_seconds = n.window_seconds AND s.window_start = n.window_start
		  )
		GROUP BY n.node_id
		ORDER BY n.node_id`, runID)
	if err != nil {
		return err
	}
	defer nodeRows.Close()
	for nodeRows.Next() {
		var nodeID string
		var nodeActive, nodeIdle, nodeWall float64
		if err := nodeRows.Scan(&nodeID, &nodeActive, &nodeIdle, &nodeWall); err != nil {
			return err
		}
		if nodeID == "" {
			nodeID = "local"
		}
		if _, err := fmt.Fprintf(out, "node_id=%s active_cpu_seconds=%.3f idle_seconds=%.3f wall_seconds=%.3f\n", nodeID, nodeActive, nodeIdle, nodeWall); err != nil {
			return err
		}
	}
	return nodeRows.Err()
}

func EstimateCost(activeCPUSeconds, wallSeconds float64, snapshotBytes, policyBlocks, quarantines int64) float64 {
	storageGB := float64(snapshotBytes) / (1024 * 1024 * 1024)
	return activeCPUSeconds*0.00001 + wallSeconds*0.000001 + storageGB*0.0001 + float64(policyBlocks)*0.0001 + float64(quarantines)*0.0005
}

func envFloat(name string, fallback float64) float64 {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

type BenchResult struct {
	Sessions    int
	IdleRatio   float64
	Admitted    int
	Rejected    int
	WeightedCPU float64
	CapacityCPU float64
}

func SimulateOvercommit(sessions int, idleRatio, cpuPerSession, physicalCPU, overcommitRatio, idleDiscount float64, memoryPerSessionMB, memoryTotalMB int64) BenchResult {
	if sessions < 0 {
		sessions = 0
	}
	if idleRatio < 0 {
		idleRatio = 0
	}
	if idleRatio > 1 {
		idleRatio = 1
	}
	if cpuPerSession == 0 {
		cpuPerSession = 1
	}
	if physicalCPU == 0 {
		physicalCPU = 8
	}
	if overcommitRatio == 0 {
		overcommitRatio = 2
	}
	if idleDiscount == 0 {
		idleDiscount = 0.1
	}
	if memoryPerSessionMB == 0 {
		memoryPerSessionMB = 256
	}
	if memoryTotalMB == 0 {
		memoryTotalMB = 8192
	}
	result := BenchResult{
		Sessions:    sessions,
		IdleRatio:   idleRatio,
		CapacityCPU: physicalCPU * overcommitRatio,
	}
	var memoryAllocated int64
	for i := 0; i < sessions; i++ {
		activeCPU := cpuPerSession * (1 - idleRatio)
		idleCPU := cpuPerSession * idleRatio
		nextWeighted := activeCPU + idleCPU*idleDiscount
		ok := Admit(AdmissionInput{
			PhysicalCPU:       physicalCPU,
			OvercommitRatio:   overcommitRatio,
			ActiveCPURequest:  result.WeightedCPU + activeCPU,
			IdleCPURequest:    idleCPU,
			IdleDiscount:      idleDiscount,
			MemoryAllocatedMB: memoryAllocated,
			MemoryRequestMB:   memoryPerSessionMB,
			MemoryTotalMB:     memoryTotalMB,
			MemorySafetyRatio: 0.9,
		})
		if !ok || math.IsNaN(nextWeighted) {
			result.Rejected++
			continue
		}
		result.Admitted++
		result.WeightedCPU += nextWeighted
		memoryAllocated += memoryPerSessionMB
	}
	return result
}
