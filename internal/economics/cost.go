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
	var active, idle, wall float64
	var fanoutCost, savedCost float64
	var snapshotBytes, blocks, quarantines int64
	err := db.QueryRow(`SELECT
		COALESCE(SUM(active_cpu_seconds), 0),
		COALESCE(SUM(idle_seconds), 0),
		COALESCE(SUM(wall_seconds), 0),
		COALESCE(SUM(snapshot_bytes), 0),
		COALESCE(SUM(policy_block_count), 0),
		COALESCE(SUM(quarantine_count), 0),
		COALESCE(SUM(fanout_cost), 0),
		COALESCE(SUM(saved_cost), 0)
		FROM cost_samples WHERE run_id = ?`, runID).Scan(&active, &idle, &wall, &snapshotBytes, &blocks, &quarantines, &fanoutCost, &savedCost)
	if err != nil {
		return err
	}
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
	sessionRows, err := db.Query(`SELECT COALESCE(session_id, ''), COALESCE(SUM(active_cpu_seconds), 0), COALESCE(SUM(idle_seconds), 0), COALESCE(SUM(wall_seconds), 0), COALESCE(SUM(snapshot_bytes), 0)
		FROM cost_samples WHERE run_id = ? GROUP BY session_id ORDER BY session_id`, runID)
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
	nodeRows, err := db.Query(`SELECT COALESCE(node_id, 'local'), COALESCE(SUM(active_cpu_seconds), 0), COALESCE(SUM(idle_seconds), 0), COALESCE(SUM(wall_seconds), 0)
		FROM cost_samples WHERE run_id = ? GROUP BY node_id ORDER BY node_id`, runID)
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
