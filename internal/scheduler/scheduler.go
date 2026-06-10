package scheduler

import (
	"database/sql"
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"

	"gopkg.in/yaml.v3"
)

type Request struct {
	RunID          string
	SessionID      string
	Runtime        string
	RiskTier       string
	CPURequest     float64
	MemoryMB       int64
	SnapshotID     string
	IdleRatio      float64
	SimulatedCount int
}

type NodeState struct {
	NodeID            string
	PhysicalCPU       float64
	OvercommitRatio   float64
	IdleDiscount      float64
	MemoryTotalMB     int64
	MemorySafetyRatio float64
	ActiveCPUDebt     float64
	EWMAActiveCPU     float64
	ThrottlingCount   int64
	MemoryAllocatedMB int64
	RunningSessions   int
	WarmPoolReady     int
	SnapshotLocal     bool
	QueuePressure     string
}

type Decision struct {
	Admitted          bool
	NodeID            string
	Runtime           string
	Reason            string
	WeightedCPU       float64
	CapacityCPU       float64
	OvercommitRatio   float64
	ActiveCPUDebt     float64
	QueuePressure     string
	MemoryPressure    string
	MemoryAllocatedMB int64
	MemoryRequestMB   int64
	MemoryCapacityMB  int64
	WarmPoolReady     int
	SnapshotLocal     bool
	ActiveCPURequest  float64
	IdleCPURequest    float64
	EffectiveCPU      float64
	BurstRisk         string
	RejectReason      string
}

type Scheduler struct {
	DB *sql.DB
}

func (s Scheduler) Admit(req Request) (Decision, error) {
	state, err := s.NodeState(req.SnapshotID)
	if err != nil {
		return Decision{}, err
	}
	return AdmitRequest(req, state), nil
}

func (s Scheduler) NodeState(snapshotID string) (NodeState, error) {
	state := NodeState{
		NodeID:            envString("ACF_NODE_ID", "local"),
		PhysicalCPU:       envFloat("ACF_NODE_CPU", float64(runtime.NumCPU())),
		OvercommitRatio:   envFloat("ACF_CPU_OVERCOMMIT_RATIO", 2.0),
		IdleDiscount:      envFloat("ACF_IDLE_CPU_DISCOUNT", 0.1),
		MemoryTotalMB:     envInt64("ACF_NODE_MEMORY_MB", 8192),
		MemorySafetyRatio: envFloat("ACF_MEMORY_SAFETY_RATIO", 0.9),
		QueuePressure:     "low",
	}
	if state.PhysicalCPU <= 0 {
		state.PhysicalCPU = 1
	}
	if state.OvercommitRatio <= 0 {
		state.OvercommitRatio = 1
	}
	if state.IdleDiscount <= 0 {
		state.IdleDiscount = 0.1
	}
	if state.MemorySafetyRatio <= 0 || state.MemorySafetyRatio > 1 {
		state.MemorySafetyRatio = 0.9
	}
	if s.DB == nil {
		return state, nil
	}
	rows, err := s.DB.Query(`SELECT l.task_yaml FROM sessions s JOIN leases l ON s.lease_id = l.id WHERE s.status IN ('running', 'idle', 'quarantined')`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var raw string
			if err := rows.Scan(&raw); err != nil {
				continue
			}
			var task struct {
				MemoryMB int64 `yaml:"memory_mb"`
			}
			_ = yaml.Unmarshal([]byte(raw), &task)
			state.RunningSessions++
			state.MemoryAllocatedMB += task.MemoryMB
		}
	}
	_ = s.DB.QueryRow(`SELECT COALESCE(SUM(active_cpu_seconds - wall_seconds), 0) FROM cost_samples WHERE node_id = ?`, state.NodeID).Scan(&state.ActiveCPUDebt)
	if state.ActiveCPUDebt < 0 {
		state.ActiveCPUDebt = 0
	}
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM warm_pool_items WHERE status = 'ready'`).Scan(&state.WarmPoolReady)
	_ = s.DB.QueryRow(`SELECT COALESCE(AVG(ewma_active_cpu), 0), COALESCE(SUM(CASE WHEN throttling != '' AND throttling != 'unknown' THEN 1 ELSE 0 END), 0) FROM cpu_samples WHERE node_id = ?`, state.NodeID).Scan(&state.EWMAActiveCPU, &state.ThrottlingCount)
	if state.ThrottlingCount > 0 {
		state.OvercommitRatio *= 0.8
		if state.OvercommitRatio < 1 {
			state.OvercommitRatio = 1
		}
	}
	if snapshotID != "" {
		_ = s.DB.QueryRow(`SELECT COUNT(*) > 0 FROM snapshots WHERE id = ? OR name = ?`, snapshotID, snapshotID).Scan(&state.SnapshotLocal)
	}
	if state.RunningSessions > int(state.PhysicalCPU*state.OvercommitRatio) {
		state.QueuePressure = "high"
	} else if state.RunningSessions > int(state.PhysicalCPU) {
		state.QueuePressure = "medium"
	}
	return state, nil
}

func AdmitRequest(req Request, state NodeState) Decision {
	if req.Runtime == "" {
		req.Runtime = "docker"
	}
	if req.CPURequest <= 0 {
		req.CPURequest = 1
	}
	if req.MemoryMB <= 0 {
		req.MemoryMB = 256
	}
	if req.IdleRatio < 0 {
		req.IdleRatio = 0
	}
	if req.IdleRatio > 1 {
		req.IdleRatio = 1
	}
	active := req.CPURequest * (1 - req.IdleRatio)
	idle := req.CPURequest * req.IdleRatio
	burstPenalty := state.EWMAActiveCPU * 0.25
	weighted := active + idle*state.IdleDiscount + state.ActiveCPUDebt + burstPenalty
	capacity := state.PhysicalCPU * state.OvercommitRatio
	memoryCapacity := int64(math.Floor(float64(state.MemoryTotalMB) * state.MemorySafetyRatio))
	decision := Decision{
		Admitted:          true,
		NodeID:            state.NodeID,
		Runtime:           req.Runtime,
		Reason:            "admitted",
		WeightedCPU:       weighted,
		CapacityCPU:       capacity,
		OvercommitRatio:   state.OvercommitRatio,
		ActiveCPUDebt:     state.ActiveCPUDebt,
		QueuePressure:     state.QueuePressure,
		MemoryPressure:    "low",
		MemoryAllocatedMB: state.MemoryAllocatedMB,
		MemoryRequestMB:   req.MemoryMB,
		MemoryCapacityMB:  memoryCapacity,
		WarmPoolReady:     state.WarmPoolReady,
		SnapshotLocal:     state.SnapshotLocal,
		ActiveCPURequest:  active,
		IdleCPURequest:    idle,
		EffectiveCPU:      weighted,
		BurstRisk:         burstRisk(state, active),
	}
	if state.MemoryAllocatedMB+req.MemoryMB > memoryCapacity {
		decision.Admitted = false
		decision.MemoryPressure = "high"
		decision.Reason = fmt.Sprintf("memory pressure: allocated_mb=%d request_mb=%d capacity_mb=%d", state.MemoryAllocatedMB, req.MemoryMB, memoryCapacity)
		decision.RejectReason = decision.Reason
		return decision
	}
	if weighted > capacity {
		decision.Admitted = false
		decision.Reason = fmt.Sprintf("active CPU overcommit: weighted_cpu=%.3f capacity_cpu=%.3f active_cpu_debt=%.3f", weighted, capacity, state.ActiveCPUDebt)
		decision.RejectReason = decision.Reason
		return decision
	}
	return decision
}

type BenchResult struct {
	Sessions          int
	IdleRatio         float64
	Admitted          int
	Rejected          int
	WeightedCPU       float64
	CapacityCPU       float64
	LastRejectReason  string
	ActiveCPUDebt     float64
	QueuePressure     string
	MemoryPressure    string
	MemoryAllocatedMB int64
	MemoryCapacityMB  int64
	OvercommitRatio   float64
	Bursty            bool
	EffectiveCPU      float64
	BurstRisk         string
}

func Simulate(sessions int, idleRatio, cpuPerSession, physicalCPU, overcommitRatio, idleDiscount float64, memoryPerSessionMB, memoryTotalMB int64, bursty bool) BenchResult {
	state := NodeState{
		NodeID:            "bench-local",
		PhysicalCPU:       physicalCPU,
		OvercommitRatio:   overcommitRatio,
		IdleDiscount:      idleDiscount,
		MemoryTotalMB:     memoryTotalMB,
		MemorySafetyRatio: 0.9,
		QueuePressure:     "low",
	}
	if state.PhysicalCPU <= 0 {
		state.PhysicalCPU = 8
	}
	if state.OvercommitRatio <= 0 {
		state.OvercommitRatio = 2
	}
	if state.IdleDiscount <= 0 {
		state.IdleDiscount = 0.1
	}
	if state.MemoryTotalMB <= 0 {
		state.MemoryTotalMB = 8192
	}
	if memoryPerSessionMB <= 0 {
		memoryPerSessionMB = 256
	}
	if cpuPerSession <= 0 {
		cpuPerSession = 1
	}
	result := BenchResult{Sessions: sessions, IdleRatio: idleRatio, CapacityCPU: state.PhysicalCPU * state.OvercommitRatio, OvercommitRatio: state.OvercommitRatio, Bursty: bursty}
	for i := 0; i < sessions; i++ {
		state.RunningSessions = result.Admitted
		nextIdleRatio := idleRatio
		if bursty && i%4 == 0 {
			nextIdleRatio = 0.05
			state.EWMAActiveCPU = cpuPerSession * 0.8
		} else if bursty {
			state.EWMAActiveCPU = state.EWMAActiveCPU*0.7 + cpuPerSession*(1-nextIdleRatio)*0.3
		}
		decision := AdmitRequest(Request{Runtime: "docker", CPURequest: cpuPerSession, MemoryMB: memoryPerSessionMB, IdleRatio: nextIdleRatio}, state)
		result.CapacityCPU = decision.CapacityCPU
		result.EffectiveCPU = decision.EffectiveCPU
		result.BurstRisk = decision.BurstRisk
		result.ActiveCPUDebt = decision.ActiveCPUDebt
		result.QueuePressure = decision.QueuePressure
		result.MemoryPressure = decision.MemoryPressure
		result.MemoryCapacityMB = decision.MemoryCapacityMB
		if !decision.Admitted {
			result.Rejected++
			result.LastRejectReason = decision.Reason
			continue
		}
		result.Admitted++
		result.WeightedCPU += decision.ActiveCPURequest + decision.IdleCPURequest*state.IdleDiscount
		state.MemoryAllocatedMB += memoryPerSessionMB
		result.MemoryAllocatedMB = state.MemoryAllocatedMB
	}
	return result
}

func burstRisk(state NodeState, active float64) string {
	if state.ThrottlingCount > 0 || state.EWMAActiveCPU+active > state.PhysicalCPU*0.8 {
		return "high"
	}
	if state.EWMAActiveCPU+active > state.PhysicalCPU*0.5 {
		return "medium"
	}
	return "low"
}

func envString(name, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
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

func envInt64(name string, fallback int64) int64 {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}
