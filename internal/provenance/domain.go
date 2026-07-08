package provenance

// Domain terms used by public APIs and documentation.
//
// The SQLite schema still contains older table/column names such as
// rollouts/fork_attempts/sessions/snapshots. Those names are treated as storage
// compatibility details. New code should prefer these domain terms at API and
// UI boundaries, then map to the physical schema in repository/query code.
type ExecutionScope struct {
	ID               string `json:"execution_scope_id"`
	RunID            string `json:"run_id,omitempty"`
	TrajectoryID     string `json:"trajectory_id,omitempty"`
	BaseStateID      string `json:"base_state_id,omitempty"`
	ToolCallID       string `json:"tool_call_id,omitempty"`
	SubstrateScopeID string `json:"substrate_scope_id,omitempty"`
	Status           string `json:"status,omitempty"`
	RiskStatus       string `json:"risk_status,omitempty"`
}

type Trajectory struct {
	ID          string `json:"trajectory_id"`
	RunID       string `json:"run_id"`
	BaseStateID string `json:"base_state_id,omitempty"`
	Status      string `json:"status,omitempty"`
	RiskStatus  string `json:"risk_status,omitempty"`
}

type ArtifactState struct {
	ID           string `json:"artifact_state_id"`
	ParentID     string `json:"parent_state_id,omitempty"`
	ManifestHash string `json:"manifest_hash,omitempty"`
	Status       string `json:"status,omitempty"`
	Tainted      bool   `json:"tainted,omitempty"`
}

func ExecutionScopeFromStorage(runID, trajectoryID, baseStateID, executionScopeID, substrateScopeID, toolCallID, status, riskStatus string) ExecutionScope {
	return ExecutionScope{
		ID:               executionScopeID,
		RunID:            runID,
		TrajectoryID:     trajectoryID,
		BaseStateID:      baseStateID,
		ToolCallID:       toolCallID,
		SubstrateScopeID: substrateScopeID,
		Status:           status,
		RiskStatus:       riskStatus,
	}
}
