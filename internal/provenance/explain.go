package provenance

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

type ExplainOptions struct {
	RunID    string
	Artifact string
	Attempt  string
	ToolCall string
	Process  string
	Event    string
	Risk     string
	File     string
	Depth    int
	Limit    int
	Cursor   string
	WithJSON bool
}

type ExplainManifest struct {
	SchemaVersion    string                      `json:"schema_version"`
	Target           ExplainTarget               `json:"target"`
	Query            ExplainQuery                `json:"query"`
	Summary          []string                    `json:"summary"`
	Upstream         []ExplainGraphEdge          `json:"upstream,omitempty"`
	Downstream       []ExplainGraphEdge          `json:"downstream,omitempty"`
	CausalityPath    []ExplainGraphEdge          `json:"causality_path,omitempty"`
	Evidence         []ExplainEvidence           `json:"evidence,omitempty"`
	Objects          []ExplainObjectRef          `json:"objects,omitempty"`
	Risks            []ExplainRisk               `json:"risks,omitempty"`
	Responses        []ExplainResponseAction     `json:"responses,omitempty"`
	ReplayRefs       []ExplainReplayRef          `json:"replay_refs,omitempty"`
	ProcessObs       []ExplainProcessObservation `json:"process_observations,omitempty"`
	TelemetryBatches []ExplainTelemetryBatch     `json:"telemetry_batches,omitempty"`
	RuntimeEdges     []ExplainGraphEdge          `json:"runtime_edges,omitempty"`
	RuntimeEvents    []ExplainEvent              `json:"runtime_events,omitempty"`
	FileDiff         *FileDiffManifest           `json:"file_diff,omitempty"`
	FileBlame        *FileBlameManifest          `json:"file_blame,omitempty"`
}

type ExplainQuery struct {
	Depth       int    `json:"depth"`
	Limit       int    `json:"limit"`
	Cursor      string `json:"cursor,omitempty"`
	NextCursor  string `json:"next_cursor,omitempty"`
	ResultSetID string `json:"result_set_id,omitempty"`
	PageHash    string `json:"page_hash,omitempty"`
	Truncated   bool   `json:"truncated"`
	EdgeCount   int    `json:"edge_count"`
	NodeCount   int    `json:"node_count"`
	FrontierHit bool   `json:"frontier_hit"`
}

type ExplainTarget struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
	Run  string `json:"run_id,omitempty"`
	File string `json:"file,omitempty"`
}

type ExplainGraphEdge struct {
	RunID         string `json:"run_id"`
	RolloutID     string `json:"rollout_id"`
	FromID        string `json:"from_id"`
	ToID          string `json:"to_id"`
	EdgeType      string `json:"edge_type"`
	SourceEventID string `json:"source_event_id"`
	CreatedAt     string `json:"created_at"`
}

type ExplainEvidence struct {
	ID          string `json:"id"`
	RunID       string `json:"run_id"`
	RolloutID   string `json:"rollout_id"`
	AttemptID   string `json:"attempt_id"`
	SessionID   string `json:"session_id"`
	ToolCallID  string `json:"tool_call_id"`
	ProcessID   string `json:"process_id,omitempty"`
	SnapshotID  string `json:"snapshot_id"`
	EventType   string `json:"event_type"`
	Priority    string `json:"priority"`
	Status      string `json:"status"`
	Payload     string `json:"payload"`
	CreatedAt   string `json:"created_at"`
	ProcessedAt string `json:"processed_at"`
}

type ExplainObjectRef struct {
	Hash         string `json:"hash"`
	Type         string `json:"type"`
	SourceID     string `json:"source_id"`
	RunID        string `json:"run_id"`
	RolloutID    string `json:"rollout_id"`
	ParentHashes string `json:"parent_hashes"`
	Path         string `json:"path"`
	SizeBytes    int64  `json:"size_bytes"`
	CreatedAt    string `json:"created_at"`
}

type ExplainRisk struct {
	ID        string `json:"id"`
	RunID     string `json:"run_id"`
	EventID   string `json:"event_id"`
	SessionID string `json:"session_id"`
	RuleID    string `json:"rule_id"`
	Decision  string `json:"decision"`
	Reason    string `json:"reason"`
	CreatedAt string `json:"created_at"`
}

type ExplainResponseAction struct {
	ID               string `json:"id"`
	RunID            string `json:"run_id"`
	SessionID        string `json:"session_id"`
	ProcessID        string `json:"process_id"`
	SnapshotID       string `json:"snapshot_id"`
	RiskSignalID     string `json:"risk_signal_id"`
	PolicyDecisionID string `json:"policy_decision_id"`
	ActionType       string `json:"action_type"`
	TargetType       string `json:"target_type"`
	TargetID         string `json:"target_id"`
	Status           string `json:"status"`
	ResultRef        string `json:"result_ref"`
	Payload          string `json:"payload"`
	CreatedAt        string `json:"created_at"`
}

type ExplainTelemetryBatch struct {
	ID             string   `json:"id"`
	RunID          string   `json:"run_id"`
	Format         string   `json:"format"`
	Path           string   `json:"path"`
	FileSHA256     string   `json:"file_sha256"`
	Read           int      `json:"read"`
	Ingested       int      `json:"ingested"`
	Skipped        int      `json:"skipped"`
	Failed         int      `json:"failed"`
	EventIDs       []string `json:"event_ids"`
	EventIDsSHA256 string   `json:"event_ids_sha256"`
	CreatedAt      string   `json:"created_at"`
}

type ExplainReplayRef struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Ref  string `json:"ref"`
}

type ExplainProcessObservation struct {
	PID               int64    `json:"pid"`
	PPID              int64    `json:"ppid"`
	Command           string   `json:"command"`
	FirstSeen         string   `json:"first_seen"`
	LastSeen          string   `json:"last_seen"`
	OutlivedRoot      bool     `json:"outlived_root"`
	Boundary          string   `json:"boundary"`
	OrphanPolicy      string   `json:"orphan_policy"`
	SourceEventID     string   `json:"source_event_id"`
	ProcessID         string   `json:"process_id"`
	ToolCallID        string   `json:"tool_call_id"`
	EvidenceIDs       []string `json:"evidence_ids,omitempty"`
	PolicyDecisionIDs []string `json:"policy_decision_ids,omitempty"`
}

type ExplainEvent struct {
	ID                    string                      `json:"id"`
	RunID                 string                      `json:"run_id"`
	SessionID             string                      `json:"session_id"`
	ToolCallID            string                      `json:"tool_call_id"`
	ProcessID             string                      `json:"process_id"`
	SnapshotID            string                      `json:"snapshot_id"`
	Lane                  string                      `json:"lane,omitempty"`
	CorrelationStatus     string                      `json:"correlation_status,omitempty"`
	RawEventID            string                      `json:"raw_event_id"`
	CorrelationMethod     string                      `json:"correlation_method"`
	CorrelationConfidence float64                     `json:"correlation_confidence"`
	ContainerID           string                      `json:"container_id"`
	CgroupID              string                      `json:"cgroup_id"`
	PID                   int64                       `json:"pid"`
	TGID                  int64                       `json:"tgid"`
	PPID                  int64                       `json:"ppid"`
	Source                string                      `json:"source"`
	EventType             string                      `json:"event_type"`
	Payload               string                      `json:"payload"`
	CreatedAt             string                      `json:"created_at"`
	Telemetry             *telemetry.EventExplanation `json:"telemetry,omitempty"`
	Drilldowns            []string                    `json:"drilldowns,omitempty"`
}

func Explain(db *sql.DB, opts ExplainOptions, out io.Writer) error {
	if opts.WithJSON {
		manifest, err := BuildExplain(db, opts)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(manifest)
	}
	selected := 0
	for _, value := range []string{opts.Artifact, opts.Attempt, opts.ToolCall, opts.Process, opts.Event, opts.Risk, opts.File} {
		if strings.TrimSpace(value) != "" {
			selected++
		}
	}
	if selected != 1 {
		return fmt.Errorf("use exactly one of --artifact, --attempt, --tool-call, --process, --event, --risk, or --file")
	}
	if opts.File != "" && opts.RunID == "" {
		return fmt.Errorf("--run is required with --file")
	}
	fmt.Fprintln(out, "explain:")
	switch {
	case opts.Artifact != "":
		fmt.Fprintf(out, "  target=artifact id=%s\n", opts.Artifact)
		return explainArtifact(db, opts.Artifact, out)
	case opts.Attempt != "":
		fmt.Fprintf(out, "  target=attempt id=%s\n", opts.Attempt)
		return explainAttempt(db, opts.Attempt, out)
	case opts.ToolCall != "":
		fmt.Fprintf(out, "  target=tool_call id=%s\n", opts.ToolCall)
		return explainToolCall(db, opts.ToolCall, out)
	case opts.Process != "":
		fmt.Fprintf(out, "  target=process id=%s\n", opts.Process)
		return explainProcess(db, opts.Process, out)
	case opts.Event != "":
		fmt.Fprintf(out, "  target=event id=%s\n", opts.Event)
		return explainEvent(db, opts.Event, out)
	case opts.Risk != "":
		fmt.Fprintf(out, "  target=risk id=%s\n", opts.Risk)
		return explainRisk(db, opts.Risk, out)
	case opts.File != "":
		fmt.Fprintf(out, "  target=file run=%s path=%s\n", opts.RunID, opts.File)
		return explainFile(db, opts.RunID, opts.File, out)
	default:
		return nil
	}
}

func PrintExplainManifestJSON(out io.Writer, manifest ExplainManifest) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(manifest)
}

func PrintExplainManifest(out io.Writer, manifest ExplainManifest) error {
	target := manifest.Target
	fmt.Fprintf(out, "explain:\n")
	fmt.Fprintf(out, "  target=%s id=%s run=%s file=%s\n", target.Type, target.ID, target.Run, target.File)
	fmt.Fprintf(out, "  schema=%s result_set=%s page_hash=%s edges=%d truncated=%t\n",
		manifest.SchemaVersion, manifest.Query.ResultSetID, manifest.Query.PageHash, manifest.Query.EdgeCount, manifest.Query.Truncated)
	for _, line := range manifest.Summary {
		fmt.Fprintf(out, "  summary=%s\n", line)
	}
	for _, risk := range manifest.Risks {
		fmt.Fprintf(out, "  risk=%s rule=%s decision=%s event=%s reason=%q\n", risk.ID, risk.RuleID, risk.Decision, risk.EventID, risk.Reason)
	}
	for _, response := range manifest.Responses {
		fmt.Fprintf(out, "  response=%s action=%s target=%s/%s status=%s\n", response.ID, response.ActionType, response.TargetType, response.TargetID, response.Status)
	}
	for _, edge := range manifest.CausalityPath {
		fmt.Fprintf(out, "  edge=%s %s -> %s source_event=%s\n", edge.EdgeType, edge.FromID, edge.ToID, edge.SourceEventID)
	}
	return nil
}

func BuildExplain(db *sql.DB, opts ExplainOptions) (ExplainManifest, error) {
	target, err := explainTarget(opts)
	if err != nil {
		return ExplainManifest{}, err
	}
	manifest := ExplainManifest{
		SchemaVersion: "agentprovenance.explain/v1",
		Target:        target,
		Query:         explainQueryFromOptions(opts),
	}
	switch target.Type {
	case "file":
		targetID := "workspace_file/" + target.File
		diff, err := BuildDiffFile(db, target.Run, target.File)
		if err != nil {
			return ExplainManifest{}, err
		}
		blame, err := BuildBlameFile(db, target.Run, target.File)
		if err != nil {
			return ExplainManifest{}, err
		}
		events, err := runtimeFileEvents(db, target.Run, target.File)
		if err != nil {
			return ExplainManifest{}, err
		}
		manifest.FileDiff = &diff
		manifest.FileBlame = &blame
		manifest.RuntimeEvents = explainEvents(target.Run, events)
		manifest.RuntimeEdges, err = runtimeEdgesForFile(db, target.Run, target.File)
		if err != nil {
			return ExplainManifest{}, err
		}
		if err := enrichExplain(db, &manifest, target.Run, targetID, explainIDsFromFile(diff, blame, events), manifest.Query.Depth, manifest.Query.Limit); err != nil {
			return ExplainManifest{}, err
		}
		manifest.Summary = append(manifest.Summary,
			fmt.Sprintf("file %s has %d attempt diff entries", target.File, len(diff.Attempts)),
			fmt.Sprintf("file %s has %d blame entries", target.File, len(blame.Entries)),
			fmt.Sprintf("file %s has %d runtime file events", target.File, len(events)),
		)
	default:
		edgeID := target.ID
		if target.Type == "event" {
			edgeID = "runtime_event/" + target.ID
		} else if target.Type == "risk" {
			edgeID = "policy_decision/" + target.ID
		}
		runID, err := runIDForExplainTarget(db, target)
		if err != nil {
			return ExplainManifest{}, err
		}
		target.Run = runID
		manifest.Target.Run = runID
		ids, err := resolveExplainIDs(db, target)
		if err != nil {
			return ExplainManifest{}, err
		}
		if target.Type == "risk" && ids["event_id"] != "" {
			edgeID = "runtime_event/" + ids["event_id"]
		}
		manifest.RuntimeEdges, err = runtimeEdgesForID(db, edgeID)
		if err != nil {
			return ExplainManifest{}, err
		}
		if err := enrichExplain(db, &manifest, runID, edgeID, ids, manifest.Query.Depth, manifest.Query.Limit); err != nil {
			return ExplainManifest{}, err
		}
		manifest.Summary = append(manifest.Summary, fmt.Sprintf("%s %s has %d runtime causality edges", target.Type, target.ID, len(manifest.RuntimeEdges)))
		if target.Type == "event" {
			event, err := eventByID(db, target.ID)
			if err != nil {
				return ExplainManifest{}, err
			}
			manifest.RuntimeEvents = []ExplainEvent{event}
		} else if target.Type == "risk" {
			if ids["event_id"] != "" {
				event, err := eventByID(db, ids["event_id"])
				if err != nil {
					return ExplainManifest{}, err
				}
				manifest.RuntimeEvents = []ExplainEvent{event}
			}
		} else {
			events, err := runtimeEventsForExplain(db, runID, ids)
			if err != nil {
				return ExplainManifest{}, err
			}
			manifest.RuntimeEvents = explainEvents(target.Run, events)
		}
	}
	if err := finalizeExplainIntegrity(&manifest); err != nil {
		return ExplainManifest{}, err
	}
	return manifest, nil
}

func explainQueryFromOptions(opts ExplainOptions) ExplainQuery {
	depth := opts.Depth
	if depth <= 0 {
		depth = 2
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}
	return ExplainQuery{Depth: depth, Limit: limit, Cursor: opts.Cursor}
}

func enrichExplain(db *sql.DB, manifest *ExplainManifest, runID, targetID string, ids map[string]string, depth, limit int) error {
	if runID == "" && manifest.Target.Run != "" {
		runID = manifest.Target.Run
	}
	if targetID != "" {
		upstream, downstream, err := upstreamDownstreamEdges(db, runID, targetID)
		if err != nil {
			return err
		}
		manifest.Upstream = upstream
		manifest.Downstream = downstream
		path, query, err := causalityPathEdges(db, runID, targetID, depth, limit, manifest.Query.Cursor)
		if err != nil {
			return err
		}
		manifest.CausalityPath = path
		manifest.Query.Depth = query.Depth
		manifest.Query.Limit = query.Limit
		manifest.Query.Cursor = query.Cursor
		manifest.Query.NextCursor = query.NextCursor
		manifest.Query.Truncated = query.Truncated
		manifest.Query.EdgeCount = query.EdgeCount
		manifest.Query.NodeCount = query.NodeCount
		manifest.Query.FrontierHit = query.FrontierHit
	}
	evidence, err := evidenceForExplain(db, runID, ids)
	if err != nil {
		return err
	}
	manifest.Evidence = evidence
	objects, err := objectsForExplain(db, runID, ids)
	if err != nil {
		return err
	}
	manifest.Objects = objects
	risks, err := risksForExplain(db, runID, ids)
	if err != nil {
		return err
	}
	manifest.Risks = risks
	responses, err := responsesForExplain(db, runID, ids)
	if err != nil {
		return err
	}
	manifest.Responses = responses
	processObs, err := processObservationsForExplain(db, runID, ids)
	if err != nil {
		return err
	}
	manifest.ProcessObs = processObs
	batches, err := telemetryBatchesForExplain(db, runID, ids)
	if err != nil {
		return err
	}
	manifest.TelemetryBatches = batches
	manifest.ReplayRefs = replayRefsForExplain(ids)
	return nil
}

func explainIDsFromFile(diff FileDiffManifest, blame FileBlameManifest, events []telemetry.EventRecord) map[string]string {
	ids := map[string]string{}
	for _, attempt := range diff.Attempts {
		if attempt.AttemptID != "" {
			ids["attempt_id"] = attempt.AttemptID
		}
		if attempt.ToolCallID != "" {
			ids["tool_call_id"] = attempt.ToolCallID
		}
		if attempt.SnapshotID != "" {
			ids["snapshot_id"] = attempt.SnapshotID
		}
		if attempt.Changed {
			break
		}
	}
	for _, entry := range blame.Entries {
		if ids["attempt_id"] == "" && entry.AttemptID != "" {
			ids["attempt_id"] = entry.AttemptID
		}
		if ids["tool_call_id"] == "" && entry.ToolCallID != "" {
			ids["tool_call_id"] = entry.ToolCallID
		}
	}
	for _, event := range events {
		if ids["event_id"] == "" && event.ID != "" {
			ids["event_id"] = event.ID
		}
		if ids["tool_call_id"] == "" && event.ToolCallID != "" {
			ids["tool_call_id"] = event.ToolCallID
		}
		if ids["process_id"] == "" && event.ProcessID != "" {
			ids["process_id"] = event.ProcessID
		}
		if ids["session_id"] == "" && event.SessionID != "" {
			ids["session_id"] = event.SessionID
		}
		if ids["snapshot_id"] == "" && event.SnapshotID != "" {
			ids["snapshot_id"] = event.SnapshotID
		}
	}
	return ids
}

func explainIDsFromTarget(target ExplainTarget) map[string]string {
	ids := map[string]string{}
	switch target.Type {
	case "attempt":
		ids["attempt_id"] = target.ID
	case "tool_call":
		ids["tool_call_id"] = target.ID
	case "process":
		ids["process_id"] = target.ID
	case "event":
		ids["event_id"] = target.ID
	case "risk":
		ids["risk_id"] = target.ID
	case "artifact":
		ids["artifact_ref"] = target.ID
	}
	return ids
}

func resolveExplainIDs(db *sql.DB, target ExplainTarget) (map[string]string, error) {
	ids := explainIDsFromTarget(target)
	switch target.Type {
	case "artifact":
		var attemptID, rolloutID, toolCallID, snapshotID string
		err := db.QueryRow(`SELECT a.id, a.rollout_id, COALESCE(a.tool_call_id, ''), COALESCE(a.snapshot_id, '')
			FROM fork_attempts a WHERE a.artifact_result = ? ORDER BY a.created_at ASC LIMIT 1`, target.ID).Scan(&attemptID, &rolloutID, &toolCallID, &snapshotID)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		ids["attempt_id"] = attemptID
		ids["rollout_id"] = rolloutID
		ids["tool_call_id"] = toolCallID
		ids["snapshot_id"] = snapshotID
	case "attempt":
		var rolloutID, toolCallID, snapshotID, artifactRef string
		err := db.QueryRow(`SELECT COALESCE(rollout_id, ''), COALESCE(tool_call_id, ''), COALESCE(snapshot_id, ''), COALESCE(artifact_result, '')
			FROM fork_attempts WHERE id = ?`, target.ID).Scan(&rolloutID, &toolCallID, &snapshotID, &artifactRef)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		ids["rollout_id"] = rolloutID
		ids["tool_call_id"] = toolCallID
		ids["snapshot_id"] = snapshotID
		ids["artifact_ref"] = artifactRef
	case "tool_call":
		var rolloutID, attemptID, sessionID, resultRef string
		err := db.QueryRow(`SELECT COALESCE(rollout_id, ''), COALESCE(attempt_id, ''), COALESCE(session_id, ''), COALESCE(result_ref, '')
			FROM tool_calls WHERE id = ?`, target.ID).Scan(&rolloutID, &attemptID, &sessionID, &resultRef)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		ids["rollout_id"] = rolloutID
		ids["attempt_id"] = attemptID
		ids["session_id"] = sessionID
		ids["artifact_ref"] = resultRef
	case "process":
		var sessionID, toolCallID string
		err := db.QueryRow(`SELECT COALESCE(session_id, ''), COALESCE(tool_call_id, '') FROM processes WHERE id = ?`, target.ID).Scan(&sessionID, &toolCallID)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		ids["session_id"] = sessionID
		ids["tool_call_id"] = toolCallID
	case "event":
		var runID, sessionID, toolCallID, processID, snapshotID string
		err := db.QueryRow(`SELECT COALESCE(run_id, ''), COALESCE(session_id, ''), COALESCE(tool_call_id, ''),
			COALESCE(process_id, ''), COALESCE(snapshot_id, '') FROM events WHERE id = ?`, target.ID).Scan(&runID, &sessionID, &toolCallID, &processID, &snapshotID)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		ids["run_id"] = runID
		ids["session_id"] = sessionID
		ids["tool_call_id"] = toolCallID
		ids["process_id"] = processID
		ids["snapshot_id"] = snapshotID
	case "risk":
		var eventID, runID, sessionID string
		err := db.QueryRow(`SELECT COALESCE(event_id, ''), COALESCE(run_id, ''), COALESCE(session_id, '')
			FROM policy_decisions WHERE id = ?`, target.ID).Scan(&eventID, &runID, &sessionID)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		ids["event_id"] = eventID
		ids["run_id"] = runID
		ids["session_id"] = sessionID
	}
	if ids["event_id"] != "" {
		var runID, sessionID, toolCallID, processID, snapshotID string
		err := db.QueryRow(`SELECT COALESCE(run_id, ''), COALESCE(session_id, ''), COALESCE(tool_call_id, ''),
			COALESCE(process_id, ''), COALESCE(snapshot_id, '') FROM events WHERE id = ?`, ids["event_id"]).Scan(&runID, &sessionID, &toolCallID, &processID, &snapshotID)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		fillID(ids, "run_id", runID)
		fillID(ids, "session_id", sessionID)
		fillID(ids, "tool_call_id", toolCallID)
		fillID(ids, "process_id", processID)
		fillID(ids, "snapshot_id", snapshotID)
	}
	if ids["tool_call_id"] != "" {
		var rolloutID, attemptID, sessionID, resultRef string
		err := db.QueryRow(`SELECT COALESCE(rollout_id, ''), COALESCE(attempt_id, ''), COALESCE(session_id, ''), COALESCE(result_ref, '')
			FROM tool_calls WHERE id = ?`, ids["tool_call_id"]).Scan(&rolloutID, &attemptID, &sessionID, &resultRef)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		fillID(ids, "rollout_id", rolloutID)
		fillID(ids, "attempt_id", attemptID)
		fillID(ids, "session_id", sessionID)
		fillID(ids, "artifact_ref", resultRef)
	}
	if ids["attempt_id"] != "" {
		var rolloutID, toolCallID, snapshotID, artifactRef string
		err := db.QueryRow(`SELECT COALESCE(rollout_id, ''), COALESCE(tool_call_id, ''), COALESCE(snapshot_id, ''), COALESCE(artifact_result, '')
			FROM fork_attempts WHERE id = ?`, ids["attempt_id"]).Scan(&rolloutID, &toolCallID, &snapshotID, &artifactRef)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		fillID(ids, "rollout_id", rolloutID)
		fillID(ids, "tool_call_id", toolCallID)
		fillID(ids, "snapshot_id", snapshotID)
		fillID(ids, "artifact_ref", artifactRef)
	}
	if ids["process_id"] == "" && ids["tool_call_id"] != "" {
		var processID string
		err := db.QueryRow(`SELECT id FROM processes WHERE tool_call_id = ? ORDER BY started_at ASC LIMIT 1`, ids["tool_call_id"]).Scan(&processID)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		fillID(ids, "process_id", processID)
	}
	if ids["process_id"] != "" {
		var sessionID, toolCallID string
		err := db.QueryRow(`SELECT COALESCE(session_id, ''), COALESCE(tool_call_id, '') FROM processes WHERE id = ?`, ids["process_id"]).Scan(&sessionID, &toolCallID)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		fillID(ids, "session_id", sessionID)
		fillID(ids, "tool_call_id", toolCallID)
	}
	return ids, nil
}

func fillID(ids map[string]string, key, value string) {
	if ids[key] == "" && strings.TrimSpace(value) != "" {
		ids[key] = value
	}
}

func explainTarget(opts ExplainOptions) (ExplainTarget, error) {
	selected := 0
	for _, value := range []string{opts.Artifact, opts.Attempt, opts.ToolCall, opts.Process, opts.Event, opts.Risk, opts.File} {
		if strings.TrimSpace(value) != "" {
			selected++
		}
	}
	if selected != 1 {
		return ExplainTarget{}, fmt.Errorf("use exactly one of --artifact, --attempt, --tool-call, --process, --event, --risk, or --file")
	}
	if opts.File != "" {
		if opts.RunID == "" {
			return ExplainTarget{}, fmt.Errorf("--run is required with --file")
		}
		return ExplainTarget{Type: "file", Run: opts.RunID, File: opts.File}, nil
	}
	if opts.Artifact != "" {
		return ExplainTarget{Type: "artifact", ID: opts.Artifact}, nil
	}
	if opts.Attempt != "" {
		return ExplainTarget{Type: "attempt", ID: opts.Attempt}, nil
	}
	if opts.ToolCall != "" {
		return ExplainTarget{Type: "tool_call", ID: opts.ToolCall}, nil
	}
	if opts.Process != "" {
		return ExplainTarget{Type: "process", ID: opts.Process}, nil
	}
	if opts.Risk != "" {
		return ExplainTarget{Type: "risk", ID: opts.Risk}, nil
	}
	return ExplainTarget{Type: "event", ID: opts.Event}, nil
}

func explainArtifact(db *sql.DB, artifactRef string, out io.Writer) error {
	if err := TraceArtifact(db, artifactRef, out); err != nil {
		return err
	}
	fmt.Fprintln(out, "decision:")
	fmt.Fprintln(out, "  artifact lineage is derived from graph edges and matching attempt result_ref")
	return nil
}

func explainAttempt(db *sql.DB, attemptID string, out io.Writer) error {
	if err := TraceAttempt(db, attemptID, out); err != nil {
		return err
	}
	fmt.Fprintln(out, "promotion_barrier:")
	rows, err := db.Query(`SELECT p.id, p.status, p.risk_status, p.telemetry_watermark, p.drain_pending_after, p.reason
		FROM promotions p WHERE p.attempt_id = ? ORDER BY p.created_at ASC`, attemptID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, status, risk, watermark, reason string
		var pending int
		if err := rows.Scan(&id, &status, &risk, &watermark, &pending, &reason); err != nil {
			return err
		}
		fmt.Fprintf(out, "  promotion=%s status=%s risk=%s watermark=%s drain_pending_after=%d reason=%q\n", id, status, risk, watermark, pending, reason)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return printRuntimeEdgesForID(db, out, attemptID)
}

func explainToolCall(db *sql.DB, toolCallID string, out io.Writer) error {
	if err := TraceToolCall(db, toolCallID, out); err != nil {
		return err
	}
	return printRuntimeEdgesForID(db, out, toolCallID)
}

func explainProcess(db *sql.DB, processID string, out io.Writer) error {
	if err := TraceProcess(db, processID, out); err != nil {
		return err
	}
	return printRuntimeEdgesForID(db, out, processID)
}

func explainEvent(db *sql.DB, eventID string, out io.Writer) error {
	var runID, sessionID, toolCallID, processID, snapshotID, source, eventType, payload, createdAt string
	var pid, tgid, ppid int64
	err := db.QueryRow(`SELECT COALESCE(run_id, ''), COALESCE(session_id, ''), COALESCE(tool_call_id, ''),
			COALESCE(process_id, ''), COALESCE(snapshot_id, ''), source, event_type, payload, created_at,
			COALESCE(pid, 0), COALESCE(tgid, 0), COALESCE(ppid, 0)
		FROM events WHERE id = ?`, eventID).Scan(&runID, &sessionID, &toolCallID, &processID, &snapshotID, &source, &eventType, &payload, &createdAt, &pid, &tgid, &ppid)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "event:")
	fmt.Fprintf(out, "  event=%s run=%s session=%s tool_call=%s process=%s snapshot=%s source=%s type=%s pid=%d tgid=%d ppid=%d created_at=%s payload=%s\n",
		eventID, runID, sessionID, toolCallID, processID, snapshotID, source, eventType, pid, tgid, ppid, createdAt, payload)
	fmt.Fprintln(out, "runtime_causality:")
	if err := printEdgesForIDs(db, out, []string{"runtime_event/" + eventID}); err != nil {
		return err
	}
	if processID != "" {
		return printRuntimeEdgesForID(db, out, processID)
	}
	return nil
}

func explainRisk(db *sql.DB, riskID string, out io.Writer) error {
	var eventID, runID, sessionID, ruleID, decision, reason, createdAt string
	err := db.QueryRow(`SELECT COALESCE(event_id, ''), COALESCE(run_id, ''), COALESCE(session_id, ''),
			rule_id, decision, reason, created_at
		FROM policy_decisions WHERE id = ?`, riskID).Scan(&eventID, &runID, &sessionID, &ruleID, &decision, &reason, &createdAt)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "risk:")
	fmt.Fprintf(out, "  risk=%s event=%s run=%s session=%s rule=%s decision=%s reason=%q created_at=%s\n",
		riskID, eventID, runID, sessionID, ruleID, decision, reason, createdAt)
	if eventID != "" {
		fmt.Fprintln(out, "event:")
		return explainEvent(db, eventID, out)
	}
	return nil
}

func explainFile(db *sql.DB, runID, filePath string, out io.Writer) error {
	fmt.Fprintln(out, "state_diff:")
	if err := DiffFile(db, runID, filePath, out); err != nil {
		return err
	}
	fmt.Fprintln(out, "state_blame:")
	if err := BlameFile(db, runID, filePath, out); err != nil {
		return err
	}
	fmt.Fprintln(out, "runtime_file_events:")
	events, err := runtimeFileEvents(db, runID, filePath)
	if err != nil {
		return err
	}
	for _, event := range events {
		fmt.Fprintf(out, "  event=%s type=%s tool_call=%s process=%s snapshot=%s correlation=%s pid=%d tgid=%d ppid=%d payload=%s\n",
			event.ID, event.EventType, event.ToolCallID, event.ProcessID, event.SnapshotID, event.CorrelationMethod, event.PID, event.TGID, event.PPID, event.Payload)
	}
	return nil
}

func runtimeFileEvents(db *sql.DB, runID, filePath string) ([]telemetry.EventRecord, error) {
	events, err := telemetry.ListEventsFiltered(db, telemetry.Filter{RunID: runID})
	if err != nil {
		return nil, err
	}
	needle1 := fmt.Sprintf(`"path":"%s"`, filePath)
	needle2 := fmt.Sprintf(`"file":"%s"`, filePath)
	filtered := []telemetry.EventRecord{}
	for _, event := range events {
		if event.EventType != "file_write" && event.EventType != "file_open" {
			continue
		}
		if !strings.Contains(event.Payload, needle1) && !strings.Contains(event.Payload, needle2) {
			continue
		}
		filtered = append(filtered, event)
	}
	return filtered, nil
}

func explainEvents(runID string, events []telemetry.EventRecord) []ExplainEvent {
	out := make([]ExplainEvent, 0, len(events))
	for _, event := range events {
		lane := timelineLane(TimelineEvent{Source: event.Source})
		status := timelineCorrelationStatus(TimelineEvent{Lane: lane, ToolCallID: event.ToolCallID, ProcessID: event.ProcessID})
		out = append(out, ExplainEvent{
			ID:                    event.ID,
			RunID:                 event.RunID,
			SessionID:             event.SessionID,
			ToolCallID:            event.ToolCallID,
			ProcessID:             event.ProcessID,
			SnapshotID:            event.SnapshotID,
			Lane:                  lane,
			CorrelationStatus:     status,
			RawEventID:            event.RawEventID,
			CorrelationMethod:     event.CorrelationMethod,
			CorrelationConfidence: event.CorrelationConfidence,
			ContainerID:           event.ContainerID,
			CgroupID:              event.CgroupID,
			PID:                   event.PID,
			TGID:                  event.TGID,
			PPID:                  event.PPID,
			Source:                event.Source,
			EventType:             event.EventType,
			Payload:               event.Payload,
			CreatedAt:             event.CreatedAt,
			Telemetry:             telemetryExplanation(event),
			Drilldowns:            explainEventDrilldowns(runID, event),
		})
	}
	return out
}

func explainEventDrilldowns(runID string, event telemetry.EventRecord) []string {
	if runID == "" {
		runID = event.RunID
	}
	return uniqueTimelineStrings([]string{
		"observe event --run " + runID + " --event " + event.ID,
		"graph explain --event " + event.ID,
		nonEmptyCommand(event.ProcessID != "", "observe process --run "+runID+" --process "+event.ProcessID),
		nonEmptyCommand(event.ToolCallID != "", "timeline --run "+runID+" --tool-call "+event.ToolCallID+" --view causality"),
	})
}

func nonEmptyCommand(ok bool, value string) string {
	if !ok {
		return ""
	}
	return value
}

func telemetryExplanation(event telemetry.EventRecord) *telemetry.EventExplanation {
	if !telemetry.TelemetrySource(event.Source, event.CorrelationMethod) {
		return nil
	}
	explanation := telemetry.ExplainEventRecord(event)
	return &explanation
}

func runtimeEdgesForFile(db *sql.DB, runID, filePath string) ([]ExplainGraphEdge, error) {
	return runtimeEdgesWhere(db, `run_id = ? AND (from_id = ? OR to_id = ?)`, runID, "workspace_file/"+filePath, "workspace_file/"+filePath)
}

func runtimeEdgesForID(db *sql.DB, id string) ([]ExplainGraphEdge, error) {
	if id == "" {
		return nil, nil
	}
	return runtimeEdgesWhere(db, `(from_id = ? OR to_id = ?)`, id, id)
}

func upstreamDownstreamEdges(db *sql.DB, runID, id string) ([]ExplainGraphEdge, []ExplainGraphEdge, error) {
	if id == "" {
		return nil, nil, nil
	}
	where := `(from_id = ? OR to_id = ?)`
	args := []any{id, id}
	if runID != "" {
		where = `run_id = ? AND ` + where
		args = append([]any{runID}, args...)
	}
	edges, err := graphEdgesWhere(db, where, args...)
	if err != nil {
		return nil, nil, err
	}
	var upstream []ExplainGraphEdge
	var downstream []ExplainGraphEdge
	for _, edge := range edges {
		if edge.ToID == id {
			upstream = append(upstream, edge)
		}
		if edge.FromID == id {
			downstream = append(downstream, edge)
		}
	}
	return upstream, downstream, nil
}

func runtimeEdgesWhere(db *sql.DB, where string, args ...any) ([]ExplainGraphEdge, error) {
	query := `SELECT run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at
		FROM graph_edges WHERE edge_type LIKE 'runtime_%' AND ` + where + ` ORDER BY created_at ASC, id ASC`
	return queryExplainEdges(db, query, args...)
}

func graphEdgesWhere(db *sql.DB, where string, args ...any) ([]ExplainGraphEdge, error) {
	// The id tiebreaker makes this a total order: edges derived from one event
	// share created_at, and the BFS order below feeds the page_hash digest.
	query := `SELECT run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at
		FROM graph_edges WHERE ` + where + ` ORDER BY created_at ASC, id ASC`
	return queryExplainEdges(db, query, args...)
}

func queryExplainEdges(db *sql.DB, query string, args ...any) ([]ExplainGraphEdge, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var edges []ExplainGraphEdge
	for rows.Next() {
		var edge ExplainGraphEdge
		if err := rows.Scan(&edge.RunID, &edge.RolloutID, &edge.FromID, &edge.ToID, &edge.EdgeType, &edge.SourceEventID, &edge.CreatedAt); err != nil {
			return nil, err
		}
		edges = append(edges, edge)
	}
	return edges, rows.Err()
}

// loadCausalityAdjacency loads the edges once and buckets them by endpoint so
// the causality BFS can expand each frontier node from memory instead of one
// query per node per depth. Each node's slice is exactly what
// graphEdgesWhere(db, "(from_id=? OR to_id=?)", node, node) would return - the
// same edges in the same created_at,id order - because the source query shares
// that ORDER BY. Preserving per-node order is required: the BFS visitation order
// feeds the page_hash digest and pagination cursor.
func loadCausalityAdjacency(db *sql.DB, runID string) (map[string][]ExplainGraphEdge, error) {
	where := ""
	var args []any
	if runID != "" {
		where = "WHERE run_id = ? "
		args = append(args, runID)
	}
	query := `SELECT run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at
		FROM graph_edges ` + where + `ORDER BY created_at ASC, id ASC`
	edges, err := queryExplainEdges(db, query, args...)
	if err != nil {
		return nil, err
	}
	adj := make(map[string][]ExplainGraphEdge)
	for _, e := range edges {
		adj[e.FromID] = append(adj[e.FromID], e)
		if e.ToID != e.FromID {
			adj[e.ToID] = append(adj[e.ToID], e)
		}
	}
	return adj, nil
}

func causalityPathEdges(db *sql.DB, runID, startID string, maxDepth, limit int, cursor string) ([]ExplainGraphEdge, ExplainQuery, error) {
	query := ExplainQuery{Depth: maxDepth, Limit: limit, Cursor: cursor}
	if maxDepth <= 0 {
		query.Depth = 2
	}
	if limit <= 0 {
		query.Limit = 100
	}
	offset, err := parseExplainCursor(cursor)
	if err != nil {
		return nil, query, err
	}
	if startID == "" {
		return nil, query, nil
	}
	adjacency, err := loadCausalityAdjacency(db, runID)
	if err != nil {
		return nil, query, err
	}
	seenNodes := map[string]bool{startID: true}
	seenEdges := map[string]bool{}
	frontier := []string{startID}
	var out []ExplainGraphEdge
	visitedEdges := 0
	for depth := 0; depth < query.Depth && len(frontier) > 0; depth++ {
		next := []string{}
		for _, node := range frontier {
			for _, edge := range adjacency[node] {
				key := edge.FromID + "\x00" + edge.ToID + "\x00" + edge.EdgeType + "\x00" + edge.SourceEventID
				if !seenEdges[key] {
					seenEdges[key] = true
					visitedEdges++
					if visitedEdges <= offset {
						for _, candidate := range []string{edge.FromID, edge.ToID} {
							if candidate == "" || seenNodes[candidate] {
								continue
							}
							seenNodes[candidate] = true
							next = append(next, candidate)
						}
						continue
					}
					if len(out) < query.Limit {
						out = append(out, edge)
					}
					if len(out) >= query.Limit {
						query.Truncated = true
						query.EdgeCount = len(out)
						query.NodeCount = len(seenNodes)
						query.FrontierHit = true
						nextCursor, err := formatExplainCursor(offset + len(out))
						if err != nil {
							return nil, query, err
						}
						query.NextCursor = nextCursor
						return out, query, nil
					}
				}
				for _, candidate := range []string{edge.FromID, edge.ToID} {
					if candidate == "" || seenNodes[candidate] {
						continue
					}
					seenNodes[candidate] = true
					next = append(next, candidate)
				}
			}
		}
		frontier = next
	}
	query.EdgeCount = len(out)
	query.NodeCount = len(seenNodes)
	query.FrontierHit = len(frontier) > 0
	return out, query, nil
}

func parseExplainCursor(cursor string) (int, error) {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return 0, nil
	}
	data, err := decodeCursor("explain", cursor)
	if err != nil {
		return 0, fmt.Errorf("invalid explain cursor")
	}
	offset, err := cursorInt(data, "offset")
	if err != nil {
		return 0, fmt.Errorf("invalid explain cursor")
	}
	return offset, nil
}

func formatExplainCursor(offset int) (string, error) {
	return encodeCursor("explain", map[string]any{"offset": offset})
}

func finalizeExplainIntegrity(manifest *ExplainManifest) error {
	resultSetID, err := stableDigest(map[string]any{
		"schema_version": manifest.SchemaVersion,
		"kind":           "explain",
		"target":         manifest.Target,
		"depth":          manifest.Query.Depth,
		"limit":          manifest.Query.Limit,
		"order":          "bfs:graph_edges.created_at,id",
	})
	if err != nil {
		return err
	}
	pageHash, err := stableDigest(map[string]any{
		"schema_version": manifest.SchemaVersion,
		"kind":           "explain_page",
		"target":         manifest.Target,
		"depth":          manifest.Query.Depth,
		"limit":          manifest.Query.Limit,
		"cursor":         manifest.Query.Cursor,
		"next_cursor":    manifest.Query.NextCursor,
		"truncated":      manifest.Query.Truncated,
		"edge_count":     manifest.Query.EdgeCount,
		"node_count":     manifest.Query.NodeCount,
		"frontier_hit":   manifest.Query.FrontierHit,
		"causality_path": manifest.CausalityPath,
	})
	if err != nil {
		return err
	}
	manifest.Query.ResultSetID = resultSetID
	manifest.Query.PageHash = pageHash
	return nil
}

func runtimeEventsForExplain(db *sql.DB, runID string, ids map[string]string) ([]telemetry.EventRecord, error) {
	clauses := []string{}
	args := []any{}
	if runID != "" {
		clauses = append(clauses, "run_id = ?")
		args = append(args, runID)
	}
	orClauses := []string{}
	for key, column := range map[string]string{
		"event_id":     "id",
		"session_id":   "session_id",
		"tool_call_id": "tool_call_id",
		"process_id":   "process_id",
		"snapshot_id":  "snapshot_id",
	} {
		if value := strings.TrimSpace(ids[key]); value != "" {
			orClauses = append(orClauses, column+" = ?")
			args = append(args, value)
		}
	}
	if len(orClauses) == 0 {
		return nil, nil
	}
	clauses = append(clauses, "("+strings.Join(orClauses, " OR ")+")")
	rows, err := db.Query(`SELECT id, COALESCE(run_id, ''), COALESCE(session_id, ''), COALESCE(tool_call_id, ''),
			COALESCE(process_id, ''), COALESCE(snapshot_id, ''), COALESCE(raw_event_id, ''),
			COALESCE(correlation_method, ''), COALESCE(correlation_confidence, 0),
			COALESCE(container_id, ''), COALESCE(cgroup_id, ''), COALESCE(pid, 0), COALESCE(tgid, 0), COALESCE(ppid, 0),
			source, event_type, payload, created_at
		FROM events WHERE `+strings.Join(clauses, " AND ")+` ORDER BY created_at ASC, id ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []telemetry.EventRecord
	for rows.Next() {
		var event telemetry.EventRecord
		if err := rows.Scan(&event.ID, &event.RunID, &event.SessionID, &event.ToolCallID, &event.ProcessID, &event.SnapshotID,
			&event.RawEventID, &event.CorrelationMethod, &event.CorrelationConfidence, &event.ContainerID, &event.CgroupID,
			&event.PID, &event.TGID, &event.PPID, &event.Source, &event.EventType, &event.Payload, &event.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

func evidenceForExplain(db *sql.DB, runID string, ids map[string]string) ([]ExplainEvidence, error) {
	clauses := []string{}
	args := []any{}
	if runID != "" {
		clauses = append(clauses, "run_id = ?")
		args = append(args, runID)
	}
	for key, column := range map[string]string{
		"attempt_id":   "attempt_id",
		"session_id":   "session_id",
		"tool_call_id": "tool_call_id",
		"snapshot_id":  "snapshot_id",
	} {
		if value := strings.TrimSpace(ids[key]); value != "" {
			clauses = append(clauses, column+" = ?")
			args = append(args, value)
		}
	}
	if len(clauses) == 0 {
		return nil, nil
	}
	rows, err := db.Query(`SELECT id, run_id, rollout_id, attempt_id, session_id, tool_call_id, snapshot_id,
			event_type, priority, status, payload, created_at, processed_at
		FROM evidence_events WHERE `+strings.Join(clauses, " AND ")+` ORDER BY created_at ASC, id ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExplainEvidence
	for rows.Next() {
		var item ExplainEvidence
		if err := rows.Scan(&item.ID, &item.RunID, &item.RolloutID, &item.AttemptID, &item.SessionID, &item.ToolCallID,
			&item.SnapshotID, &item.EventType, &item.Priority, &item.Status, &item.Payload, &item.CreatedAt, &item.ProcessedAt); err != nil {
			return nil, err
		}
		if processID := ids["process_id"]; processID != "" {
			item.ProcessID = processID
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func processObservationsForExplain(db *sql.DB, runID string, ids map[string]string) ([]ExplainProcessObservation, error) {
	clauses := []string{"source = 'record_process_sample'", "event_type = 'process_observed'"}
	args := []any{}
	if runID != "" {
		clauses = append(clauses, "run_id = ?")
		args = append(args, runID)
	}
	scopeClauses := []string{}
	for _, keyColumn := range []struct {
		key    string
		column string
	}{
		{key: "tool_call_id", column: "tool_call_id"},
		{key: "session_id", column: "session_id"},
		{key: "process_id", column: "process_id"},
	} {
		if value := strings.TrimSpace(ids[keyColumn.key]); value != "" {
			scopeClauses = append(scopeClauses, keyColumn.column+" = ?")
			args = append(args, value)
		}
	}
	if len(scopeClauses) > 0 {
		clauses = append(clauses, "("+strings.Join(scopeClauses, " OR ")+")")
	}
	rows, err := db.Query(`SELECT id, COALESCE(process_id, ''), COALESCE(tool_call_id, ''), payload
		FROM events WHERE `+strings.Join(clauses, " AND ")+` ORDER BY created_at ASC, id ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExplainProcessObservation{}
	for rows.Next() {
		var eventID, processID, toolCallID, payload string
		if err := rows.Scan(&eventID, &processID, &toolCallID, &payload); err != nil {
			return nil, err
		}
		var proc RecordObservedProcess
		if err := json.Unmarshal(unwrapRecordProcessPayload(payload), &proc); err != nil || proc.PID == 0 {
			continue
		}
		obs := ExplainProcessObservation{
			PID:           proc.PID,
			PPID:          proc.PPID,
			Command:       proc.Command,
			FirstSeen:     proc.FirstSeen,
			LastSeen:      proc.LastSeen,
			OutlivedRoot:  proc.OutlivedRoot,
			Boundary:      "root_pid_descendants+cwd+time_window",
			OrphanPolicy:  "observe_only",
			SourceEventID: eventID,
			ProcessID:     processID,
			ToolCallID:    toolCallID,
		}
		if proc.OutlivedRoot {
			evidenceIDs, decisionIDs, err := orphanLifecycleRefs(db, runID, proc.PID)
			if err != nil {
				return nil, err
			}
			obs.EvidenceIDs = evidenceIDs
			obs.PolicyDecisionIDs = decisionIDs
		}
		out = append(out, obs)
	}
	return out, rows.Err()
}

func orphanLifecycleRefs(db *sql.DB, runID string, pid int64) ([]string, []string, error) {
	rows, err := db.Query(`SELECT id, payload FROM evidence_events
		WHERE run_id = ? AND event_type = 'orphan_lifecycle_decision' ORDER BY created_at ASC, id ASC`, runID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	evidenceIDs := []string{}
	decisionSet := map[string]bool{}
	for rows.Next() {
		var id, payload string
		if err := rows.Scan(&id, &payload); err != nil {
			return nil, nil, err
		}
		var decoded struct {
			PID              int64  `json:"pid"`
			PolicyDecisionID string `json:"policy_decision_id"`
		}
		if err := json.Unmarshal([]byte(payload), &decoded); err != nil || decoded.PID != pid {
			continue
		}
		evidenceIDs = append(evidenceIDs, id)
		if decoded.PolicyDecisionID != "" {
			decisionSet[decoded.PolicyDecisionID] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	decisionIDs := []string{}
	for id := range decisionSet {
		decisionIDs = append(decisionIDs, id)
	}
	return evidenceIDs, decisionIDs, nil
}

func telemetryBatchesForExplain(db *sql.DB, runID string, ids map[string]string) ([]ExplainTelemetryBatch, error) {
	eventIDs := map[string]bool{}
	if id := strings.TrimSpace(ids["event_id"]); id != "" {
		eventIDs[id] = true
	}
	if len(eventIDs) == 0 {
		events, err := runtimeEventsForExplain(db, runID, ids)
		if err != nil {
			return nil, err
		}
		for _, event := range events {
			if event.ID != "" {
				eventIDs[event.ID] = true
			}
		}
	}
	if len(eventIDs) == 0 {
		return nil, nil
	}
	// Batch/event matching happens in Go below (against batch.EventIDs); a SQL
	// prefilter with one LIKE clause per event overflows SQLite's expression
	// depth limit once a scope holds more than ~1000 events.
	query := `SELECT id, COALESCE(run_id, ''), format, path, file_sha256, read_count, ingested_count,
			skipped_count, failed_count, event_ids_json, event_ids_sha256, created_at
		FROM telemetry_batches`
	args := []any{}
	if runID != "" {
		query += ` WHERE run_id = ?`
		args = append(args, runID)
	}
	query += ` ORDER BY created_at ASC, id ASC`
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExplainTelemetryBatch{}
	seen := map[string]bool{}
	for rows.Next() {
		var batch ExplainTelemetryBatch
		var eventIDsJSON string
		if err := rows.Scan(&batch.ID, &batch.RunID, &batch.Format, &batch.Path, &batch.FileSHA256, &batch.Read, &batch.Ingested, &batch.Skipped, &batch.Failed, &eventIDsJSON, &batch.EventIDsSHA256, &batch.CreatedAt); err != nil {
			return nil, err
		}
		if seen[batch.ID] {
			continue
		}
		if err := json.Unmarshal([]byte(eventIDsJSON), &batch.EventIDs); err != nil {
			batch.EventIDs = nil
		}
		matched := false
		for _, eventID := range batch.EventIDs {
			if eventIDs[eventID] {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		seen[batch.ID] = true
		out = append(out, batch)
	}
	return out, rows.Err()
}

func objectsForExplain(db *sql.DB, runID string, ids map[string]string) ([]ExplainObjectRef, error) {
	clauses := []string{}
	args := []any{}
	if runID != "" {
		clauses = append(clauses, "run_id = ?")
		args = append(args, runID)
	}
	sourceIDs := explainSourceIDs(ids)
	batches, err := telemetryBatchesForExplain(db, runID, ids)
	if err != nil {
		return nil, err
	}
	for _, batch := range batches {
		sourceIDs = append(sourceIDs, batch.ID)
	}
	if runID != "" {
		sourceIDs = append(sourceIDs, runID)
	}
	if len(sourceIDs) > 0 {
		placeholders := make([]string, 0, len(sourceIDs))
		for _, id := range sourceIDs {
			placeholders = append(placeholders, "?")
			args = append(args, id)
		}
		clauses = append(clauses, "source_id IN ("+strings.Join(placeholders, ",")+")")
	}
	if len(clauses) == 0 {
		return nil, nil
	}
	rows, err := db.Query(`SELECT hash, object_type, source_id, run_id, rollout_id, parent_hashes, path, size_bytes, created_at
		FROM provenance_objects WHERE `+strings.Join(clauses, " AND ")+` ORDER BY created_at ASC, hash ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExplainObjectRef
	for rows.Next() {
		var item ExplainObjectRef
		if err := rows.Scan(&item.Hash, &item.Type, &item.SourceID, &item.RunID, &item.RolloutID, &item.ParentHashes, &item.Path, &item.SizeBytes, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func risksForExplain(db *sql.DB, runID string, ids map[string]string) ([]ExplainRisk, error) {
	clauses := []string{}
	args := []any{}
	if runID != "" {
		clauses = append(clauses, "run_id = ?")
		args = append(args, runID)
	}
	if eventID := strings.TrimSpace(ids["event_id"]); eventID != "" {
		clauses = append(clauses, "event_id = ?")
		args = append(args, eventID)
	}
	if riskID := strings.TrimSpace(ids["risk_id"]); riskID != "" {
		clauses = append(clauses, "id = ?")
		args = append(args, riskID)
	}
	if sessionID := strings.TrimSpace(ids["session_id"]); sessionID != "" {
		clauses = append(clauses, "session_id = ?")
		args = append(args, sessionID)
	}
	if len(clauses) == 0 {
		return nil, nil
	}
	rows, err := db.Query(`SELECT id, COALESCE(run_id, ''), COALESCE(event_id, ''), COALESCE(session_id, ''),
			rule_id, decision, reason, created_at
		FROM policy_decisions WHERE `+strings.Join(clauses, " AND ")+` ORDER BY created_at ASC, id ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExplainRisk
	for rows.Next() {
		var item ExplainRisk
		if err := rows.Scan(&item.ID, &item.RunID, &item.EventID, &item.SessionID, &item.RuleID, &item.Decision, &item.Reason, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func responsesForExplain(db *sql.DB, runID string, ids map[string]string) ([]ExplainResponseAction, error) {
	clauses := []string{}
	args := []any{}
	if runID != "" {
		clauses = append(clauses, "run_id = ?")
		args = append(args, runID)
	}
	var match []string
	if riskID := strings.TrimSpace(ids["risk_id"]); riskID != "" {
		match = append(match, "policy_decision_id = ?")
		args = append(args, riskID)
	}
	if eventID := strings.TrimSpace(ids["event_id"]); eventID != "" {
		match = append(match, `policy_decision_id IN (SELECT id FROM policy_decisions WHERE event_id = ?)`)
		args = append(args, eventID)
		match = append(match, `risk_signal_id IN (SELECT id FROM risk_signals WHERE event_id = ?)`)
		args = append(args, eventID)
	}
	if sessionID := strings.TrimSpace(ids["session_id"]); sessionID != "" {
		match = append(match, "session_id = ?")
		args = append(args, sessionID)
	}
	if processID := strings.TrimSpace(ids["process_id"]); processID != "" {
		match = append(match, "process_id = ?")
		args = append(args, processID)
	}
	if snapshotID := strings.TrimSpace(ids["snapshot_id"]); snapshotID != "" {
		match = append(match, "snapshot_id = ?")
		args = append(args, snapshotID)
	}
	if len(match) > 0 {
		clauses = append(clauses, "("+strings.Join(match, " OR ")+")")
	}
	if len(clauses) == 0 {
		return nil, nil
	}
	rows, err := db.Query(`SELECT id, COALESCE(run_id, ''), COALESCE(session_id, ''), COALESCE(process_id, ''),
			COALESCE(snapshot_id, ''), COALESCE(risk_signal_id, ''), COALESCE(policy_decision_id, ''),
			action_type, target_type, target_id, status, COALESCE(result_ref, ''), payload, created_at
		FROM response_actions WHERE `+strings.Join(clauses, " AND ")+` ORDER BY created_at ASC, id ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExplainResponseAction
	seen := map[string]bool{}
	for rows.Next() {
		var item ExplainResponseAction
		if err := rows.Scan(&item.ID, &item.RunID, &item.SessionID, &item.ProcessID, &item.SnapshotID, &item.RiskSignalID, &item.PolicyDecisionID, &item.ActionType, &item.TargetType, &item.TargetID, &item.Status, &item.ResultRef, &item.Payload, &item.CreatedAt); err != nil {
			return nil, err
		}
		if seen[item.ID] {
			continue
		}
		seen[item.ID] = true
		out = append(out, item)
	}
	return out, rows.Err()
}

func replayRefsForExplain(ids map[string]string) []ExplainReplayRef {
	var refs []ExplainReplayRef
	for _, item := range []struct {
		key  string
		kind string
		ref  string
	}{
		{"attempt_id", "attempt", "replay --attempt"},
		{"rollout_id", "rollout", "rollout attempts"},
		{"tool_call_id", "tool_call", "graph explain --tool-call"},
		{"process_id", "process", "graph explain --process"},
		{"event_id", "event", "graph explain --event"},
		{"risk_id", "risk", "graph explain --risk"},
		{"snapshot_id", "snapshot", "snapshot inspect"},
		{"artifact_ref", "artifact", "graph explain --artifact"},
	} {
		if id := strings.TrimSpace(ids[item.key]); id != "" {
			refs = append(refs, ExplainReplayRef{Kind: item.kind, ID: id, Ref: item.ref + " " + id})
		}
	}
	return refs
}

func explainSourceIDs(ids map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, key := range []string{"rollout_id", "attempt_id", "tool_call_id", "process_id", "event_id", "risk_id", "snapshot_id", "artifact_ref"} {
		id := strings.TrimSpace(ids[key])
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func runIDForExplainTarget(db *sql.DB, target ExplainTarget) (string, error) {
	if target.Run != "" {
		return target.Run, nil
	}
	var runID string
	var err error
	switch target.Type {
	case "attempt":
		err = db.QueryRow(`SELECT r.run_id FROM fork_attempts a JOIN rollouts r ON a.rollout_id = r.id WHERE a.id = ?`, target.ID).Scan(&runID)
	case "tool_call":
		err = db.QueryRow(`SELECT COALESCE(run_id, '') FROM tool_calls WHERE id = ?`, target.ID).Scan(&runID)
	case "process":
		err = db.QueryRow(`SELECT COALESCE(s.run_id, '') FROM processes p JOIN sessions s ON p.session_id = s.id WHERE p.id = ?`, target.ID).Scan(&runID)
	case "event":
		err = db.QueryRow(`SELECT COALESCE(run_id, '') FROM events WHERE id = ?`, target.ID).Scan(&runID)
	case "risk":
		err = db.QueryRow(`SELECT COALESCE(run_id, '') FROM policy_decisions WHERE id = ?`, target.ID).Scan(&runID)
	case "artifact":
		err = db.QueryRow(`SELECT r.run_id FROM fork_attempts a JOIN rollouts r ON a.rollout_id = r.id WHERE a.artifact_result = ? ORDER BY a.created_at ASC LIMIT 1`, target.ID).Scan(&runID)
	default:
		return "", nil
	}
	if err == sql.ErrNoRows {
		return "", nil
	}
	return runID, err
}

func eventByID(db *sql.DB, eventID string) (ExplainEvent, error) {
	var event ExplainEvent
	err := db.QueryRow(`SELECT id, COALESCE(run_id, ''), COALESCE(session_id, ''), COALESCE(tool_call_id, ''),
			COALESCE(process_id, ''), COALESCE(snapshot_id, ''), COALESCE(raw_event_id, ''),
			COALESCE(correlation_method, ''), COALESCE(correlation_confidence, 0),
			COALESCE(container_id, ''), COALESCE(cgroup_id, ''), COALESCE(pid, 0), COALESCE(tgid, 0), COALESCE(ppid, 0),
			source, event_type, payload, created_at
		FROM events WHERE id = ?`, eventID).Scan(&event.ID, &event.RunID, &event.SessionID, &event.ToolCallID,
		&event.ProcessID, &event.SnapshotID, &event.RawEventID, &event.CorrelationMethod, &event.CorrelationConfidence,
		&event.ContainerID, &event.CgroupID, &event.PID, &event.TGID, &event.PPID, &event.Source, &event.EventType, &event.Payload, &event.CreatedAt)
	if err == nil {
		record := telemetry.EventRecord{
			ID:                    event.ID,
			RunID:                 event.RunID,
			SessionID:             event.SessionID,
			ToolCallID:            event.ToolCallID,
			ProcessID:             event.ProcessID,
			SnapshotID:            event.SnapshotID,
			RawEventID:            event.RawEventID,
			CorrelationMethod:     event.CorrelationMethod,
			CorrelationConfidence: event.CorrelationConfidence,
			ContainerID:           event.ContainerID,
			CgroupID:              event.CgroupID,
			PID:                   event.PID,
			TGID:                  event.TGID,
			PPID:                  event.PPID,
			Source:                event.Source,
			EventType:             event.EventType,
			Payload:               event.Payload,
			CreatedAt:             event.CreatedAt,
		}
		event.Telemetry = telemetryExplanation(record)
		event.Lane = timelineLane(TimelineEvent{Source: event.Source})
		event.CorrelationStatus = timelineCorrelationStatus(TimelineEvent{Lane: event.Lane, ToolCallID: event.ToolCallID, ProcessID: event.ProcessID})
		event.Drilldowns = explainEventDrilldowns(event.RunID, record)
	}
	return event, err
}

func printRuntimeEdgesForID(db *sql.DB, out io.Writer, id string) error {
	if id == "" {
		return nil
	}
	fmt.Fprintln(out, "runtime_causality_explain:")
	rows, err := db.Query(`SELECT run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at
		FROM graph_edges
		WHERE edge_type LIKE 'runtime_%' AND (from_id = ? OR to_id = ?)
		ORDER BY created_at ASC, id ASC`, id, id)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var runID, rolloutID, fromID, toID, edgeType, sourceEventID, createdAt string
		if err := rows.Scan(&runID, &rolloutID, &fromID, &toID, &edgeType, &sourceEventID, &createdAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "  run=%s rollout=%s from=%s to=%s type=%s source_event=%s created_at=%s\n",
			runID, rolloutID, fromID, toID, edgeType, sourceEventID, createdAt)
	}
	return rows.Err()
}
