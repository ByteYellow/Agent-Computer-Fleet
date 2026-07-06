package intent

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/hooksbridge"
	"github.com/byteyellow/agentprovenance/internal/security"
)

// Result summarizes a Materialize run.
type Result struct {
	RunID        string         `json:"run_id"`
	Effects      int            `json:"effects"`
	Contracts    int            `json:"contracts"`
	Diffs        int            `json:"diffs"`
	ByStatus     map[string]int `json:"by_status"`
	Mismatches   int            `json:"mismatches"`
	CoverageGaps int            `json:"coverage_gaps"`
}

// Edge types wiring the diff into the signed graph.
const (
	edgeIntentContract = "intent_contract" // contract(scope) -> diff node
	edgeIntentEffect   = "intent_diff_effect"
)

// Materialize computes the Intent-Runtime Diff for a run and persists it. It is
// idempotent: prior diff rows and edges for the run are cleared first. It first
// runs the command-match attribution (hooksbridge.CorrelateSyscalls) so runtime
// effects are tied to the agent whose tool call caused them -- the effects are
// normally pinned by the sensor to the record-scope tool call, not the agent's
// hook tool call, and this bridge closes that gap.
func Materialize(db *sql.DB, runID string) (Result, error) {
	if runID == "" {
		return Result{}, fmt.Errorf("intent materialize: run id is required")
	}
	res := Result{RunID: runID, ByStatus: map[string]int{}}
	eng := security.DefaultEngine()

	// Build the command-match attribution edges only when the run has none yet.
	// CorrelateSyscalls is destructive (it clears then rebuilds agent_syscall
	// edges); skipping it when edges already exist protects an imported signed
	// bundle that shipped with good attribution from being degraded by a
	// re-derivation that may fail on truncated argv.
	var existing int
	_ = db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id = ? AND edge_type = 'agent_syscall'`, runID).Scan(&existing)
	if existing == 0 {
		if _, err := hooksbridge.CorrelateSyscalls(db, runID); err != nil {
			return res, fmt.Errorf("intent materialize: correlate syscalls: %w", err)
		}
	}

	effects, err := normalizeEffects(db, runID, eng)
	if err != nil {
		return res, fmt.Errorf("intent materialize: normalize effects: %w", err)
	}
	res.Effects = len(effects)

	contracts, err := ExtractContracts(db, runID, DefaultProfiles())
	if err != nil {
		return res, fmt.Errorf("intent materialize: extract contracts: %w", err)
	}
	res.Contracts = len(contracts)

	diffs := Diff(contracts, effects)
	res.Diffs = len(diffs)

	if err := persistDiffs(db, runID, diffs); err != nil {
		return res, err
	}
	if err := emitSignals(db, runID, diffs); err != nil {
		return res, err
	}
	for _, d := range diffs {
		res.ByStatus[d.Status]++
		if d.Status == StatusMismatch || d.Status == StatusRefusedBypass {
			res.Mismatches++
		}
		if d.Status == StatusCoverageGap {
			res.CoverageGaps++
		}
	}
	return res, nil
}

// emitSignals projects the diffs into the unified signal model as a new
// intent_conformance dimension -- so a mismatch composes with the behavior/cost/
// quality/security signals rather than living in a parallel silo, and any
// consumer (dashboard, observe summary, launch verdict) sees it. Idempotent:
// prior intent_conformance signals for the run are cleared first.
func emitSignals(db *sql.DB, runID string, diffs []IntentRuntimeDiff) error {
	if _, err := db.Exec(`DELETE FROM signals WHERE run_id = ? AND dimension = 'intent_conformance'`, runID); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, d := range diffs {
		sev := severityForStatus(d.Status)
		if sev == "" {
			continue // decided_and_executed: a healthy match raises no signal
		}
		if _, err := db.Exec(`INSERT INTO signals
			(id, dimension, signal_type, graph_ref_kind, graph_ref_id, run_id, tool_call_id, severity,
			 confidence, recommended_action, produced_by, source_table, source_id, created_at)
			VALUES (?, 'intent_conformance', ?, 'edge', ?, ?, ?, ?, ?, ?, 'intent.diff', 'intent_diffs', ?, ?)`,
			"sig-"+trimDiff(d.ID), signalType(d), d.ID, runID, d.ToolCallID, sev,
			d.Confidence, recommendedAction(d.Status), d.ID, now); err != nil {
			return err
		}
	}
	return nil
}

func severityForStatus(status string) string {
	switch status {
	case StatusRefusedBypass:
		return "critical"
	case StatusMismatch:
		return "high"
	case StatusCoverageGap:
		return "info"
	default:
		return "" // decided_and_executed
	}
}

func signalType(d IntentRuntimeDiff) string {
	if d.Finding != "" {
		return d.Finding
	}
	return d.Status
}

func recommendedAction(status string) string {
	switch status {
	case StatusRefusedBypass:
		return "investigate: a refused action's effects occurred anyway"
	case StatusMismatch:
		return "review: runtime exceeded declared intent"
	case StatusCoverageGap:
		return "improve intent capture for this scope"
	}
	return ""
}

func trimDiff(id string) string { return strings.ReplaceAll(strings.TrimPrefix(id, "diff/"), "/", "-") }

// effectEventTypes are the runtime events worth normalizing into effects: the
// process anchor plus the security-relevant syscalls. Benign high-volume events
// (hundreds of library file_opens) are excluded so the diff stays signal.
var effectEventTypes = []string{"execve", "secret_path", "metadata_ip", "private_cidr", "network_connect", "file_write"}

// normalizeEffects classifies a run's security-relevant events into normalized
// RuntimeEffects and attributes each to an agent. Attribution has two tiers, most
// precise first: (1) the command-match agent_syscall edge (a specific sub-agent's
// tool call caused this syscall); (2) the event's own tool_call -> agent_id.
// When neither resolves an agent, the effect is left scope-attributed but
// agent-unattributed -- the diff then reports it honestly as an
// intent_coverage_gap rather than inventing a mismatch. This is the crux of the
// honesty contract: an effect we cannot tie to captured intent is a gap, not a
// rogue action.
func normalizeEffects(db *sql.DB, runID string, eng security.Engine) ([]RuntimeEffect, error) {
	// tool_call -> agent
	agentOf := map[string]string{}
	arows, err := db.Query(`SELECT id, agent_id FROM tool_calls WHERE run_id = ? AND agent_id != ''`, runID)
	if err != nil {
		return nil, err
	}
	for arows.Next() {
		var id, agent string
		if err := arows.Scan(&id, &agent); err != nil {
			arows.Close()
			return nil, err
		}
		agentOf[id] = agent
	}
	arows.Close()

	// Refinement: command-match attribution (agent_syscall edge: tool_call ->
	// runtime_event/<eventID>) overrides the coarse tool_call join when present.
	refinedAgent := map[string]string{}
	refinedToolCall := map[string]string{}
	erows, err := db.Query(`SELECT from_id, to_id FROM graph_edges
		WHERE run_id = ? AND edge_type = 'agent_syscall'`, runID)
	if err != nil {
		return nil, err
	}
	for erows.Next() {
		var from, to string
		if err := erows.Scan(&from, &to); err != nil {
			erows.Close()
			return nil, err
		}
		eid := strings.TrimPrefix(to, "runtime_event/")
		if a := agentOf[from]; a != "" {
			refinedAgent[eid] = a
			refinedToolCall[eid] = from
		}
	}
	erows.Close()

	windows := loadToolCallWindows(db, runID)

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(effectEventTypes)), ",")
	args := []any{runID}
	for _, t := range effectEventTypes {
		args = append(args, t)
	}
	rows, err := db.Query(`SELECT id, event_type, COALESCE(tool_call_id,''), payload, correlation_confidence, created_at
		FROM events WHERE run_id = ? AND event_type IN (`+placeholders+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuntimeEffect
	for rows.Next() {
		var id, etype, toolCall, payload, createdAt string
		var conf float64
		if err := rows.Scan(&id, &etype, &toolCall, &payload, &conf, &createdAt); err != nil {
			return nil, err
		}
		kind, target, ok := classifyEvent(eng, etype, payload)
		if !ok {
			continue
		}
		if conf == 0 {
			conf = 1.0 // kernel-witnessed default when the store left it unset
		}
		// Attribution, most precise first: (1) command-match agent_syscall edge;
		// (2) the event's own correlated tool_call -> agent; (3) time-window --
		// the hook tool_call whose real [start,end] brackets this effect. Each
		// tier caps the attribution confidence carried into the diff.
		agent := refinedAgent[id]
		tc := toolCall
		if r := refinedToolCall[id]; r != "" {
			tc = r
		}
		if agent == "" {
			agent = agentOf[toolCall]
		}
		if agent == "" {
			// Time-window attribution requires BOTH the effect's timestamp to fall
			// in the tool call's window AND its process comm to match the tool
			// call's program -- otherwise a harness background thread (claude/Bun)
			// that touched the same file in the same window would be misattributed
			// to the tool as a spurious mismatch.
			if w, ok := windows.containing(createdAt, extractComm(payload)); ok {
				agent, tc = w.agent, w.toolCall
				if conf > timeWindowConfidence {
					conf = timeWindowConfidence
				}
			}
		}
		out = append(out, RuntimeEffect{
			Kind: kind, Target: target, AgentID: agent,
			ToolCallID: tc, EventID: id, Confidence: conf,
		})
	}
	return out, nil
}

// timeWindowConfidence caps attribution made purely by time bracketing (weaker
// than a command-match or a kernel cgroup correlation, stronger than nothing).
const timeWindowConfidence = 0.7

// grace is how far outside a tool call's hook window an effect may still be
// attributed to it. Small on purpose: big enough for the hook/syscall skew
// (~3s), small enough that an async effect tens of seconds later is NOT pinned
// to a nearby same-program tool call. Bigger gaps are honest coverage_gaps.
const grace = 10 * time.Second

type toolCallWindow struct {
	agent, toolCall string
	program         string // basename of the tool call's leading program token
	start, end      time.Time
}

type toolCallWindows []toolCallWindow

// loadToolCallWindows loads each agent hook tool_call's real [start,end] window.
// Windows are only usable once hook events carry real timestamps (launch's
// hook-log stamps them); tool_calls left at the synthetic epoch are ignored so a
// bogus 2026-01-01 window can never bracket a real effect.
func loadToolCallWindows(db *sql.DB, runID string) toolCallWindows {
	rows, err := db.Query(`SELECT id, agent_id, command, started_at, ended_at FROM tool_calls
		WHERE run_id = ? AND agent_id != '' AND started_at != ''`, runID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out toolCallWindows
	for rows.Next() {
		var id, agent, command, startedAt, endedAt string
		if err := rows.Scan(&id, &agent, &command, &startedAt, &endedAt); err != nil {
			return out
		}
		start, err := time.Parse(time.RFC3339Nano, startedAt)
		if err != nil || start.Year() < 2020 {
			continue // synthetic-epoch or unparseable -> not a real window
		}
		end, err := time.Parse(time.RFC3339Nano, endedAt)
		if err != nil {
			end = start
		}
		// Grace: PostToolUse can fire a few seconds before the tool's subprocess
		// actually performs its syscalls (observed ~3s on the lab VM), so a tight
		// window misses the real effect. But it must stay SMALL: a truly async
		// effect (e.g. an install that triggers a background exfil ~35s later) must
		// NOT be pinned to a same-program tool call that merely ran nearby -- that
		// is a wrong-tool attribution. Effects outside this grace fall to an honest
		// coverage_gap; tying them back needs command-match, not a wider window.
		out = append(out, toolCallWindow{
			agent: agent, toolCall: id, program: programName(command),
			start: start.Add(-grace), end: end.Add(grace),
		})
	}
	return out
}

// containing returns the most specific (latest-starting) window that both
// brackets ts AND whose program matches the effect's process comm. The comm gate
// is what stops a harness background thread (comm=claude/"Bun Pool") from being
// attributed to an unrelated tool call whose subprocess (comm=cat, python3, ...)
// is what the window is really about. When comm is unknown, no time-window
// attribution is made -- the effect falls to an honest coverage gap.
func (w toolCallWindows) containing(createdAt, comm string) (toolCallWindow, bool) {
	ts, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil || comm == "" {
		return toolCallWindow{}, false
	}
	comm = strings.ToLower(comm)
	best := -1
	for i, win := range w {
		if win.program == "" || win.program != comm {
			continue
		}
		if !ts.Before(win.start) && !ts.After(win.end) {
			if best == -1 || win.start.After(w[best].start) {
				best = i
			}
		}
	}
	if best == -1 {
		return toolCallWindow{}, false
	}
	return w[best], true
}

// programName returns the lowercased basename of a command's leading token
// ("cat /a/b" -> "cat", "/usr/bin/python3 x" -> "python3"), for matching against
// a runtime event's process comm.
func programName(command string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return ""
	}
	prog := fields[0]
	if i := strings.LastIndex(prog, "/"); i >= 0 {
		prog = prog[i+1:]
	}
	return strings.ToLower(prog)
}

func persistDiffs(db *sql.DB, runID string, diffs []IntentRuntimeDiff) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM intent_diffs WHERE run_id = ?`, runID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM graph_edges WHERE run_id = ? AND edge_type IN (?, ?)`,
		runID, edgeIntentContract, edgeIntentEffect); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	seq := 0
	for _, d := range diffs {
		declared, _ := json.Marshal(d.Declared)
		forbidden, _ := json.Marshal(d.Forbidden)
		observed, _ := json.Marshal(d.Observed)
		if _, err := tx.Exec(`INSERT INTO intent_diffs
			(id, run_id, agent_id, tool_call_id, contract_kind, operation, target, status, finding, confidence,
			 declared_effects, forbidden_effects, observed_effects, mismatch_reason, source, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			d.ID, runID, d.AgentID, d.ToolCallID, d.ContractKind, d.Operation, d.Target, d.Status, d.Finding, d.Confidence,
			string(declared), string(forbidden), string(observed), d.MismatchReason, d.Source, now); err != nil {
			return err
		}
		// Wire the diff into the graph: scope -> diff node, and diff node -> each
		// observed runtime event. Endpoints are not checked by graph verify, so
		// these new edge types are safe to add.
		scope := "agent/" + d.AgentID
		if d.ToolCallID != "" {
			scope = d.ToolCallID
		}
		if err := insertEdge(tx, runID, scope, d.ID, edgeIntentContract, now, &seq); err != nil {
			return err
		}
		for _, eid := range d.EventIDs {
			if err := insertEdge(tx, runID, d.ID, "runtime_event/"+eid, edgeIntentEffect, now, &seq); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// insertEdge writes a graph edge with a per-persist monotonic id, so the primary
// key can never collide within a run's diff materialization.
func insertEdge(tx *sql.Tx, runID, from, to, edgeType, now string, seq *int) error {
	*seq++
	_, err := tx.Exec(`INSERT INTO graph_edges (id, run_id, from_id, to_id, edge_type, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		fmt.Sprintf("edge-%s-%s-%d", edgeType, runID, *seq), runID, from, to, edgeType, now)
	return err
}

// --- small string helpers shared across the package ---

func trimContract(id string) string { return strings.TrimPrefix(id, "contract/") }

func joinKinds(ks []EffectKind) string {
	parts := make([]string, len(ks))
	for i, k := range ks {
		parts[i] = string(k)
	}
	return strings.Join(parts, ", ")
}

func shorten(s string, n int) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n]
}
