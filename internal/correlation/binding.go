package correlation

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
)

type Binding struct {
	ID            string
	RunID         string
	SessionID     string
	AttemptID     string
	ToolCallID    string
	ProcessID     string
	ContainerID   string
	CgroupID      string
	RootPID       int64
	PID           int64
	StartedAt     string
	EndedAt       string
	BindingSource string
	Confidence    float64
}

type RawIdentity struct {
	RunID       string
	ProcessID   string
	ContainerID string
	CgroupID    string
	PID         int64
	TGID        int64
	PPID        int64
	Timestamp   string
}

type Match struct {
	Binding
	Method     string
	Confidence float64
}

type BindingFilter struct {
	RunID      string
	SessionID  string
	AttemptID  string
	ToolCallID string
	ProcessID  string
}

// BindingSourceK8sCgroup marks a scope established by passive cgroup→pod
// attribution (a node sensor observing an externally-scheduled pod we did not
// launch), as opposed to a scope we launched via record/control-plane.
const BindingSourceK8sCgroup = "k8s_cgroup"

// DefaultBindingConfidence caps how much a binding may vouch for a match by how
// it was established, when the caller did not set an explicit confidence.
// scanOne takes the MIN of this binding confidence and the resolution method's
// own confidence, so an app-asserted (ai_asserted) join can never read as
// certain as a kernel-verified one even if it happens to match by pid. This is
// the honesty tier: a scope the model merely CLAIMED is worth less than one the
// control plane launched or the kernel witnessed.
func DefaultBindingConfidence(bindingSource string) float64 {
	switch bindingSource {
	case "ai_asserted":
		// App-asserted only: a join key the model provided. Real, but unverified.
		return 0.5
	case BindingSourceK8sCgroup:
		// Passive cgroup→pod attribution: the kernel really witnessed these
		// events in this cgroup, but we did not launch the scope via record, so
		// it sits below a control-plane/record binding and above a bare claim.
		return 0.8
	default:
		// Control-plane / record / rollout launches and direct API binds are
		// first-party facts about a process we started; keep them authoritative.
		return 1
	}
}

func RecordBinding(db *sql.DB, binding Binding) (string, error) {
	if binding.StartedAt == "" {
		binding.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if binding.BindingSource == "" {
		binding.BindingSource = "control_plane"
	}
	if binding.Confidence <= 0 {
		binding.Confidence = DefaultBindingConfidence(binding.BindingSource)
	}
	if binding.ID == "" {
		binding.ID = ids.New("bind")
	}
	_, err := db.Exec(`INSERT INTO execution_context_bindings
		(id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, started_at, ended_at, binding_source, confidence, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		binding.ID, binding.RunID, binding.SessionID, binding.AttemptID, binding.ToolCallID, binding.ProcessID, binding.ContainerID, binding.CgroupID, binding.RootPID, binding.PID, binding.StartedAt, binding.EndedAt, binding.BindingSource, binding.Confidence, time.Now().UTC().Format(time.RFC3339Nano))
	return binding.ID, err
}

func ListBindings(db *sql.DB, filter BindingFilter) ([]Binding, error) {
	query := `SELECT id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, started_at, ended_at, binding_source, confidence
		FROM execution_context_bindings`
	args := []any{}
	clauses := []string{}
	if filter.RunID != "" {
		clauses = append(clauses, "run_id = ?")
		args = append(args, filter.RunID)
	}
	if filter.SessionID != "" {
		clauses = append(clauses, "session_id = ?")
		args = append(args, filter.SessionID)
	}
	if filter.AttemptID != "" {
		clauses = append(clauses, "attempt_id = ?")
		args = append(args, filter.AttemptID)
	}
	if filter.ToolCallID != "" {
		clauses = append(clauses, "tool_call_id = ?")
		args = append(args, filter.ToolCallID)
	}
	if filter.ProcessID != "" {
		clauses = append(clauses, "process_id = ?")
		args = append(args, filter.ProcessID)
	}
	if len(clauses) > 0 {
		query += " WHERE " + clauses[0]
		for i := 1; i < len(clauses); i++ {
			query += " AND " + clauses[i]
		}
	}
	query += " ORDER BY started_at ASC, created_at ASC"
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var bindings []Binding
	for rows.Next() {
		var binding Binding
		if err := rows.Scan(&binding.ID, &binding.RunID, &binding.SessionID, &binding.AttemptID, &binding.ToolCallID, &binding.ProcessID, &binding.ContainerID, &binding.CgroupID, &binding.RootPID, &binding.PID, &binding.StartedAt, &binding.EndedAt, &binding.BindingSource, &binding.Confidence); err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	return bindings, rows.Err()
}

func GetBinding(db *sql.DB, id string) (Binding, bool, error) {
	if id == "" {
		return Binding{}, false, nil
	}
	var binding Binding
	err := db.QueryRow(`SELECT id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, started_at, ended_at, binding_source, confidence
		FROM execution_context_bindings WHERE id = ?`, id).
		Scan(&binding.ID, &binding.RunID, &binding.SessionID, &binding.AttemptID, &binding.ToolCallID, &binding.ProcessID,
			&binding.ContainerID, &binding.CgroupID, &binding.RootPID, &binding.PID, &binding.StartedAt, &binding.EndedAt,
			&binding.BindingSource, &binding.Confidence)
	if err == sql.ErrNoRows {
		return Binding{}, false, nil
	}
	if err != nil {
		return Binding{}, false, err
	}
	return binding, true, nil
}

func CloseBinding(db *sql.DB, processID, endedAt string) error {
	if processID == "" {
		return nil
	}
	if endedAt == "" {
		endedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	_, err := db.Exec(`UPDATE execution_context_bindings SET ended_at = ? WHERE process_id = ? AND ended_at = ''`, endedAt, processID)
	return err
}

// CloseBindingByPID closes open bindings for an OS pid, used when a system
// process_exit is observed (the kernel pid is known, our internal process_id is
// not). Setting ended_at bounds the binding's match window so it no longer
// over-binds later, unrelated events that reuse the pid -- the stale-open
// problem MaxOpenBindingAge only partially guards. Matches pid, not root_pid: a
// child exiting must not close the scope-root's binding.
func CloseBindingByPID(db *sql.DB, pid int64, endedAt string) error {
	if pid == 0 {
		return nil
	}
	if endedAt == "" {
		endedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	_, err := db.Exec(`UPDATE execution_context_bindings SET ended_at = ? WHERE pid = ? AND ended_at = ''`, endedAt, pid)
	return err
}

func Resolve(db *sql.DB, raw RawIdentity) (Match, bool, error) {
	at := raw.Timestamp
	if at == "" {
		at = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if raw.ProcessID != "" {
		match, ok, err := resolveByProcess(db, raw.RunID, raw.ProcessID)
		if err != nil || ok {
			return match, ok, err
		}
	}
	if raw.CgroupID != "" {
		match, ok, err := resolveByCgroup(db, raw.RunID, raw.CgroupID, at)
		if err != nil || ok {
			return match, ok, err
		}
	}
	if raw.ContainerID != "" {
		match, ok, err := resolveByContainer(db, raw.RunID, raw.ContainerID, at)
		if err != nil || ok {
			return match, ok, err
		}
	}
	if raw.PID != 0 {
		match, ok, err := resolveByPID(db, raw.RunID, raw.PID, at)
		if err != nil || ok {
			return match, ok, err
		}
	}
	return Match{}, false, nil
}

func resolveByProcess(db *sql.DB, runID, processID string) (Match, bool, error) {
	if runID != "" {
		return scanOne(db, "process_id", "run_id+process_id", 1, `SELECT id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, started_at, ended_at, binding_source, confidence
			FROM execution_context_bindings WHERE run_id = ? AND process_id = ? ORDER BY created_at DESC LIMIT 1`, runID, processID)
	}
	return scanOne(db, "process_id", "process_id", 1, `SELECT id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, started_at, ended_at, binding_source, confidence
		FROM execution_context_bindings WHERE process_id = ? ORDER BY created_at DESC LIMIT 1`, processID)
}

// MaxOpenBindingAge bounds how long a binding left open (ended_at = "") is
// allowed to match telemetry. Without it, a binding whose CloseBinding was
// dropped - every close call is best-effort (record/control) - would
// match every future event for its container/pid forever, silently over-binding
// later, unrelated executions to a stale context. An open binding only matches
// events within this window after it started; older events fall through to the
// next resolution tier or to unresolved.
//
// PRODUCT SEMANTICS: this assumes an open binding represents a SHORT-LIVED
// ToolCallScope (a tool call / process lifetime), not a session-lifetime
// identity. A long-running agent or session that stays open past this window
// without a close/reopen will see its real events go unresolved rather than
// risk mis-binding - which is the safe failure here. Session-lifetime identity
// that legitimately exceeds 24h must keep its binding refreshed (re-record on
// activity) or model itself as a series of scoped bindings, not one perpetual
// open binding. Tune via this var if the deployment's scope lifetimes differ.
var MaxOpenBindingAge = 24 * time.Hour

// openBindingLowerBound returns the earliest started_at an open binding may have
// to still match an event observed at `at`. On an unparseable timestamp it
// returns "" (every RFC3339 value is lexically >= ""), preserving the legacy
// unbounded-open behavior rather than silently dropping matches.
func openBindingLowerBound(at string) string {
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return ""
	}
	return t.Add(-MaxOpenBindingAge).UTC().Format(time.RFC3339Nano)
}

const bindingColumns = `id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, started_at, ended_at, binding_source, confidence`

// resolveWindow runs a time-windowed binding lookup, shared by the
// cgroup/container/pid tiers (previously six near-identical queries). matchExpr
// is the tier predicate (e.g. "cgroup_id = ?"); matchArgs are its bound values.
//
// boundOpen applies the stale-open guard (MaxOpenBindingAge) to bindings left
// open (ended_at = ""). It is enabled ONLY for the pid tier: pid reuse is the
// real over-matching threat for an accidentally-unclosed binding. container_id /
// cgroup_id are specific keys, and a long-lived open anchor on them (e.g. an
// external-telemetry bind with a far-past start meant to match all events for a
// container) is a legitimate, intentional pattern that must keep resolving.
func resolveWindow(db *sql.DB, runID, method, source, matchExpr string, confidence float64, at string, boundOpen bool, matchArgs ...any) (Match, bool, error) {
	var sb strings.Builder
	args := make([]any, 0, len(matchArgs)+4)
	sb.WriteString("SELECT " + bindingColumns + " FROM execution_context_bindings WHERE ")
	if runID != "" {
		sb.WriteString("run_id = ? AND ")
		args = append(args, runID)
	}
	sb.WriteString(matchExpr)
	args = append(args, matchArgs...)
	sb.WriteString(" AND started_at <= ?")
	args = append(args, at)
	if boundOpen {
		// Closed interval still covers `at`, or open but started within
		// MaxOpenBindingAge of `at` (guards pid-reuse over-matching).
		sb.WriteString(" AND ((ended_at != '' AND ended_at >= ?) OR (ended_at = '' AND started_at >= ?))")
		args = append(args, at, openBindingLowerBound(at))
	} else {
		sb.WriteString(" AND (ended_at = '' OR ended_at >= ?)")
		args = append(args, at)
	}
	sb.WriteString(" ORDER BY started_at DESC LIMIT 1")
	return scanOne(db, method, source, confidence, sb.String(), args...)
}

func resolveByCgroup(db *sql.DB, runID, cgroupID, at string) (Match, bool, error) {
	source := "cgroup_id+time"
	if runID != "" {
		source = "run_id+cgroup_id+time"
	}
	return resolveWindow(db, runID, "cgroup_time_window", source, "cgroup_id = ?", 0.98, at, false, cgroupID)
}

func resolveByContainer(db *sql.DB, runID, containerID, at string) (Match, bool, error) {
	source := "container_id+time"
	if runID != "" {
		source = "run_id+container_id+time"
	}
	return resolveWindow(db, runID, "container_time_window", source, "container_id = ?", 0.92, at, false, containerID)
}

func resolveByPID(db *sql.DB, runID string, pid int64, at string) (Match, bool, error) {
	source := "pid+time"
	if runID != "" {
		source = "run_id+pid+time"
	}
	return resolveWindow(db, runID, "pid_time_window", source, "(pid = ? OR root_pid = ?)", 0.85, at, true, pid, pid)
}

func scanOne(db *sql.DB, method, source string, confidence float64, query string, args ...any) (Match, bool, error) {
	var item Binding
	err := db.QueryRow(query, args...).Scan(&item.ID, &item.RunID, &item.SessionID, &item.AttemptID, &item.ToolCallID, &item.ProcessID, &item.ContainerID, &item.CgroupID, &item.RootPID, &item.PID, &item.StartedAt, &item.EndedAt, &item.BindingSource, &item.Confidence)
	if err == sql.ErrNoRows {
		return Match{}, false, nil
	}
	if err != nil {
		return Match{}, false, err
	}
	if item.Confidence > 0 && item.Confidence < confidence {
		confidence = item.Confidence
	}
	return Match{Binding: item, Method: method + ":" + source, Confidence: confidence}, true, nil
}

func EventPayloadWithCorrelation(payload string, match Match, resolved bool) string {
	if payload == "" {
		payload = "{}"
	}
	if !resolved {
		return fmt.Sprintf(`{"raw":%s,"correlation":{"method":"unresolved","confidence":0}}`, payload)
	}
	return fmt.Sprintf(`{"raw":%s,"correlation":{"binding_id":%q,"method":%q,"confidence":%.2f}}`, payload, match.ID, match.Method, match.Confidence)
}
