// Package dashboard serves a local, read-only web view over the verifiable
// provenance graph: the runs, their merged timeline, the unified signals/risks,
// the verify+signature status, and -- the signature view -- the causality DAG
// (LLM intent -> action -> policy -> risk), which a flat event stream cannot
// show. It is a thin presentation layer: every JSON endpoint reuses the SAME
// internal functions as the CLI/AI tools (provenance.Verify, signals.Export,
// etc.), so the UI never diverges from the contract. Read-only, local-first:
// the HTML/JS is embedded in the binary and loads no external assets.
package dashboard

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/byteyellow/agentprovenance/internal/compliance"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/redact"
	securitymodel "github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/signals"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

//go:embed index.html
var indexHTML []byte

// Server serves the dashboard over a single read-only *sql.DB.
type Server struct{ DB *sql.DB }

// Handler returns the dashboard's HTTP routes (static UI + JSON API).
func (s Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.index)
	mux.HandleFunc("GET /api/runs", s.runs)
	mux.HandleFunc("GET /api/overview", s.overview)
	mux.HandleFunc("GET /api/timeline", s.timeline)
	mux.HandleFunc("GET /api/events", s.events)
	mux.HandleFunc("GET /api/graph", s.graph)
	mux.HandleFunc("GET /api/lens", s.lens)
	mux.HandleFunc("GET /api/artifact", s.artifact)
	mux.HandleFunc("GET /api/egress", s.egress)
	mux.HandleFunc("GET /api/processes", s.processes)
	mux.HandleFunc("GET /api/frameworks", s.frameworks)
	mux.HandleFunc("GET /api/compliance", s.compliance)
	return mux
}

// rawBody unwraps the stored telemetry payload ({"payload":{"raw":{...}}} or
// {"raw":{...}} or a bare body) down to the raw event fields.
func rawBody(payload string) map[string]any {
	var top map[string]any
	if json.Unmarshal([]byte(payload), &top) != nil {
		return map[string]any{}
	}
	if inner, ok := top["payload"].(map[string]any); ok {
		top = inner
	}
	if raw, ok := top["raw"].(map[string]any); ok {
		return raw
	}
	return top
}

func firstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// egress lists the run's outbound network attempts (the destination is the
// security-relevant fact), flagging the risky ones (metadata IP, private CIDR).
func (s Server) egress(w http.ResponseWriter, r *http.Request) {
	run := r.URL.Query().Get("run")
	if run == "" {
		httpError(w, "run is required", 400)
		return
	}
	rows, err := s.DB.Query(`SELECT event_type, payload, created_at FROM events
		WHERE run_id = ? AND event_type IN ('network_connect','metadata_ip','private_cidr','dns_query') ORDER BY created_at`, run)
	if err != nil {
		httpError(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	// A getaddrinfo(hostname) immediately precedes the connect(resolved-IP) in the
	// same process, so the most recent dns_query hostname per comm resolves the IP
	// egress that follows it — giving egress a NAME, not just an IP, node-side.
	lastHost := map[string]string{}
	lastHostAny := ""
	for rows.Next() {
		var et, payload, created string
		if err := rows.Scan(&et, &payload, &created); err != nil {
			httpError(w, err.Error(), 500)
			return
		}
		raw := rawBody(payload)
		comm := firstStr(raw, "comm")
		if et == "dns_query" {
			if h := firstStr(raw, "host"); h != "" {
				lastHost[comm] = h
				lastHostAny = h
			}
			continue // the resolution, not an egress row
		}
		domain := lastHost[comm]
		if domain == "" {
			domain = lastHostAny
		}
		out = append(out, map[string]any{
			"type":   et,
			"dst":    firstStr(raw, "host", "dst_ip", "dst"),
			"domain": domain,
			"port":   firstStr(raw, "port", "dst_port"),
			"comm":   comm,
			"risk":   et == "metadata_ip" || et == "private_cidr",
			"time":   created,
		})
	}
	writeJSON(w, out)
}

// processes returns the run's OS process events (pid/ppid/command) so the client
// can render the process tree by parent pid.
func (s Server) processes(w http.ResponseWriter, r *http.Request) {
	run := r.URL.Query().Get("run")
	if run == "" {
		httpError(w, "run is required", 400)
		return
	}
	rows, err := s.DB.Query(`SELECT pid, ppid, event_type, payload, created_at FROM events
		WHERE run_id = ? AND event_type IN ('execve','process_observed') ORDER BY created_at`, run)
	if err != nil {
		httpError(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var pid, ppid int64
		var et, payload, created string
		if err := rows.Scan(&pid, &ppid, &et, &payload, &created); err != nil {
			httpError(w, err.Error(), 500)
			return
		}
		raw := rawBody(payload)
		out = append(out, map[string]any{
			"pid": pid, "ppid": ppid, "type": et,
			"command": firstStr(raw, "command", "comm"), "comm": firstStr(raw, "comm"), "time": created,
		})
	}
	writeJSON(w, out)
}

// frameworks lists the built-in compliance frameworks (id, title, control count)
// so the UI can populate its framework selector. It mirrors `compliance map` --
// the same compliance.Frameworks() the CLI uses, so the dashboard never drifts
// from the supported set.
func (s Server) frameworks(w http.ResponseWriter, r *http.Request) {
	type fw struct {
		ID         string `json:"id"`
		Title      string `json:"title"`
		Controls   int    `json:"controls"`
		Disclaimer string `json:"disclaimer,omitempty"`
	}
	out := []fw{}
	for _, f := range compliance.Frameworks() {
		out = append(out, fw{ID: f.ID, Title: f.Title, Controls: len(f.Controls), Disclaimer: f.Disclaimer})
	}
	writeJSON(w, out)
}

// compliance maps the configured detection RULES onto a framework's controls
// for one run, returning the four-state coverage report from
// compliance.MapRunRules: enforced (a mapped rule fired and blocked), detected
// (a mapped rule fired but is detect-only), not_triggered (rule exists, did not
// fire), no_rule (no detector maps to this control -- an honest coverage gap,
// not a clean pass). Each evidence ref is an entity (policy_decision/risk_signal)
// the UI cross-links back to its graph node. The rule->control taxonomy lives on
// security.Rule.Controls (single source of truth), so custom YAML rules that set
// controls: participate automatically.
func (s Server) compliance(w http.ResponseWriter, r *http.Request) {
	run := r.URL.Query().Get("run")
	if run == "" {
		httpError(w, "run is required", 400)
		return
	}
	framework := r.URL.Query().Get("framework")
	if framework == "" {
		// Default to the first framework so the panel is never empty.
		if fws := compliance.Frameworks(); len(fws) > 0 {
			framework = fws[0].ID
		}
	}
	report, err := compliance.MapRunRules(s.DB, compliance.RuleMappingOptions{Framework: framework, RunID: run})
	if err != nil {
		httpError(w, err.Error(), 400)
		return
	}
	writeJSON(w, report)
}

func (s Server) index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store") // always serve the latest embedded UI
	_, _ = w.Write(indexHTML)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func httpError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

type runSummary struct {
	Run    string `json:"run"`
	Events int    `json:"events"`
}

func (s Server) runs(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.Query(`SELECT run_id, COUNT(*) FROM events WHERE run_id != ''
		GROUP BY run_id ORDER BY MAX(created_at) DESC`)
	if err != nil {
		httpError(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	out := []runSummary{}
	for rows.Next() {
		var rs runSummary
		if err := rows.Scan(&rs.Run, &rs.Events); err != nil {
			httpError(w, err.Error(), 500)
			return
		}
		out = append(out, rs)
	}
	writeJSON(w, out)
}

// overview bundles verify + signals + risks for one run in a single call.
// graph verify re-reads and re-hashes every provenance object (seconds for a
// large run), and the overview endpoint is hit on first load AND on every live
// refresh. For a read-only dashboard the result is stable until the run's data
// changes, so cache it keyed by a cheap fingerprint (object + event counts).
// This turns the multi-second Run Overview into an instant load after the first.
var (
	verifyCacheMu sync.Mutex
	verifyCache   = map[string]verifyCacheEntry{}
)

type verifyCacheEntry struct {
	fingerprint string
	result      any
}

func (s Server) cachedVerify(run string) any {
	var objs, evs int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM provenance_objects WHERE run_id = ?`, run).Scan(&objs)
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id = ?`, run).Scan(&evs)
	fp := fmt.Sprintf("%d:%d", objs, evs)
	verifyCacheMu.Lock()
	if e, ok := verifyCache[run]; ok && e.fingerprint == fp {
		verifyCacheMu.Unlock()
		return e.result
	}
	verifyCacheMu.Unlock()

	// The local dashboard is an investigation UI. Full graph verification can
	// re-hash tens of thousands of objects and should stay an explicit CLI/API
	// action for large imported bundles. When a ready forensics bundle exists,
	// import already verified its embedded object content before committing rows;
	// surface that fast provenance posture here and keep the page responsive.
	if bundle := s.cachedBundleVerify(run, objs); bundle != nil {
		verifyCacheMu.Lock()
		verifyCache[run] = verifyCacheEntry{fingerprint: fp, result: bundle}
		verifyCacheMu.Unlock()
		return bundle
	}

	var result any
	if v, err := provenance.Verify(s.DB, run); err == nil {
		result = v
	} else {
		result = map[string]any{"error": err.Error()}
	}
	verifyCacheMu.Lock()
	verifyCache[run] = verifyCacheEntry{fingerprint: fp, result: result}
	verifyCacheMu.Unlock()
	return result
}

func (s Server) cachedBundleVerify(run string, objectCount int) any {
	var bundleID, sha, status string
	var size int64
	err := s.DB.QueryRow(`SELECT id, sha256, size_bytes, status FROM forensics_bundles
		WHERE run_id = ? ORDER BY created_at DESC LIMIT 1`, run).Scan(&bundleID, &sha, &size, &status)
	if err == nil && status == "ready" && sha != "" {
		return map[string]any{
			"status":        "ok",
			"error_count":   0,
			"warning_count": 0,
			"mode":          "forensics_bundle",
			"bundle_id":     bundleID,
			"bundle_sha256": sha,
			"bundle_bytes":  size,
		}
	}
	if objectCount > 5000 {
		return map[string]any{
			"status":        "deferred",
			"error_count":   0,
			"warning_count": 1,
			"mode":          "deferred_full_verify",
			"message":       "full graph verification is available through `agentprov graph verify`",
		}
	}
	return nil
}

func (s Server) overview(w http.ResponseWriter, r *http.Request) {
	run := r.URL.Query().Get("run")
	if run == "" {
		httpError(w, "run is required", 400)
		return
	}
	out := map[string]any{}
	out["verify"] = s.cachedVerify(run)
	if sig, err := signals.Export(s.DB, run); err == nil {
		out["signals"] = sig
	}
	if risks, err := securitymodel.BuildRiskSignalsReport(s.DB, run); err == nil {
		out["risks"] = risks
	}
	writeJSON(w, out)
}

func (s Server) timeline(w http.ResponseWriter, r *http.Request) {
	run := r.URL.Query().Get("run")
	if run == "" {
		httpError(w, "run is required", 400)
		return
	}
	events, err := telemetry.ListEventsFiltered(s.DB, telemetry.Filter{RunID: run})
	if err != nil {
		httpError(w, err.Error(), 500)
		return
	}
	total := len(events)
	limit := atoiClamp(r.URL.Query().Get("limit"), 50, 1, 500)
	offset := atoiClamp(r.URL.Query().Get("offset"), 0, 0, total)
	end := offset + limit
	if end > total {
		end = total
	}
	page := events[offset:end]
	if page == nil {
		page = []telemetry.EventRecord{}
	}
	writeJSON(w, map[string]any{"events": page, "total": total, "limit": limit, "offset": offset})
}

func (s Server) events(w http.ResponseWriter, r *http.Request) {
	run := r.URL.Query().Get("run")
	if run == "" {
		httpError(w, "run is required", 400)
		return
	}
	limit := atoiClamp(r.URL.Query().Get("limit"), 50, 1, 500)
	offset := atoiClamp(r.URL.Query().Get("offset"), 0, 0, 1_000_000_000)
	q, err := s.eventQueryFromRequest(run, r)
	if err != nil {
		httpError(w, err.Error(), 500)
		return
	}
	page, total, err := s.queryEventsPage(run, q, limit, offset)
	if err != nil {
		httpError(w, err.Error(), 500)
		return
	}
	if page == nil {
		page = []telemetry.EventRecord{}
	}
	writeJSON(w, map[string]any{
		"schema_version": "agentprovenance.dashboard_events/v1",
		"events":         page,
		"total":          total,
		"limit":          limit,
		"offset":         offset,
		"filter": map[string]any{
			"run": run, "lens": r.URL.Query().Get("lens"), "group": r.URL.Query().Get("group"),
			"focus": r.URL.Query().Get("focus"), "type": r.URL.Query().Get("type"),
			"tool_call": r.URL.Query().Get("tool_call"), "pid": r.URL.Query().Get("pid"),
		},
	})
}

func (s Server) eventQueryFromRequest(run string, r *http.Request) (eventQuery, error) {
	refs := eventRefsFromQuery(r)
	if len(refs) > 0 {
		ids, err := s.resolveEventRefs(run, refs)
		if err != nil {
			return eventQuery{}, err
		}
		if len(ids) == 0 {
			return eventQuery{None: true}, nil
		}
		return eventQuery{IDs: ids}, nil
	}
	q := eventQuery{
		Type:       r.URL.Query().Get("type"),
		ToolCallID: r.URL.Query().Get("tool_call"),
		ProcessID:  r.URL.Query().Get("process"),
		PID:        r.URL.Query().Get("pid"),
	}
	if focus := strings.TrimSpace(r.URL.Query().Get("focus")); focus != "" {
		switch {
		case strings.HasPrefix(focus, "runtime_event/"):
			q.IDs = []string{strings.TrimPrefix(focus, "runtime_event/")}
		case strings.HasPrefix(focus, "runtime_process/pid/"):
			q.PID = strings.TrimPrefix(focus, "runtime_process/pid/")
		case strings.HasPrefix(focus, "process/"):
			q.ProcessID = focus
		case !strings.Contains(focus, "/"):
			q.ToolCallID = focus
		}
	}
	applyLensGroupFilter(&q, r.URL.Query().Get("lens"), r.URL.Query().Get("group"))
	return q, nil
}

type eventQuery struct {
	None       bool
	IDs        []string
	Types      []string
	Type       string
	ToolCallID string
	ProcessID  string
	PID        string
	PayloadAny []string
	PayloadNot []string
}

func applyLensGroupFilter(q *eventQuery, lens, group string) {
	group = strings.TrimSpace(group)
	switch lens {
	case "process":
		if group != "" && group != "summary" && group != "processes" {
			q.Types = []string{group}
		}
	case "network-egress":
		q.Types = []string{"network_connect", "metadata_ip", "private_cidr", "dns_query", "network_deny", "egress_deny", "tls_write", "tls_read"}
		switch group {
		case "risky_egress":
			q.Types = []string{"metadata_ip", "private_cidr", "network_deny", "egress_deny"}
			q.PayloadNot = append(q.PayloadNot, "127.0.0.")
		case "dns":
			q.Types = []string{"dns_query"}
		case "loopback":
			q.PayloadAny = append(q.PayloadAny, "127.0.0.")
		case "tls":
			q.Types = []string{"tls_write", "tls_read"}
		}
	case "security":
		if group != "" {
			q.Types = append(q.Types, group)
		} else {
			q.Types = []string{"metadata_ip", "private_cidr", "secret_path", "abnormal_process_tree", "setuid", "setgid", "ptrace", "file_rename", "file_unlink"}
		}
	case "file-artifact":
		q.Types = []string{"file_write", "file_create", "file_modify", "file_read", "secret_path", "artifact_export"}
		switch group {
		case "workspace_source_files":
			q.PayloadAny = append(q.PayloadAny, ".py", ".go", ".js", ".ts", ".md", ".yaml", ".yml", ".json")
		case "dependency_cache":
			q.PayloadAny = append(q.PayloadAny, "node_modules", ".venv", "__pycache__", ".cache", "site-packages")
		case "secret_or_config":
			q.PayloadAny = append(q.PayloadAny, "secret", "token", ".env", ".aws", "credentials")
		}
	}
}

func eventRefsFromQuery(r *http.Request) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(raw string) {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part != "" && !seen[part] {
				seen[part] = true
				out = append(out, part)
			}
		}
	}
	for _, raw := range r.URL.Query()["ref"] {
		add(raw)
	}
	add(r.URL.Query().Get("refs"))
	return out
}

func (s Server) resolveEventRefs(run string, refs []string) ([]string, error) {
	seen := map[string]bool{}
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id != "" {
			seen[id] = true
		}
	}
	for _, ref := range refs {
		switch {
		case strings.HasPrefix(ref, "runtime_event/"):
			add(strings.TrimPrefix(ref, "runtime_event/"))
		case strings.HasPrefix(ref, "policy_decision/"):
			id := strings.TrimPrefix(ref, "policy_decision/")
			var eventID string
			if err := s.DB.QueryRow(`SELECT COALESCE(event_id, '') FROM policy_decisions WHERE run_id = ? AND id = ?`, run, id).Scan(&eventID); err == nil {
				add(eventID)
			}
		case strings.HasPrefix(ref, "risk_signal/"):
			id := strings.TrimPrefix(ref, "risk_signal/")
			var eventID string
			if err := s.DB.QueryRow(`SELECT COALESCE(event_id, '') FROM risk_signals WHERE run_id = ? AND id = ?`, run, id).Scan(&eventID); err == nil {
				add(eventID)
			}
		case strings.HasPrefix(ref, "response_action/"):
			id := strings.TrimPrefix(ref, "response_action/")
			rows, err := s.DB.Query(`SELECT COALESCE(rs.event_id, ''), COALESCE(pd.event_id, '')
				FROM response_actions ra
				LEFT JOIN risk_signals rs ON rs.id = ra.risk_signal_id AND rs.run_id = ra.run_id
				LEFT JOIN policy_decisions pd ON pd.id = ra.policy_decision_id AND pd.run_id = ra.run_id
				WHERE ra.run_id = ? AND ra.id = ?`, run, id)
			if err != nil {
				return nil, err
			}
			for rows.Next() {
				var riskEvent, policyEvent string
				if err := rows.Scan(&riskEvent, &policyEvent); err != nil {
					rows.Close()
					return nil, err
				}
				add(riskEvent)
				add(policyEvent)
			}
			rows.Close()
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	return ids, nil
}

func (s Server) queryEventsPage(run string, q eventQuery, limit, offset int) ([]telemetry.EventRecord, int, error) {
	if q.None {
		return []telemetry.EventRecord{}, 0, nil
	}
	where, args := eventWhereClause(run, q)
	var total int
	if err := s.DB.QueryRow(`SELECT COALESCE(COUNT(*), 0) FROM events `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if offset > total {
		offset = total
	}
	query := `SELECT id, COALESCE(run_id, ''), COALESCE(session_id, ''), COALESCE(tool_call_id, ''),
		COALESCE(process_id, ''), COALESCE(snapshot_id, ''), COALESCE(raw_event_id, ''),
		COALESCE(correlation_method, ''), COALESCE(correlation_confidence, 0),
		COALESCE(container_id, ''), COALESCE(cgroup_id, ''), COALESCE(pid, 0),
		COALESCE(tgid, 0), COALESCE(ppid, 0), COALESCE(binding_source, ''),
		source, event_type, payload, created_at
		FROM events `
	query += where + " ORDER BY created_at ASC, id ASC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)
	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []telemetry.EventRecord{}
	for rows.Next() {
		var event telemetry.EventRecord
		if err := rows.Scan(&event.ID, &event.RunID, &event.SessionID, &event.ToolCallID, &event.ProcessID, &event.SnapshotID, &event.RawEventID, &event.CorrelationMethod, &event.CorrelationConfidence, &event.ContainerID, &event.CgroupID, &event.PID, &event.TGID, &event.PPID, &event.BindingSource, &event.Source, &event.EventType, &event.Payload, &event.CreatedAt); err != nil {
			return nil, 0, err
		}
		event.CorrelationClass = telemetry.CorrelationClass(event.Source, event.CorrelationMethod, event.ContainerID, event.CorrelationConfidence)
		event.SelfLaunched = telemetry.SelfLaunched(event.Source, event.BindingSource)
		out = append(out, event)
	}
	return out, total, rows.Err()
}

func eventWhereClause(run string, q eventQuery) (string, []any) {
	args := []any{run}
	clauses := []string{"run_id = ?"}
	if len(q.IDs) > 0 {
		ph := make([]string, 0, len(q.IDs))
		for _, id := range q.IDs {
			ph = append(ph, "?")
			args = append(args, id)
		}
		clauses = append(clauses, "id IN ("+strings.Join(ph, ",")+")")
	}
	if q.Type != "" {
		clauses = append(clauses, "event_type = ?")
		args = append(args, q.Type)
	}
	if len(q.Types) > 0 {
		ph := make([]string, 0, len(q.Types))
		for _, typ := range q.Types {
			ph = append(ph, "?")
			args = append(args, typ)
		}
		clauses = append(clauses, "event_type IN ("+strings.Join(ph, ",")+")")
	}
	if q.ToolCallID != "" {
		clauses = append(clauses, "tool_call_id = ?")
		args = append(args, q.ToolCallID)
	}
	if q.ProcessID != "" {
		clauses = append(clauses, "process_id = ?")
		args = append(args, q.ProcessID)
	}
	if q.PID != "" {
		clauses = append(clauses, "pid = ?")
		args = append(args, q.PID)
	}
	if len(q.PayloadAny) > 0 {
		ors := make([]string, 0, len(q.PayloadAny))
		for _, v := range q.PayloadAny {
			ors = append(ors, "payload LIKE ?")
			args = append(args, "%"+v+"%")
		}
		clauses = append(clauses, "("+strings.Join(ors, " OR ")+")")
	}
	for _, v := range q.PayloadNot {
		clauses = append(clauses, "payload NOT LIKE ?")
		args = append(args, "%"+v+"%")
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

func atoiClamp(s string, def, lo, hi int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		n = def
	}
	if n < lo {
		n = lo
	}
	if n > hi {
		n = hi
	}
	return n
}

func (s Server) lens(w http.ResponseWriter, r *http.Request) {
	run := r.URL.Query().Get("run")
	if run == "" {
		httpError(w, "run is required", 400)
		return
	}
	manifest, err := provenance.BuildGraphLens(s.DB, provenance.GraphLensOptions{
		RunID:    run,
		Lens:     r.URL.Query().Get("lens"),
		Focus:    r.URL.Query().Get("focus"),
		Detail:   r.URL.Query().Get("detail"),
		Overlays: r.URL.Query()["overlay"],
		Limit:    atoiClamp(r.URL.Query().Get("limit"), 500, 1, 2000),
	})
	if err != nil {
		httpError(w, err.Error(), 500)
		return
	}
	writeJSON(w, manifest)
}

// --- artifact content preview (Side Panel) ---

const (
	artifactPreviewBytes = 64 * 1024 // text shown to the user
	artifactReadBytes    = 8 << 20   // cap on what we'll read at all
)

type artifactResp struct {
	Kind      string `json:"kind"` // text | diff | binary | unavailable
	Ref       string `json:"ref,omitempty"`
	Source    string `json:"source,omitempty"` // object | file
	SHA256    string `json:"sha256,omitempty"`
	Size      int64  `json:"size"`
	Mime      string `json:"mime,omitempty"`
	Truncated bool   `json:"truncated"`
	Redacted  bool   `json:"redacted"`
	Content   string `json:"content,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// artifact serves a bounded, type-aware, secret-redacted preview of the content
// behind a graph node — the provenance object it was materialized into (by
// source_id/hash) or a recorded artifact file. It never serves arbitrary paths:
// only content registered for this run, capped at artifactReadBytes.
func (s Server) artifact(w http.ResponseWriter, r *http.Request) {
	run := r.URL.Query().Get("run")
	node := r.URL.Query().Get("node")
	if run == "" || node == "" {
		httpError(w, "run and node are required", 400)
		return
	}
	path, hash, source := s.resolveArtifactPath(run, node)
	if path == "" {
		// No stored object file, but many graph nodes still carry inspectable
		// content in the DB: a tool_call's command/verdict, a runtime event's
		// payload. Serve that so the node isn't a dead click.
		if content, ok := s.nodeDBContent(run, node); ok {
			writeJSON(w, artifactResp{Kind: "text", Source: "db", Mime: "text/plain", Content: content})
			return
		}
		writeJSON(w, artifactResp{Kind: "unavailable", Reason: "no stored content for this node"})
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		writeJSON(w, artifactResp{Kind: "unavailable", Ref: hash, Source: source, Reason: "content not present on this host"})
		return
	}
	resp := artifactResp{Ref: hash, Source: source, Size: info.Size()}
	if info.Size() > artifactReadBytes {
		resp.Kind = "unavailable"
		resp.Reason = "artifact too large to preview"
		writeJSON(w, resp)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		resp.Kind = "unavailable"
		resp.Reason = "content unreadable"
		writeJSON(w, resp)
		return
	}
	if resp.SHA256 = hash; resp.SHA256 == "" {
		sum := sha256.Sum256(data)
		resp.SHA256 = "sha256:" + hex.EncodeToString(sum[:])
	}
	// Artifact objects wrap the file in a provenance envelope; show the file the
	// node produced, not the metadata wrapper. (Evidence objects — events, policy,
	// etc. — are left as-is so the panel shows the full signed record.)
	mimePath := path
	if rendered, ok := renderLLMMessage(data); ok {
		// A captured LLM request/response: show a readable summary + the pretty
		// body, not the raw provenance envelope with a double-escaped content field.
		data = rendered
		mimePath = "llm-message.txt"
	} else if content, srcPath, ok := unwrapArtifactContent(data); ok {
		data = content
		if srcPath != "" {
			mimePath = srcPath
		}
	}
	preview := data
	if len(preview) > artifactPreviewBytes {
		preview = preview[:artifactPreviewBytes]
		resp.Truncated = true
	}
	if isBinaryContent(preview) {
		resp.Kind = "binary"
		resp.Mime = "application/octet-stream"
		resp.Reason = "binary content — hash and size only"
		writeJSON(w, resp)
		return
	}
	red, didRedact := redactSecrets(string(preview))
	resp.Content = red
	resp.Redacted = didRedact
	resp.Mime = mimeForPath(mimePath)
	if looksLikeDiff(red) {
		resp.Kind = "diff"
	} else {
		resp.Kind = "text"
	}
	writeJSON(w, resp)
}

// nodeDBContent builds an inspectable text preview for graph nodes that have no
// stored object file: tool_calls (command + verdict) and runtime events (payload).
func (s Server) nodeDBContent(run, node string) (string, bool) {
	seg := node
	if i := strings.LastIndex(node, "/"); i >= 0 {
		seg = node[i+1:]
	}
	if strings.HasPrefix(node, "runtime_event/") {
		var etype, payload string
		if err := s.DB.QueryRow(`SELECT event_type, COALESCE(payload,'') FROM events WHERE run_id = ? AND id = ?`, run, seg).Scan(&etype, &payload); err == nil {
			var b strings.Builder
			fmt.Fprintf(&b, "event: %s\n\n", etype)
			var pretty bytes.Buffer
			if json.Indent(&pretty, []byte(payload), "", "  ") == nil {
				b.Write(pretty.Bytes())
			} else {
				b.WriteString(payload)
			}
			return b.String(), true
		}
	}
	var cmd, status, policy string
	if err := s.DB.QueryRow(`SELECT COALESCE(command,''), COALESCE(status,''), COALESCE(policy_decision,'')
		FROM tool_calls WHERE run_id = ? AND id = ?`, run, seg).Scan(&cmd, &status, &policy); err == nil && (cmd != "" || status != "") {
		var b strings.Builder
		if status != "" {
			fmt.Fprintf(&b, "status: %s", status)
			if policy != "" && policy != "allow" {
				fmt.Fprintf(&b, "   (%s)", policy)
			}
			b.WriteString("\n\n")
		}
		b.WriteString(cmd)
		return b.String(), true
	}
	return "", false
}

// resolveArtifactPath maps a graph node to a content source recorded for this run:
// first the provenance object it was materialized into (matched by source_id or
// hash, accepting a "prefix/<id>" node form), then a recorded artifact result file.
func (s Server) resolveArtifactPath(run, node string) (path, hash, source string) {
	seg := node
	if i := strings.LastIndex(node, "/"); i >= 0 {
		seg = node[i+1:]
	}
	row := s.DB.QueryRow(`SELECT path, hash FROM provenance_objects
		WHERE run_id = ? AND (source_id = ? OR source_id = ? OR hash = ? OR hash = ?) LIMIT 1`,
		run, node, seg, node, "sha256:"+strings.TrimPrefix(seg, "sha256:"))
	if err := row.Scan(&path, &hash); err == nil && path != "" {
		return path, hash, "object"
	}
	var p string
	if err := s.DB.QueryRow(`SELECT result_ref FROM tool_calls WHERE run_id = ? AND result_ref = ? AND result_ref != '' LIMIT 1`, run, node).Scan(&p); err == nil && p != "" {
		return p, "", "file"
	}
	if err := s.DB.QueryRow(`SELECT artifact_result FROM fork_attempts WHERE artifact_result = ? AND artifact_result != '' LIMIT 1`, node).Scan(&p); err == nil && p != "" {
		return p, "", "file"
	}
	return "", "", ""
}

// unwrapArtifactContent returns the file content inside an "artifact"-type
// provenance object envelope (and its original path for mime detection). Evidence
// envelopes (other types) return ok=false so they display as their full record.
func unwrapArtifactContent(data []byte) (content []byte, path string, ok bool) {
	var obj struct {
		Schema  string `json:"schema"`
		Type    string `json:"type"`
		Payload struct {
			Content string `json:"content"`
			Path    string `json:"path"`
		} `json:"payload"`
	}
	if json.Unmarshal(data, &obj) != nil {
		return nil, "", false
	}
	if obj.Schema != "agentprov.provenance.object.v1" || obj.Type != "artifact" || obj.Payload.Content == "" {
		return nil, "", false
	}
	return []byte(obj.Payload.Content), obj.Payload.Path, true
}

// renderLLMMessage turns a captured llm_message provenance object into a readable
// preview: a short intent summary followed by the pretty-printed request/response
// body (instead of the raw envelope whose `content` is a double-escaped JSON blob).
func renderLLMMessage(data []byte) ([]byte, bool) {
	var obj struct {
		Type    string `json:"type"`
		Payload struct {
			Direction string `json:"direction"`
			Model     string `json:"model"`
			Content   string `json:"content"`
			Semantics struct {
				MessageCount int      `json:"message_count"`
				ToolsOffered []string `json:"tools_offered"`
				ToolCalls    []string `json:"tool_calls"`
				ToolCommands []string `json:"tool_commands"`
				StopReason   string   `json:"stop_reason"`
			} `json:"semantics"`
		} `json:"payload"`
	}
	if json.Unmarshal(data, &obj) != nil || obj.Type != "llm_message" {
		return nil, false
	}
	p := obj.Payload
	var b strings.Builder
	fmt.Fprintf(&b, "%s   model: %s\n", strings.ToUpper(p.Direction), p.Model)
	s := p.Semantics
	if p.Direction == "request" {
		fmt.Fprintf(&b, "messages: %d\n", s.MessageCount)
		if len(s.ToolsOffered) > 0 {
			fmt.Fprintf(&b, "tools offered: %s\n", strings.Join(s.ToolsOffered, ", "))
		}
	} else {
		if len(s.ToolCalls) > 0 {
			fmt.Fprintf(&b, "decided tool: %s\n", strings.Join(s.ToolCalls, ", "))
		}
		if len(s.ToolCommands) > 0 {
			fmt.Fprintf(&b, "decided command: %s\n", strings.Join(s.ToolCommands, " ; "))
		}
		if s.StopReason != "" {
			fmt.Fprintf(&b, "stop reason: %s\n", s.StopReason)
		}
	}
	b.WriteString("\n─────────── body ───────────\n")
	var pretty bytes.Buffer
	if json.Indent(&pretty, []byte(p.Content), "", "  ") == nil {
		b.Write(pretty.Bytes())
	} else {
		b.WriteString(p.Content)
	}
	return []byte(b.String()), true
}

func isBinaryContent(data []byte) bool {
	if bytes.IndexByte(data, 0) >= 0 {
		return true
	}
	return !utf8.Valid(data)
}

func looksLikeDiff(text string) bool {
	if strings.HasPrefix(text, "diff --git ") || strings.HasPrefix(text, "--- ") || strings.HasPrefix(text, "Index: ") {
		return true
	}
	return diffHunkRe.MatchString(text)
}

func mimeForPath(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "application/json"
	case ".py":
		return "text/x-python"
	case ".diff", ".patch":
		return "text/x-diff"
	case ".md":
		return "text/markdown"
	case ".sh":
		return "text/x-shellscript"
	case ".js", ".ts":
		return "text/javascript"
	default:
		return "text/plain"
	}
}

var diffHunkRe = regexp.MustCompile(`(?m)^@@ .* @@`)

// redactSecrets masks credentials in a previewed artifact so it can't leak them —
// the demo plants fake secrets that the poisoned dependency exfiltrates, and the
// preview must show "it touched a secret" without re-displaying it. This is a
// read-time backstop; capture/write-time redaction (internal/redact via telemetry
// ingest, object materialize, and forensics export) is the primary defense. Both
// share the one redactor so their coverage never drifts.
func redactSecrets(text string) (string, bool) {
	return redact.Redact(text)
}

// --- causality DAG (the signature view) ---

type graphNode struct {
	ID      string         `json:"id"`
	Label   string         `json:"label"`
	Kind    string         `json:"kind"`    // event | policy | risk | response
	Subtype string         `json:"subtype"` // event_type | decision | severity | status
	Detail  string         `json:"detail"`
	Data    map[string]any `json:"data,omitempty"` // full record for the click-through detail panel
}

type graphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"`
}

// causalEdgeTypes is the curated set surfaced in the DAG: the intent chain and
// the enforcement chain. The noisy structural plumbing (runtime_attempt_event,
// runtime_process_observed, ...) is intentionally dropped so the hero story --
// model intent -> action -> policy -> risk -> response -- reads clearly.
var causalEdgeTypes = map[string]bool{
	"llm_call":                      true,
	"llm_intent_caused":             true,
	"runtime_event_policy_decision": true,
	"policy_decision_risk_signal":   true,
	"risk_signal_response_action":   true,
	// Multi-agent orchestration: delegation, peer influence, per-agent tool
	// calls, and the command-match join from a tool call to the syscall it caused.
	"agent_spawn":     true,
	"agent_message":   true,
	"agent_tool_call": true,
	"agent_syscall":   true,
}

func (s Server) graph(w http.ResponseWriter, r *http.Request) {
	run := r.URL.Query().Get("run")
	if run == "" {
		httpError(w, "run is required", 400)
		return
	}
	nodes, err := s.nodeLabels(run)
	if err != nil {
		httpError(w, err.Error(), 500)
		return
	}
	rows, err := s.DB.Query(`SELECT from_id, to_id, edge_type FROM graph_edges
		WHERE run_id = ? ORDER BY created_at, id`, run)
	if err != nil {
		httpError(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	edges := []graphEdge{}
	used := map[string]bool{}
	seenEdge := map[string]bool{}
	for rows.Next() {
		var e graphEdge
		if err := rows.Scan(&e.From, &e.To, &e.Type); err != nil {
			httpError(w, err.Error(), 500)
			return
		}
		if !causalEdgeTypes[e.Type] {
			continue
		}
		key := e.From + "|" + e.To + "|" + e.Type
		if seenEdge[key] {
			continue
		}
		seenEdge[key] = true
		edges = append(edges, e)
		used[e.From] = true
		used[e.To] = true
	}
	outNodes := []graphNode{}
	for _, id := range sortedKeys(used) {
		if n, ok := nodes[id]; ok {
			outNodes = append(outNodes, n)
		} else {
			outNodes = append(outNodes, graphNode{ID: id, Label: shortRef(id), Kind: "other"})
		}
	}
	writeJSON(w, map[string]any{"nodes": outNodes, "edges": edges})
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// nodeLabels builds rich labels for every node a curated edge might reference:
// events by their event_type, and the enforcement nodes by their actual verdict
// (decision / severity / action), so the verdict shows up IN the graph.
func (s Server) nodeLabels(run string) (map[string]graphNode, error) {
	nodes := map[string]graphNode{}
	add := func(n graphNode) { nodes[n.ID] = n }

	evRows, err := s.DB.Query(`SELECT id, event_type, COALESCE(correlation_method,''), COALESCE(correlation_confidence,0), COALESCE(created_at,''), COALESCE(payload,'')
		FROM events WHERE run_id = ?`, run)
	if err != nil {
		return nil, err
	}
	for evRows.Next() {
		var id, etype, method, created, payload string
		var conf float64
		if err := evRows.Scan(&id, &etype, &method, &conf, &created, &payload); err != nil {
			evRows.Close()
			return nil, err
		}
		add(graphNode{ID: "runtime_event/" + id, Label: etype, Kind: "event", Subtype: etype, Detail: method, Data: map[string]any{
			"event_id": id, "event_type": etype, "correlation_method": method, "correlation_confidence": conf, "created_at": created, "payload": payload,
		}})
	}
	evRows.Close()

	pdRows, err := s.DB.Query(`SELECT id, decision, COALESCE(rule_id,''), COALESCE(reason,'') FROM policy_decisions WHERE run_id = ?`, run)
	if err != nil {
		return nil, err
	}
	for pdRows.Next() {
		var id, decision, rule, reason string
		if err := pdRows.Scan(&id, &decision, &rule, &reason); err != nil {
			pdRows.Close()
			return nil, err
		}
		add(graphNode{ID: "policy_decision/" + id, Label: "policy: " + decision, Kind: "policy", Subtype: decision, Detail: reason, Data: map[string]any{
			"decision": decision, "rule_id": rule, "reason": reason,
		}})
	}
	pdRows.Close()

	rsRows, err := s.DB.Query(`SELECT id, signal_type, severity, COALESCE(reason,''), COALESCE(recommended_action,'') FROM risk_signals WHERE run_id = ?`, run)
	if err != nil {
		return nil, err
	}
	for rsRows.Next() {
		var id, stype, severity, reason, action string
		if err := rsRows.Scan(&id, &stype, &severity, &reason, &action); err != nil {
			rsRows.Close()
			return nil, err
		}
		add(graphNode{ID: "risk_signal/" + id, Label: stype, Kind: "risk", Subtype: severity, Detail: "recommended: " + action, Data: map[string]any{
			"signal_type": stype, "severity": severity, "reason": reason, "recommended_action": action,
		}})
	}
	rsRows.Close()

	raRows, err := s.DB.Query(`SELECT id, action_type, COALESCE(status,''), COALESCE(target_type,''), COALESCE(target_id,'') FROM response_actions WHERE run_id = ?`, run)
	if err != nil {
		return nil, err
	}
	for raRows.Next() {
		var id, atype, status, ttype, tid string
		if err := raRows.Scan(&id, &atype, &status, &ttype, &tid); err != nil {
			raRows.Close()
			return nil, err
		}
		add(graphNode{ID: "response_action/" + id, Label: "response: " + atype, Kind: "response", Subtype: status, Detail: status, Data: map[string]any{
			"action_type": atype, "status": status, "target": ttype + "/" + tid,
		}})
	}
	raRows.Close()

	// Multi-agent orchestration nodes (from the hooks bridge): the agents, each
	// agent's tool calls (a denied/refused proposal renders as the "refused"
	// kind), and the objectified peer-message bodies.
	agentNameByID := map[string]string{}
	agRows, err := s.DB.Query(`SELECT id, COALESCE(name,''), COALESCE(agent_type,'') FROM agents WHERE run_id = ?`, run)
	if err != nil {
		return nil, err
	}
	for agRows.Next() {
		var id, name, atype string
		if err := agRows.Scan(&id, &name, &atype); err != nil {
			agRows.Close()
			return nil, err
		}
		agentNameByID[id] = name
		label := name
		if label == "" {
			label = id
		}
		add(graphNode{ID: "agent/" + id, Label: label, Kind: "agent", Subtype: atype, Data: map[string]any{
			"agent_id": id, "name": name, "agent_type": atype,
		}})
	}
	agRows.Close()

	tcRows, err := s.DB.Query(`SELECT id, COALESCE(command,''), COALESCE(status,''), COALESCE(policy_decision,'') FROM tool_calls WHERE run_id = ? AND agent_id != ''`, run)
	if err != nil {
		return nil, err
	}
	for tcRows.Next() {
		var id, command, status, policy string
		if err := tcRows.Scan(&id, &command, &status, &policy); err != nil {
			tcRows.Close()
			return nil, err
		}
		kind := "tool_call"
		if status == "denied" || status == "refused" {
			kind = "refused"
		}
		add(graphNode{ID: id, Label: shortRef(command), Kind: kind, Subtype: status, Detail: policy, Data: map[string]any{
			"command": command, "status": status, "policy_decision": policy,
		}})
	}
	tcRows.Close()

	msgRows, err := s.DB.Query(`SELECT hash, COALESCE(source_id,'') FROM provenance_objects WHERE run_id = ? AND source_id LIKE 'agent_message/%'`, run)
	if err != nil {
		return nil, err
	}
	for msgRows.Next() {
		var hash, sourceID string
		if err := msgRows.Scan(&hash, &sourceID); err != nil {
			msgRows.Close()
			return nil, err
		}
		label, kind, subtype := "message", "message", "peer"
		if from, to, ok := parseAgentMsgSource(sourceID); ok {
			// Topology only, no benign/malicious verdict: peer (对等) vs delegation (主从).
			label = "peer " + agentDisplay(agentNameByID, from) + " -> " + agentDisplay(agentNameByID, to)
			if from == "main" { // main/orchestrator -> sub-agent = delegation
				label = "delegate " + agentDisplay(agentNameByID, from) + " -> " + agentDisplay(agentNameByID, to)
				kind, subtype = "relay", "delegation"
			}
		}
		add(graphNode{ID: hash, Label: label, Kind: kind, Subtype: subtype, Detail: sourceID, Data: map[string]any{
			"source_id": sourceID,
		}})
	}
	msgRows.Close()

	return nodes, nil
}

// parseAgentMsgSource splits "agent_message/<from>-><to>/<seq>" into from/to ids.
func parseAgentMsgSource(sourceID string) (from, to string, ok bool) {
	rest, found := strings.CutPrefix(sourceID, "agent_message/")
	if !found {
		return "", "", false
	}
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		rest = rest[:i]
	}
	return strings.Cut(rest, "->")
}

func agentDisplay(names map[string]string, id string) string {
	if n := names[id]; n != "" {
		return n
	}
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func shortRef(ref string) string {
	if i := lastSlash(ref); i >= 0 && i+1 < len(ref) {
		return ref[:i]
	}
	return ref
}

func lastSlash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}
