// Package hooksbridge translates a Claude Code (or compatible) harness hook log
// into AgentProvenance's graph: agent nodes, delegation spawn edges, peer
// (peer) message edges carrying the message body as objectified evidence, and a
// tool_call per agent tool invocation bound to the acting agent_id. Each proposed
// tool call is pre-flighted through the trusted policy engine so an obviously
// unsafe proposal (e.g. an SSRF to the metadata IP, or a credential read) lands as
// a status=denied "refused" node -- the app-side half of the blame chain the
// kernel sensor later confirms.
//
// Trust boundary: everything the bridge writes is APP-ASSERTED context derived
// from the harness's own hooks (binding_source=hooks). It records no system
// events and forges no signatures; the deny verdict on a refused node is computed
// by the trusted engine, not by the model. The kernel sensor remains the ground
// truth that a syscall actually happened; the bridge only says which agent
// intended it.
package hooksbridge

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	security "github.com/byteyellow/agentprovenance/internal/security"
)

// Edge types the bridge emits (all app-asserted orchestration structure).
const (
	EdgeAgentSpawn    = "agent_spawn"     // delegation: parent/main -> sub-agent (delegation)
	EdgeAgentMessage  = "agent_message"   // peer: sender -> body-object -> recipient (peer influence)
	EdgeAgentToolCall = "agent_tool_call" // agent -> the tool_call it invoked
	EdgeAgentSyscall  = "agent_syscall"   // tool_call -> the kernel event it caused (command-match join)
)

// bindingSource marks every row the bridge writes, so a consumer can tell
// hook-derived orchestration context apart from control-plane / kernel evidence.
const bindingSource = "hooks"

// mainAgentID is the synthetic root: the orchestrator / main thread whose tool
// calls carry no agent_id in the hooks.
const mainAgentID = "main"

// Options configures an ingest.
type Options struct {
	RunID string
	// Engine pre-flights each proposed tool call. Zero value -> DefaultEngine.
	Engine security.Engine
	// Objects stores message bodies as content-addressed evidence objects.
	Objects provenance.ObjectStore
	// Base is the fallback clock: events without a stamped `ts` are ordered
	// monotonically from Base (hook stdin carries no timestamp). Zero -> a fixed
	// epoch so synthetic runs are deterministic.
	Base time.Time
}

// Summary reports what an ingest wrote.
type Summary struct {
	Agents       int `json:"agents"`
	ToolCalls    int `json:"tool_calls"`
	Refused      int `json:"refused"`
	SpawnEdges   int `json:"spawn_edges"`
	MessageEdges int `json:"message_edges"`
	Lines        int `json:"lines"`
}

// hookEvent is the tolerant projection of one hook JSON line.
type hookEvent struct {
	TS        string
	Event     string
	AgentID   string
	AgentType string
	ToolName  string
	ToolUseID string
	SessionID string
	LastMsg   string
	ToolInput map[string]any
}

type agentState struct {
	id        string
	name      string
	agentType string
	parent    string
	startedAt string
	endedAt   string
	spawned   bool
}

var (
	// Match the teammate name however the harness phrases the dispatch prompt:
	// "Your name is bob", "You are bob", "You are the bob teammate", "named bob".
	nameRe = regexp.MustCompile(`(?i)(?:your name is|you are(?: the)?|named)\s+([A-Za-z][A-Za-z0-9_-]*)`)
	// An LLM security-refusal needs BOTH a refusal/decline verb AND a sensitive
	// subject, so a benign delivery failure ("I was unable to send the message")
	// is not mistaken for a policy refusal.
	refuseVerbRe = regexp.MustCompile(`(?i)\b(refus|decline|cannot|can't|won't|will not|not able|not comfortable|against (?:policy|my)|i (?:can|will) not|not going to)\b`)
	refuseNounRe = regexp.MustCompile(`(?i)(credential|secret|exfiltrat|\.aws|metadata|169\.254|malicious|unsafe|harvest|sensitive data|private key|id_rsa|security (?:risk|concern|reason))`)
	hexRe        = regexp.MustCompile(`^[0-9a-f]{8,}$`)
)

// isSecurityRefusal reports whether a model's closing message reads as a refusal
// on security grounds (not a generic tool/delivery failure).
func isSecurityRefusal(msg string) bool {
	return refuseVerbRe.MatchString(msg) && refuseNounRe.MatchString(msg)
}

// Ingest reads a hook JSONL stream and writes the orchestration graph for RunID.
// Prior bridge-written rows for the run are cleared first so re-ingest is clean;
// it never touches record/sensor rows (only rows with agent_id / agent_* edges).
func Ingest(db *sql.DB, r io.Reader, opts Options) (Summary, error) {
	if opts.RunID == "" {
		return Summary{}, fmt.Errorf("hooksbridge: RunID is required")
	}
	if len(opts.Engine.Rules) == 0 {
		opts.Engine = security.DefaultEngine()
	}
	if opts.Base.IsZero() {
		opts.Base = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	if err := clearPrior(db, opts.RunID); err != nil {
		return Summary{}, err
	}

	agents := map[string]*agentState{}
	ensure := func(id string) *agentState {
		if id == "" {
			id = mainAgentID
		}
		a := agents[id]
		if a == nil {
			a = &agentState{id: id}
			agents[id] = a
		}
		return a
	}
	// The orchestrator root always exists so spawn edges have a parent.
	root := ensure(mainAgentID)
	root.name = "orchestrator"
	root.agentType = "main"
	root.spawned = true

	toolCallByUse := map[string]string{}
	var sum Summary
	msgSeq := 0

	evs, err := readEvents(r)
	if err != nil {
		return sum, fmt.Errorf("hooksbridge: read: %w", err)
	}
	sum.Lines = len(evs)
	// Pre-pass: build the agent roster (names + types + parent) so a SendMessage
	// that names a teammate BEFORE its SubagentStart still resolves to the right
	// agent id (the peer message precedes the recipient's spawn in the log).
	prefillRoster(evs, ensure)

	for idx, ev := range evs {
		ts := eventTime(ev.TS, opts.Base, idx)
		switch ev.Event {
		case "PreToolUse":
			switch ev.ToolName {
			case "Agent":
				// A dispatch (delegation); the teammate name is resolved in the
				// prefill pass. The dispatch itself carries no agent_id.
			case "SendMessage":
				if err := writeMessageEdge(db, opts, ev, agents, &msgSeq, ts, &sum); err != nil {
					return sum, err
				}
			default:
				if isCoordinationTool(ev.ToolName) {
					break // internal team-coordination plumbing, not an agent action
				}
				if err := writeToolCall(db, opts, ev, ensure, toolCallByUse, ts, &sum); err != nil {
					return sum, err
				}
			}
		case "PostToolUse":
			if id := toolCallByUse[ev.ToolUseID]; id != "" {
				_, _ = db.Exec(`UPDATE tool_calls SET ended_at = ? WHERE id = ?`, ts, id)
			}
		case "SubagentStart":
			a := ensure(ev.AgentID)
			if a.startedAt == "" {
				a.startedAt = ts
			}
			a.endedAt = "" // reopen
			if !a.spawned {
				if err := writeEdge(db, opts.RunID, "agent/"+a.parent, "agent/"+a.id, EdgeAgentSpawn, ts); err != nil {
					return sum, err
				}
				a.spawned = true
				sum.SpawnEdges++
			}
		case "SubagentStop":
			a := ensure(ev.AgentID)
			a.endedAt = ts
			if ev.LastMsg != "" && isSecurityRefusal(ev.LastMsg) {
				if err := writeRefusal(db, opts.RunID, ev.AgentID, ev.LastMsg, ts, &sum); err != nil {
					return sum, err
				}
			}
		case "Stop", "StopFailure":
			// A refusal can also land on the MAIN agent's Stop -- the model
			// declines the task outright instead of spawning a teammate that then
			// refuses. Surface it as a refused node too (attributed to main), so a
			// visible-intent refusal is captured whichever agent said it.
			agentID := ev.AgentID
			if agentID == "" {
				agentID = mainAgentID
			}
			ensure(agentID)
			if ev.LastMsg != "" && isSecurityRefusal(ev.LastMsg) {
				if err := writeRefusal(db, opts.RunID, agentID, ev.LastMsg, ts, &sum); err != nil {
					return sum, err
				}
			}
		}
	}

	// Persist agent rows (node labels + lifecycle).
	for _, a := range agents {
		if _, err := db.Exec(`INSERT OR REPLACE INTO agents
			(id, run_id, name, agent_type, parent_agent_id, binding_source, created_at, started_at, ended_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			a.id, opts.RunID, a.name, a.agentType, a.parent, bindingSource,
			eventTime("", opts.Base, 0), a.startedAt, a.endedAt); err != nil {
			return sum, fmt.Errorf("hooksbridge: write agent %s: %w", a.id, err)
		}
		sum.Agents++
	}
	return sum, nil
}

// writeToolCall records an agent's proposed tool call, pre-flighted through the
// gate: a deny-class verdict makes it a status=denied refused node.
func writeToolCall(db *sql.DB, opts Options, ev hookEvent, ensure func(string) *agentState, byUse map[string]string, ts string, sum *Summary) error {
	agentID := ev.AgentID
	if agentID == "" {
		agentID = mainAgentID
	}
	ensure(agentID)
	command, sev := proposedEvent(ev.ToolName, ev.ToolInput)
	d := opts.Engine.Evaluate(sev)
	status := "asserted"
	policy := d.Decision
	denied := d.Mode == "enforce" && (d.Decision == "deny" || d.Decision == "kill" || d.Decision == "quarantine")
	if denied {
		status = "denied"
		sum.Refused++
	}
	id := ev.ToolUseID
	if id == "" {
		id = ids.New("tool")
	}
	if _, err := db.Exec(`INSERT OR REPLACE INTO tool_calls
		(id, run_id, agent_id, command, status, policy_decision, created_at, started_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, opts.RunID, agentID, command, status, policy, ts, ts); err != nil {
		return fmt.Errorf("hooksbridge: write tool_call: %w", err)
	}
	byUse[ev.ToolUseID] = id
	sum.ToolCalls++
	return writeEdge(db, opts.RunID, "agent/"+agentID, id, EdgeAgentToolCall, ts)
}

// writeMessageEdge records a peer SendMessage: the body is objectified as
// content-addressed evidence, and the directed edge routes sender -> body ->
// recipient so the lateral-injection payload is inspectable and verifiable.
func writeMessageEdge(db *sql.DB, opts Options, ev hookEvent, agents map[string]*agentState, seq *int, ts string, sum *Summary) error {
	sender := ev.AgentID
	if sender == "" {
		sender = mainAgentID
	}
	recipient := strArg(ev.ToolInput, "recipient", "to")
	recipient = normalizeRecipient(recipient, agents)
	body := strArg(ev.ToolInput, "message", "content")
	*seq++
	res, err := opts.Objects.PutExternalObject(provenance.ExternalObjectInput{
		Type:     "artifact",
		SourceID: fmt.Sprintf("agent_message/%s->%s/%d", sender, recipient, *seq),
		RunID:    opts.RunID,
		Payload: map[string]any{
			"kind":    "agent_message",
			"from":    sender,
			"to":      recipient,
			"body":    body,
			"content": body, // dashboard preview key
		},
	})
	if err != nil {
		return fmt.Errorf("hooksbridge: objectify message: %w", err)
	}
	if err := writeEdge(db, opts.RunID, "agent/"+sender, res.Hash, EdgeAgentMessage, ts); err != nil {
		return err
	}
	if err := writeEdge(db, opts.RunID, res.Hash, "agent/"+recipient, EdgeAgentMessage, ts); err != nil {
		return err
	}
	sum.MessageEdges++
	return nil
}

// writeRefusal records an LLM-asserted refusal (the model declined in text, no
// tool call). Weaker than a gate deny -- labeled refused_by_model, app-asserted.
func writeRefusal(db *sql.DB, runID, agentID, msg, ts string, sum *Summary) error {
	if agentID == "" {
		agentID = mainAgentID
	}
	id := ids.New("refusal")
	cmd := "[llm refusal] " + truncate(oneLine(msg), 200)
	if _, err := db.Exec(`INSERT INTO tool_calls
		(id, run_id, agent_id, command, status, policy_decision, created_at, started_at)
		VALUES (?, ?, ?, ?, 'refused', 'refused_by_model', ?, ?)`,
		id, runID, agentID, cmd, ts, ts); err != nil {
		return fmt.Errorf("hooksbridge: write refusal: %w", err)
	}
	sum.Refused++
	sum.ToolCalls++
	return writeEdge(db, runID, "agent/"+agentID, id, EdgeAgentToolCall, ts)
}

// CorrelateSyscalls attributes kernel syscall events to the acting sub-agent.
// In-process agents share ONE cgroup, so the sensor cannot split them; the join
// is COMMAND-MATCH -- the sensor's execve command against an agent tool_call's
// command -- then propagation to the high-risk events (secret_path, metadata_ip,
// ...) that ran in the SAME pid. This turns "some process in the run read the
// secret" into "bob's install tool_call read the secret", completing the blame
// chain agent -> tool_call -> syscall. Returns the number of links written.
func CorrelateSyscalls(db *sql.DB, runID string) (int, error) {
	if _, err := db.Exec(`DELETE FROM graph_edges WHERE run_id = ? AND edge_type = ?`, runID, EdgeAgentSyscall); err != nil {
		return 0, err
	}
	type toolCall struct{ id, cmd string }
	var calls []toolCall
	rows, err := db.Query(`SELECT id, command FROM tool_calls WHERE run_id = ? AND agent_id != '' AND command != ''`, runID)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var t toolCall
		if err := rows.Scan(&t.id, &t.cmd); err != nil {
			rows.Close()
			return 0, err
		}
		calls = append(calls, t)
	}
	rows.Close()
	if len(calls) == 0 {
		return 0, nil
	}

	// First pass: match each execve to a tool_call by command, recording which
	// pid the tool_call owns.
	pidToCall := map[int64]string{}
	evRows, err := db.Query(`SELECT id, event_type, COALESCE(pid,0), payload FROM events WHERE run_id = ?`, runID)
	if err != nil {
		return 0, err
	}
	type evt struct {
		id  string
		typ string
		pid int64
	}
	var events []evt
	for evRows.Next() {
		var id, typ, payload string
		var pid int64
		if err := evRows.Scan(&id, &typ, &pid, &payload); err != nil {
			evRows.Close()
			return 0, err
		}
		events = append(events, evt{id, typ, pid})
		if typ == "execve" && pid > 0 {
			cmd := payloadCommand(payload)
			if cmd == "" {
				continue
			}
			for _, c := range calls {
				if commandsMatch(cmd, c.cmd) {
					pidToCall[pid] = c.id
					break
				}
			}
		}
	}
	evRows.Close()
	if len(pidToCall) == 0 {
		return 0, nil
	}

	// Second pass: link every attributable event (the execve and the high-risk
	// syscalls sharing its pid) to the owning tool_call.
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	n := 0
	for _, e := range events {
		callID, ok := pidToCall[e.pid]
		if !ok || !attributableEvent(e.typ) {
			continue
		}
		if err := writeEdge(db, runID, callID, "runtime_event/"+e.id, EdgeAgentSyscall, ts); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// attributableEvent is the set of kernel events worth pinning to an agent: the
// matched execve (the join anchor) plus the security-relevant syscalls that carry
// the blame. Benign file_open/file_write (a process loads hundreds of library
// files) are deliberately excluded so the attribution edges stay the exfil story,
// not noise.
func attributableEvent(t string) bool {
	switch t {
	case "execve", "secret_path", "metadata_ip", "private_cidr", "network_connect":
		return true
	default:
		return false
	}
}

// commandsMatch reports whether a sensor execve command and a tool_call command
// refer to the same invocation. The sensor truncates argv (31 chars/arg), so the
// match is substring-either-way on whitespace-normalized commands, requiring at
// least two shared leading tokens to avoid trivial collisions.
func commandsMatch(a, b string) bool {
	na, nb := normCmd(a), normCmd(b)
	if na == "" || nb == "" {
		return false
	}
	short, long := na, nb
	if len(short) > len(long) {
		short, long = long, short
	}
	if len(strings.Fields(short)) < 2 {
		return false
	}
	return strings.Contains(long, short)
}

func normCmd(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), " ")) }

func payloadCommand(payload string) string {
	var m map[string]any
	if json.Unmarshal([]byte(payload), &m) != nil {
		return ""
	}
	// The stored event payload is an envelope: {rollout_id, attempt_id,
	// payload:{raw:{command,argv,comm}, correlation:{...}}}. Descend through each
	// layer, preferring the full command over the bare comm.
	inner := mapAt(m, "payload")
	for _, layer := range []map[string]any{mapAt(inner, "raw"), inner, mapAt(m, "raw"), m} {
		if c := strArg(layer, "command", "cmdline"); c != "" {
			return c
		}
	}
	for _, layer := range []map[string]any{mapAt(inner, "raw"), mapAt(m, "raw")} {
		if c := strArg(layer, "comm"); c != "" {
			return c
		}
	}
	return ""
}

func mapAt(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	sub, _ := m[key].(map[string]any)
	return sub
}

func writeEdge(db *sql.DB, runID, from, to, edgeType, ts string) error {
	if from == "" || to == "" {
		return nil
	}
	_, err := db.Exec(`INSERT INTO graph_edges
		(id, run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at)
		VALUES (?, ?, '', ?, ?, ?, 'hooks', ?)`,
		ids.New("edge"), runID, from, to, edgeType, ts)
	if err != nil {
		return fmt.Errorf("hooksbridge: write edge %s: %w", edgeType, err)
	}
	return nil
}

// clearPrior removes only bridge-written rows for the run (agent_* edges, agents,
// and tool_calls that carry an agent_id) so re-ingest is idempotent and never
// disturbs recorder/sensor evidence.
func clearPrior(db *sql.DB, runID string) error {
	stmts := []struct {
		q string
		a []any
	}{
		// Includes agent_syscall so a re-ingest with --correlate=false cannot leave
		// stale attribution edges (CorrelateSyscalls also clears them when it runs).
		{`DELETE FROM graph_edges WHERE run_id = ? AND edge_type IN (?, ?, ?, ?)`, []any{runID, EdgeAgentSpawn, EdgeAgentMessage, EdgeAgentToolCall, EdgeAgentSyscall}},
		{`DELETE FROM tool_calls WHERE run_id = ? AND agent_id != ''`, []any{runID}},
		{`DELETE FROM agents WHERE run_id = ?`, []any{runID}},
	}
	for _, s := range stmts {
		if _, err := db.Exec(s.q, s.a...); err != nil {
			return fmt.Errorf("hooksbridge: clear prior: %w", err)
		}
	}
	return nil
}

// proposedEvent maps a hook tool_input to the policy Event shape the gate scores,
// plus a human display command. Bash argv carries the intent (metadata-IP,
// install...); Read/Write carry a path (secret_path).
func proposedEvent(toolName string, ti map[string]any) (string, security.Event) {
	switch toolName {
	case "Bash":
		cmd := strArg(ti, "command")
		return cmd, security.Event{Source: "ai_gate", EventType: "execve", Args: strings.Fields(cmd)}
	case "Read":
		p := strArg(ti, "file_path", "path")
		return "read " + filepath.Base(p), security.Event{Source: "ai_gate", EventType: "file_open", Path: p}
	case "Write", "Edit":
		p := strArg(ti, "file_path", "path")
		return "write " + filepath.Base(p), security.Event{Source: "ai_gate", EventType: "file_write", Path: p}
	default:
		return toolName, security.Event{Source: "ai_gate", EventType: strings.ToLower(toolName)}
	}
}

func normalizeRecipient(r string, agents map[string]*agentState) string {
	if r == "" {
		return "unknown"
	}
	// name -> its agent_id
	for id, a := range agents {
		if a.name != "" && strings.EqualFold(a.name, r) {
			return id
		}
	}
	// a raw agent-id string (possibly longer than the 8-char short id) -> match by prefix
	if hexRe.MatchString(r) {
		for id := range agents {
			if strings.HasPrefix(r, id) || strings.HasPrefix(id, r) {
				return id
			}
		}
	}
	return r
}

func parseName(ti map[string]any) string {
	// The Agent tool carries the sub-agent's name explicitly -- prefer it over
	// regex-sniffing the prompt (which only catches "you are <name>" phrasings and
	// missed agents whose dispatch prompt worded the role differently).
	if n := strArg(ti, "name"); n != "" {
		return strings.ToLower(n)
	}
	if m := nameRe.FindStringSubmatch(strArg(ti, "prompt", "description")); len(m) == 2 {
		return strings.ToLower(m[1])
	}
	return ""
}

// readEvents buffers the whole (small) hook log so the bridge can make two
// passes: a roster pre-pass then the graph-writing pass.
func readEvents(r io.Reader) ([]hookEvent, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	var out []hookEvent
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue // tolerate non-JSON noise
		}
		out = append(out, parseEvent(raw))
	}
	return out, sc.Err()
}

// prefillRoster resolves each sub-agent's name (from the preceding Agent-dispatch
// prompt, matched by FIFO proximity) and parent before any edges are written, so
// name-based SendMessage recipients resolve even when the message precedes the
// recipient's spawn.
func prefillRoster(evs []hookEvent, ensure func(string) *agentState) {
	var pending []string
	for _, ev := range evs {
		switch ev.Event {
		case "PreToolUse":
			if ev.ToolName == "Agent" {
				if n := parseName(ev.ToolInput); n != "" {
					pending = append(pending, n)
				}
			}
		case "SubagentStart":
			a := ensure(ev.AgentID)
			if ev.AgentType != "" {
				a.agentType = ev.AgentType
			}
			if a.parent == "" {
				a.parent = mainAgentID
			}
			if a.name == "" && len(pending) > 0 {
				a.name = pending[0]
				pending = pending[1:]
			}
		}
	}
}

func parseEvent(raw map[string]any) hookEvent {
	ti, _ := raw["tool_input"].(map[string]any)
	return hookEvent{
		TS:        firstStr(raw, "ts", "_ts", "timestamp"),
		Event:     firstStr(raw, "hook_event_name", "hookEventName", "event"),
		AgentID:   firstStr(raw, "agent_id", "agentId"),
		AgentType: firstStr(raw, "agent_type", "agentType"),
		ToolName:  firstStr(raw, "tool_name", "toolName"),
		ToolUseID: firstStr(raw, "tool_use_id", "toolUseId"),
		SessionID: firstStr(raw, "session_id"),
		LastMsg:   firstStr(raw, "last_assistant_message"),
		ToolInput: ti,
	}
}

// eventTime returns a stamped ts if the wrapper injected one, else a synthetic
// monotonic time from base (hook stdin has no timestamp).
func eventTime(stamped string, base time.Time, idx int) string {
	if stamped != "" {
		if t, ok := parseStamp(stamped); ok {
			return t.UTC().Format(time.RFC3339Nano)
		}
	}
	return base.Add(time.Duration(idx) * time.Millisecond).UTC().Format(time.RFC3339Nano)
}

func parseStamp(s string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		sec := int64(f)
		nsec := int64((f - float64(sec)) * 1e9)
		return time.Unix(sec, nsec), true
	}
	return time.Time{}, false
}

func firstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func strArg(m map[string]any, keys ...string) string {
	if m == nil {
		return ""
	}
	for _, k := range keys {
		if s, ok := m[k].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// isCoordinationTool reports whether a tool is internal team-coordination
// plumbing (reading a teammate's output, task bookkeeping) rather than a real
// agent action worth a node in the blame graph.
func isCoordinationTool(name string) bool {
	switch name {
	case "TaskOutput", "TaskCreate", "TaskUpdate", "TaskGet", "TaskList", "TaskStop", "TeammateIdle":
		return true
	default:
		return false
	}
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
