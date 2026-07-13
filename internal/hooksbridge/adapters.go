package hooksbridge

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// BridgeTranscript opens a harness's session record at path (a Kimi session
// DIRECTORY, else a transcript file) and returns a reader of normalized hook
// events ready for Ingest. It is the one entry point launch and `hooks bridge`
// share, so both handle Kimi's per-agent directory the same way.
func BridgeTranscript(harness, path string) (io.Reader, error) {
	if harness == "kimi" {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			return AdaptKimiSession(path)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Buffer the whole file before returning: the claude adapter is a passthrough
	// that hands the reader back unread, so a reader over `f` would be consumed by
	// the caller AFTER this defer closes it ("file already closed"). A bytes.Reader
	// is safe after close, and the codex/kimi adapters read eagerly anyway.
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return AdaptHarness(harness, bytes.NewReader(data))
}

// AdaptHarness wraps a harness-specific session transcript in a reader of the
// normalized hook-JSONL events Ingest consumes, so a non-Claude-Code harness is
// captured by translating its OWN session record — no per-harness bespoke bridge.
// harness "" / "claude" is a passthrough (the events are already normalized).
func AdaptHarness(harness string, r io.Reader) (io.Reader, error) {
	switch harness {
	case "", "claude":
		return r, nil
	case "kimi":
		return adaptKimiWire(r)
	case "codex":
		return adaptCodexRollout(r)
	default:
		return nil, fmt.Errorf("hooksbridge: unknown harness %q (want claude|kimi|codex)", harness)
	}
}

// normalizedEvent is one hook-JSONL line in the schema parseEvent reads.
type normalizedEvent struct {
	Event     string         `json:"hook_event_name"`
	ToolName  string         `json:"tool_name,omitempty"`
	ToolInput map[string]any `json:"tool_input,omitempty"`
	ToolUseID string         `json:"tool_use_id,omitempty"`
	AgentID   string         `json:"agent_id,omitempty"`
	AgentType string         `json:"agent_type,omitempty"`
	TS        string         `json:"timestamp,omitempty"`
	LastMsg   string         `json:"last_assistant_message,omitempty"`
}

func encodeEvents(evs []normalizedEvent) (io.Reader, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range evs {
		if err := enc.Encode(e); err != nil {
			return nil, err
		}
	}
	return &buf, nil
}

// adaptKimiWire maps Kimi Code CLI's per-agent wire.jsonl (an internal event
// stream) onto normalized hook events. Kimi's tool.call/tool.result carry the
// same tool NAMES as Claude Code (Read/Write/Bash/Edit), so command-match to
// kernel syscalls works unchanged. tool.call -> PreToolUse, tool.result ->
// PostToolUse.
func adaptKimiWire(r io.Reader) (io.Reader, error) {
	evs, err := kimiWireEvents(r, "")
	if err != nil {
		return nil, err
	}
	return encodeEvents(evs)
}

// AdaptKimiSession walks a Kimi session directory (…/session_<id>/) and its
// per-agent wire.jsonl files into one normalized hook stream. The main agent's
// `Agent` tool call is the delegation dispatch (Kimi reuses Claude Code's tool
// name), and each agents/<sub>/ becomes a SubagentStart + its own tool calls —
// so the existing bridge draws the same delegation graph as Claude Code.
func AdaptKimiSession(sessionDir string) (io.Reader, error) {
	agentsDir := filepath.Join(sessionDir, "agents")
	entries, err := os.ReadDir(agentsDir)
	if err != nil {
		return nil, err
	}
	var subs []string
	hasMain := false
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if e.Name() == "main" {
			hasMain = true
		} else {
			subs = append(subs, e.Name())
		}
	}
	sort.Strings(subs)
	var out []normalizedEvent
	appendAgent := func(id string) error {
		f, err := os.Open(filepath.Join(agentsDir, id, "wire.jsonl"))
		if err != nil {
			return err
		}
		defer f.Close()
		evs, err := kimiWireEvents(f, id)
		if err != nil {
			return err
		}
		out = append(out, evs...)
		return nil
	}
	if hasMain {
		if err := appendAgent("main"); err != nil {
			return nil, err
		}
	}
	for _, s := range subs {
		f, err := os.Open(filepath.Join(agentsDir, s, "wire.jsonl"))
		if err != nil {
			return nil, err
		}
		evs, err := kimiWireEvents(f, s)
		f.Close()
		if err != nil {
			return nil, err
		}
		// Bracket the sub-agent's events with a Start/Stop stamped from its own
		// timeline so the merged, time-sorted stream keeps them in causal order.
		start, stop := "", ""
		if len(evs) > 0 {
			start, stop = evs[0].TS, evs[len(evs)-1].TS
		}
		out = append(out, normalizedEvent{Event: "SubagentStart", AgentID: s, AgentType: kimiAgentType(filepath.Join(agentsDir, s, "wire.jsonl")), TS: start})
		out = append(out, evs...)
		out = append(out, normalizedEvent{Event: "SubagentStop", AgentID: s, TS: stop})
	}
	// Merge every agent's events into one wall-clock timeline (stable, so events
	// sharing a timestamp keep their per-agent emission order).
	sort.SliceStable(out, func(i, j int) bool { return out[i].TS < out[j].TS })
	return encodeEvents(out)
}

// kimiWireEvents parses one wire.jsonl into normalized events tagged with
// agentID (empty = main). A tool.call named "Agent" is emitted as a delegation
// dispatch (PreToolUse/Agent) with a resolvable teammate name; other tool.calls
// map to PreToolUse and their results to PostToolUse.
func kimiWireEvents(r io.Reader, agentID string) ([]normalizedEvent, error) {
	var out []normalizedEvent
	callTool := map[string]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		var top map[string]any
		if json.Unmarshal(sc.Bytes(), &top) != nil {
			continue
		}
		ev := top
		if t, _ := top["type"].(string); t == "context.append_loop_event" {
			if inner, ok := top["event"].(map[string]any); ok {
				ev = inner
			}
		}
		ts := stampFromUnixMillis(top["time"], top["ts"])
		switch ev["type"] {
		case "tool.call":
			id := str(ev["toolCallId"])
			name := str(ev["name"])
			callTool[id] = name
			args, _ := ev["args"].(map[string]any)
			if name == "Agent" {
				// Delegation dispatch: give the roster a teammate name to bind the
				// sub-agent to (subagent_type, else the task description).
				ti := map[string]any{"name": firstStr(args, "subagent_type", "description")}
				out = append(out, normalizedEvent{Event: "PreToolUse", ToolName: "Agent", ToolInput: ti, ToolUseID: id, AgentID: agentID, TS: ts})
				break
			}
			out = append(out, normalizedEvent{Event: "PreToolUse", ToolName: name, ToolInput: args, ToolUseID: id, AgentID: agentID, TS: ts})
		case "tool.result":
			id := str(ev["toolCallId"])
			out = append(out, normalizedEvent{Event: "PostToolUse", ToolName: callTool[id], ToolUseID: id, AgentID: agentID, TS: ts})
		}
	}
	return out, sc.Err()
}

// kimiAgentType reads a sub-agent's profile (its type) from its first
// config.update event.
func kimiAgentType(wirePath string) string {
	f, err := os.Open(wirePath)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		var o map[string]any
		if json.Unmarshal(sc.Bytes(), &o) != nil {
			continue
		}
		if o["type"] == "config.update" {
			if p := str(o["profileName"]); p != "" && p != "agent" {
				return p
			}
		}
	}
	return ""
}

// adaptCodexRollout maps OpenAI Codex CLI's session rollout-*.jsonl onto
// normalized hook events. Codex records response items; a function_call item is
// the agent's tool call (name + arguments), its output the result.
func adaptCodexRollout(r io.Reader) (io.Reader, error) {
	var out []normalizedEvent
	spawnSub := map[string]string{} // spawn_agent call_id -> synthetic sub-agent id
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		var top map[string]any
		if json.Unmarshal(sc.Bytes(), &top) != nil {
			continue
		}
		ts := str(top["timestamp"])
		payload, _ := top["payload"].(map[string]any)
		if payload == nil {
			continue
		}
		// Codex wraps items as {type:"response_item", payload:{type:"function_call"|"local_shell_call"|..., name, arguments, call_id}}.
		itemType := firstStr(payload, "type")
		switch itemType {
		case "function_call", "local_shell_call", "custom_tool_call":
			name := firstStr(payload, "name")
			if name == "" && itemType == "local_shell_call" {
				name = "Bash"
			}
			callID := firstStr(payload, "call_id", "id")
			ti := codexArgs(payload)
			// Codex multi-agent: spawn_agent is a delegation dispatch. The parent
			// rollout records that a sub-agent (role=agent_type) was created with an
			// initial task; that sub-agent's OWN tool calls live in a separate
			// per-thread trace, not this file, so they are out of scope here. Emit
			// the dispatch as an Agent call plus a SubagentStart/Stop so the bridge
			// draws the main->sub spawn edge and a named teammate node, exactly like
			// Claude Code / Kimi delegation.
			if isCodexSpawnAgent(name) {
				subID := "codex-sub-" + callID
				spawnSub[callID] = subID
				out = append(out,
					normalizedEvent{Event: "PreToolUse", ToolName: "Agent", ToolInput: map[string]any{"name": codexSpawnLabel(ti)}, ToolUseID: callID, TS: ts},
					normalizedEvent{Event: "SubagentStart", AgentID: subID, AgentType: firstStr(ti, "agent_type", "new_agent_role", "agent_role"), TS: ts},
				)
				break
			}
			// Codex's shell tool (exec_command / local_shell) is where syscalls
			// come from; normalize it to Bash with a `command` so command-match to
			// the kernel works, exactly like Claude Code / Kimi.
			if cmd := firstStr(ti, "command", "cmd"); cmd != "" && isCodexShellTool(name) {
				name, ti = "Bash", map[string]any{"command": cmd}
			}
			out = append(out, normalizedEvent{Event: "PreToolUse", ToolName: name, ToolInput: ti, ToolUseID: callID, TS: ts})
		case "function_call_output", "local_shell_call_output", "custom_tool_call_output":
			callID := firstStr(payload, "call_id", "id")
			if subID := spawnSub[callID]; subID != "" {
				out = append(out, normalizedEvent{Event: "SubagentStop", AgentID: subID, TS: ts})
				break
			}
			out = append(out, normalizedEvent{Event: "PostToolUse", ToolUseID: callID, TS: ts})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return encodeEvents(out)
}

// isCodexSpawnAgent reports whether a codex tool name is the multi-agent spawn
// dispatch, bare or namespaced (e.g. "multi_agent_v1.spawn_agent").
func isCodexSpawnAgent(name string) bool {
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	return name == "spawn_agent"
}

// codexSpawnLabel picks a teammate label for a spawn_agent dispatch: the agent
// role, else the first line of the initial task message, else "agent".
func codexSpawnLabel(ti map[string]any) string {
	if r := firstStr(ti, "agent_type", "new_agent_role", "agent_role"); r != "" {
		return r
	}
	if m := firstStr(ti, "message", "prompt", "instruction"); m != "" {
		if i := strings.IndexByte(m, '\n'); i >= 0 {
			m = m[:i]
		}
		if m = strings.TrimSpace(m); m != "" {
			if len(m) > 60 {
				m = m[:60]
			}
			return m
		}
	}
	return "agent"
}

// isCodexShellTool reports whether a codex tool name runs a shell command (so it
// should be normalized to Bash for command-match).
func isCodexShellTool(name string) bool {
	switch name {
	case "exec_command", "local_shell", "shell", "bash", "run", "container.exec":
		return true
	}
	return name == "" // an unnamed local_shell_call
}

// codexArgs turns a codex tool item into a tool_input map, decoding the JSON
// `arguments` string when present (function_call) or lifting a shell command.
func codexArgs(payload map[string]any) map[string]any {
	if raw := firstStr(payload, "arguments"); raw != "" {
		var m map[string]any
		if json.Unmarshal([]byte(raw), &m) == nil {
			return m
		}
	}
	if cmd, ok := payload["command"]; ok {
		return map[string]any{"command": commandString(cmd)}
	}
	return nil
}

func commandString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		parts := make([]string, 0, len(t))
		for _, p := range t {
			parts = append(parts, str(p))
		}
		return joinSpace(parts)
	}
	return ""
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func joinSpace(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += " "
		}
		out += p
	}
	return out
}

// stampFromUnixMillis renders the first present unix-millis timestamp as RFC3339.
func stampFromUnixMillis(vals ...any) string {
	for _, v := range vals {
		if f, ok := v.(float64); ok && f > 0 {
			return time.UnixMilli(int64(f)).UTC().Format(time.RFC3339Nano)
		}
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}
