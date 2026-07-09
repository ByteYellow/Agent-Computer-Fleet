package hooksbridge

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

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
	var out []normalizedEvent
	callTool := map[string]string{} // toolCallId -> tool name (to label the result)
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
			out = append(out, normalizedEvent{Event: "PreToolUse", ToolName: name, ToolInput: args, ToolUseID: id, TS: ts})
		case "tool.result":
			id := str(ev["toolCallId"])
			out = append(out, normalizedEvent{Event: "PostToolUse", ToolName: callTool[id], ToolUseID: id, TS: ts})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return encodeEvents(out)
}

// adaptCodexRollout maps OpenAI Codex CLI's session rollout-*.jsonl onto
// normalized hook events. Codex records response items; a function_call item is
// the agent's tool call (name + arguments), its output the result.
func adaptCodexRollout(r io.Reader) (io.Reader, error) {
	var out []normalizedEvent
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
			ti := codexArgs(payload)
			out = append(out, normalizedEvent{Event: "PreToolUse", ToolName: name, ToolInput: ti, ToolUseID: firstStr(payload, "call_id", "id"), TS: ts})
		case "function_call_output", "local_shell_call_output", "custom_tool_call_output":
			out = append(out, normalizedEvent{Event: "PostToolUse", ToolUseID: firstStr(payload, "call_id", "id"), TS: ts})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return encodeEvents(out)
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
