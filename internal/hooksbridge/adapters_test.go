package hooksbridge

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func decodeAdapted(t *testing.T, r io.Reader) []normalizedEvent {
	t.Helper()
	var out []normalizedEvent
	dec := json.NewDecoder(r)
	for dec.More() {
		var e normalizedEvent
		if err := dec.Decode(&e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func TestAdaptKimiWireMapsToolCalls(t *testing.T) {
	// Kimi wraps its events in context.append_loop_event; tool.call carries the
	// same tool NAMES as Claude Code, so command-match works unchanged.
	wire := strings.Join([]string{
		`{"type":"metadata","protocol_version":"1.4"}`,
		`{"type":"turn.prompt","input":[{"type":"text","text":"do it"}]}`,
		`{"type":"context.append_loop_event","event":{"type":"tool.call","toolCallId":"c1","name":"Bash","args":{"command":"python3 setup.py install"}},"time":1783581116451}`,
		`{"type":"context.append_loop_event","event":{"type":"tool.result","toolCallId":"c1","result":{"output":"ok"}},"time":1783581116999}`,
		`{"type":"context.append_loop_event","event":{"type":"tool.call","toolCallId":"c2","name":"Read","args":{"path":"/etc/hosts"}}}`,
	}, "\n")

	r, err := AdaptHarness("kimi", strings.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	evs := decodeAdapted(t, r)
	if len(evs) != 3 {
		t.Fatalf("got %d events, want 3 (2 PreToolUse + 1 PostToolUse): %+v", len(evs), evs)
	}
	if evs[0].Event != "PreToolUse" || evs[0].ToolName != "Bash" || evs[0].ToolInput["command"] != "python3 setup.py install" {
		t.Fatalf("first event wrong: %+v", evs[0])
	}
	if evs[1].Event != "PostToolUse" || evs[1].ToolUseID != "c1" || evs[1].ToolName != "Bash" {
		t.Fatalf("result not labeled with its call's tool: %+v", evs[1])
	}
	if evs[2].ToolName != "Read" || evs[2].ToolInput["path"] != "/etc/hosts" {
		t.Fatalf("read call wrong: %+v", evs[2])
	}
}

func TestAdaptCodexRolloutMapsFunctionCalls(t *testing.T) {
	// Codex records response items; a function_call / local_shell_call is a tool
	// call whose arguments are a JSON string (function) or an argv (shell).
	rollout := strings.Join([]string{
		`{"timestamp":"2026-07-09T05:49:40Z","type":"session_meta","payload":{"session_id":"s1"}}`,
		`{"timestamp":"2026-07-09T05:49:41Z","type":"response_item","payload":{"type":"function_call","name":"read_file","arguments":"{\"path\":\"/etc/hosts\"}","call_id":"f1"}}`,
		`{"timestamp":"2026-07-09T05:49:42Z","type":"response_item","payload":{"type":"local_shell_call","command":["python3","setup.py","install"],"call_id":"s2"}}`,
		`{"timestamp":"2026-07-09T05:49:43Z","type":"response_item","payload":{"type":"function_call_output","call_id":"f1"}}`,
	}, "\n")

	r, err := AdaptHarness("codex", strings.NewReader(rollout))
	if err != nil {
		t.Fatal(err)
	}
	evs := decodeAdapted(t, r)
	if len(evs) != 3 {
		t.Fatalf("got %d events, want 3: %+v", len(evs), evs)
	}
	if evs[0].ToolName != "read_file" || evs[0].ToolInput["path"] != "/etc/hosts" {
		t.Fatalf("function_call args not decoded: %+v", evs[0])
	}
	if evs[1].ToolName != "Bash" || evs[1].ToolInput["command"] != "python3 setup.py install" {
		t.Fatalf("shell argv not joined to a command: %+v", evs[1])
	}
	if evs[2].Event != "PostToolUse" || evs[2].ToolUseID != "f1" {
		t.Fatalf("output not mapped: %+v", evs[2])
	}
}

func TestAdaptKimiSessionCapturesDelegation(t *testing.T) {
	// A Kimi multi-agent session: main dispatches an `Agent` (subagent_type=coder),
	// and agents/agent-0/ is that sub-agent doing the work. The adapter must yield
	// the same delegation shape Claude Code does: an Agent dispatch + a SubagentStart.
	dir := t.TempDir()
	main := filepath.Join(dir, "agents", "main")
	sub := filepath.Join(dir, "agents", "agent-0")
	if err := os.MkdirAll(main, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	mainWire := `{"type":"context.append_loop_event","event":{"type":"tool.call","toolCallId":"a1","name":"Agent","args":{"subagent_type":"coder","description":"read calc.py"}}}`
	subWire := strings.Join([]string{
		`{"type":"config.update","profileName":"coder"}`,
		`{"type":"context.append_loop_event","event":{"type":"tool.call","toolCallId":"r1","name":"Read","args":{"path":"/tmp/calc.py"}}}`,
	}, "\n")
	if err := os.WriteFile(filepath.Join(main, "wire.jsonl"), []byte(mainWire), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "wire.jsonl"), []byte(subWire), 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := AdaptKimiSession(dir)
	if err != nil {
		t.Fatal(err)
	}
	evs := decodeAdapted(t, r)
	var dispatch, substart, subread bool
	for _, e := range evs {
		if e.Event == "PreToolUse" && e.ToolName == "Agent" && e.ToolInput["name"] == "coder" {
			dispatch = true
		}
		if e.Event == "SubagentStart" && e.AgentID == "agent-0" && e.AgentType == "coder" {
			substart = true
		}
		if e.Event == "PreToolUse" && e.ToolName == "Read" && e.AgentID == "agent-0" {
			subread = true
		}
	}
	if !dispatch || !substart || !subread {
		t.Fatalf("delegation not captured (dispatch=%v substart=%v subread=%v): %+v", dispatch, substart, subread, evs)
	}
}

func TestAdaptHarnessUnknownRejected(t *testing.T) {
	if _, err := AdaptHarness("langchain", strings.NewReader("")); err == nil {
		t.Fatal("unknown harness should error")
	}
}
