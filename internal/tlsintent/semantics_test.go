package tlsintent

import (
	"reflect"
	"testing"
)

func TestParseSemanticsAnthropic(t *testing.T) {
	req := `{"model":"claude-opus-4-8","system":"you are helpful","messages":[
		{"role":"user","content":"hi"},{"role":"assistant","content":"hello"}],
		"tools":[{"name":"bash"},{"name":"read_file"}]}`
	s := ParseSemantics(Request, []byte(req))
	if s.Model != "claude-opus-4-8" || s.MessageCount != 2 || !s.HasSystem {
		t.Errorf("request semantics wrong: %+v", s)
	}
	if !reflect.DeepEqual(s.ToolsOffered, []string{"bash", "read_file"}) {
		t.Errorf("tools offered = %v", s.ToolsOffered)
	}

	resp := `{"model":"claude-opus-4-8","stop_reason":"tool_use","content":[
		{"type":"text","text":"let me run that"},
		{"type":"tool_use","name":"bash","input":{"command":"cat creds"}}]}`
	r := ParseSemantics(Response, []byte(resp))
	if r.StopReason != "tool_use" {
		t.Errorf("stop_reason = %q", r.StopReason)
	}
	if !reflect.DeepEqual(r.ToolCalls, []string{"bash"}) {
		t.Errorf("tool_calls = %v, want [bash]", r.ToolCalls)
	}
	if !reflect.DeepEqual(r.ToolCommands, []string{"cat creds"}) {
		t.Errorf("tool_commands = %v, want [cat creds]", r.ToolCommands)
	}
}

func TestParseSemanticsOpenAI(t *testing.T) {
	req := `{"model":"gpt-x","messages":[{"role":"user","content":"hi"}],
		"tools":[{"type":"function","function":{"name":"run_shell"}}]}`
	s := ParseSemantics(Request, []byte(req))
	if s.Model != "gpt-x" || s.MessageCount != 1 {
		t.Errorf("req: %+v", s)
	}
	if !reflect.DeepEqual(s.ToolsOffered, []string{"run_shell"}) {
		t.Errorf("tools = %v", s.ToolsOffered)
	}

	resp := `{"model":"gpt-x","choices":[{"finish_reason":"tool_calls","message":{"tool_calls":[
		{"function":{"name":"run_shell"}}]}}]}`
	r := ParseSemantics(Response, []byte(resp))
	if r.StopReason != "tool_calls" {
		t.Errorf("stop = %q", r.StopReason)
	}
	if !reflect.DeepEqual(r.ToolCalls, []string{"run_shell"}) {
		t.Errorf("tool_calls = %v", r.ToolCalls)
	}
}

func TestParseSemanticsNonLLM(t *testing.T) {
	if s := ParseSemantics(Request, []byte("not json")); s.Model != "" || s.MessageCount != 0 {
		t.Errorf("garbage should yield empty semantics: %+v", s)
	}
}
