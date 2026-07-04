package tlsintent

import "encoding/json"

// Semantics is the minimal structured intent pulled from an LLM request/response
// body, tolerant across the common provider shapes (Anthropic Messages, OpenAI
// Chat Completions). Empty fields mean "not present / not an LLM call".
type Semantics struct {
	Model        string   `json:"model,omitempty"`
	MessageCount int      `json:"message_count,omitempty"` // request: number of messages
	HasSystem    bool     `json:"has_system,omitempty"`    // request: a system prompt is present
	ToolsOffered []string `json:"tools_offered,omitempty"` // request: tool names offered to the model
	ToolCalls    []string `json:"tool_calls,omitempty"`    // response: tool names the model decided to call
	StopReason   string   `json:"stop_reason,omitempty"`   // response: why generation stopped
}

// ParseSemantics extracts structured intent from a request or response body.
func ParseSemantics(direction string, body []byte) Semantics {
	var raw map[string]any
	if json.Unmarshal(body, &raw) != nil {
		return Semantics{}
	}
	s := Semantics{Model: str(raw["model"])}
	if direction == Request {
		if msgs, ok := raw["messages"].([]any); ok {
			s.MessageCount = len(msgs)
		}
		if _, ok := raw["system"]; ok {
			s.HasSystem = true
		}
		s.ToolsOffered = toolNames(raw["tools"])
		return s
	}
	// Response.
	s.StopReason = firstStr(raw, "stop_reason", "finish_reason")
	// Anthropic: content:[{type:"tool_use", name:...}].
	if content, ok := raw["content"].([]any); ok {
		for _, item := range content {
			m, _ := item.(map[string]any)
			if str(m["type"]) == "tool_use" {
				if n := str(m["name"]); n != "" {
					s.ToolCalls = append(s.ToolCalls, n)
				}
			}
		}
	}
	// OpenAI: choices:[{message:{tool_calls:[{function:{name}}]}, finish_reason}].
	if choices, ok := raw["choices"].([]any); ok {
		for _, c := range choices {
			cm, _ := c.(map[string]any)
			if s.StopReason == "" {
				s.StopReason = str(cm["finish_reason"])
			}
			msg, _ := cm["message"].(map[string]any)
			for _, tc := range asSlice(msg["tool_calls"]) {
				tcm, _ := tc.(map[string]any)
				fn, _ := tcm["function"].(map[string]any)
				if n := str(fn["name"]); n != "" {
					s.ToolCalls = append(s.ToolCalls, n)
				}
			}
		}
	}
	return s
}

// toolNames extracts tool names from an Anthropic (`tools:[{name}]`) or OpenAI
// (`tools:[{function:{name}}]`) tools array.
func toolNames(v any) []string {
	var out []string
	for _, t := range asSlice(v) {
		tm, _ := t.(map[string]any)
		if n := str(tm["name"]); n != "" {
			out = append(out, n)
			continue
		}
		if fn, ok := tm["function"].(map[string]any); ok {
			if n := str(fn["name"]); n != "" {
				out = append(out, n)
			}
		}
	}
	return out
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func firstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}
