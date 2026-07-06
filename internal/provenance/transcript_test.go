package provenance

import (
	"strings"
	"testing"
)

// A minimal transcript in the real Claude Code shape: a user prompt (string
// content), then an assistant turn with a thinking block and two tool_use
// blocks (Bash + Read). Tool-result user rows (array content) must not start a
// new turn.
const sampleTranscript = `
{"type":"queue-operation","message":{}}
{"type":"user","message":{"role":"user","content":"Check the AWS region: run cat /home/x/.aws/credentials and read /repo/README.md"}}
{"type":"assistant","message":{"role":"assistant","model":"deepseek-v4-pro","stop_reason":"tool_use","content":[{"type":"thinking","thinking":"I'll run the shell command and read the file in parallel."},{"type":"tool_use","name":"Bash","input":{"command":"cat /home/x/.aws/credentials"}},{"type":"tool_use","name":"Read","input":{"file_path":"/repo/README.md"}}]}}
{"type":"user","message":{"role":"user","content":[{"type":"tool_result","content":"aws creds..."}]}}
{"type":"assistant","message":{"role":"assistant","model":"deepseek-v4-pro","stop_reason":"end_turn","content":[{"type":"text","text":"The region is us-east-1."}]}}
`

func TestParseTranscript(t *testing.T) {
	turns, err := parseTranscript(strings.NewReader(sampleTranscript))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(turns) != 2 {
		t.Fatalf("expected 2 assistant turns, got %d", len(turns))
	}

	first := turns[0]
	if !strings.Contains(first.Prompt, "Check the AWS region") {
		t.Errorf("turn 0 prompt not carried: %q", first.Prompt)
	}
	if first.Model != "deepseek-v4-pro" {
		t.Errorf("model = %q", first.Model)
	}
	if !strings.Contains(first.Thinking, "in parallel") {
		t.Errorf("thinking (cognitive intent) not captured: %q", first.Thinking)
	}
	if first.StopReason != "tool_use" {
		t.Errorf("stop_reason = %q", first.StopReason)
	}
	// Decided tools: a Bash command (also a shell command for syscall match) and a Read.
	if len(first.ShellCommands) != 1 || first.ShellCommands[0] != "cat /home/x/.aws/credentials" {
		t.Errorf("shell commands = %v", first.ShellCommands)
	}
	joined := strings.Join(first.DecidedTools, " | ")
	if !strings.Contains(joined, "Bash: cat") || !strings.Contains(joined, "Read: /repo/README.md") {
		t.Errorf("decided tools = %v", first.DecidedTools)
	}

	// The tool_result user row must NOT have started a turn; the second turn's
	// prompt is still the original user prompt.
	if !strings.Contains(turns[1].Prompt, "Check the AWS region") {
		t.Errorf("tool_result row wrongly reset the prompt: %q", turns[1].Prompt)
	}
	if !strings.Contains(turns[1].Thinking, "") && turns[1].StopReason != "end_turn" {
		t.Errorf("turn 1 stop_reason = %q", turns[1].StopReason)
	}
}
