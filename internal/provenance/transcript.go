package provenance

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// HarvestTranscript ingests a Claude Code session transcript (the JSONL file a
// hook's stdin points at via `transcript_path`) into the same llm_call graph
// model that TLS capture feeds -- so the agent-intent 4-stage flow renders the
// model's real prompt, reasoning, and tool decisions with ZERO instrumentation
// and on any platform (no eBPF/TLS needed). This is the cognitive-intent axis
// the contract-vs-effect diff deliberately cannot capture: what the model was
// asked, what it reasoned, and what it decided to do.
//
// Each user→assistant turn becomes: an llm_message request object (the prompt),
// an llm_message response object (the assistant's reasoning + decided tools), an
// llm_call node linking them, and llm_caused edges to the syscalls the decided
// shell commands actually ran. Idempotent per run.
func HarvestTranscript(store ObjectStore, db *sql.DB, runID, path string) (int, error) {
	if runID == "" {
		return 0, fmt.Errorf("harvest transcript: run id is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("harvest transcript: open %s: %w", path, err)
	}
	defer f.Close()

	turns, err := parseTranscript(f)
	if err != nil {
		return 0, err
	}
	if len(turns) == 0 {
		return 0, nil
	}

	// Idempotent: clear prior transcript-sourced objects and edges for the run.
	if _, err := db.Exec(`DELETE FROM provenance_objects WHERE run_id = ? AND source_id LIKE 'transcript/%'`, runID); err != nil {
		return 0, err
	}
	if _, err := db.Exec(`DELETE FROM graph_edges WHERE run_id = ? AND from_id LIKE 'llm_call/tr-%'`, runID); err != nil {
		return 0, err
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	n := 0
	for i, t := range turns {
		reqContent, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"content": t.Prompt}}})
		reqObj, err := store.PutExternalObject(ExternalObjectInput{
			Type: "llm_message", SourceID: fmt.Sprintf("transcript/req-%d", i), RunID: runID,
			Payload: map[string]any{
				"direction": "request", "model": t.Model, "content": string(reqContent),
				"semantics": map[string]any{"model": t.Model, "message_count": 1},
			},
		})
		if err != nil {
			return n, fmt.Errorf("harvest transcript: request object: %w", err)
		}
		respContent, _ := json.Marshal(map[string]any{"content": t.ContentBlocks, "thinking": t.Thinking, "text": t.Text})
		respObj, err := store.PutExternalObject(ExternalObjectInput{
			Type: "llm_message", SourceID: fmt.Sprintf("transcript/resp-%d", i), RunID: runID,
			Payload: map[string]any{
				"direction": "response", "model": t.Model, "content": string(respContent),
				"semantics": map[string]any{
					"model": t.Model, "tool_calls": t.DecidedTools, "stop_reason": t.StopReason,
				},
			},
		})
		if err != nil {
			return n, fmt.Errorf("harvest transcript: response object: %w", err)
		}

		llmNode := fmt.Sprintf("llm_call/tr-%d", i)
		if err := insertLLMEdge(db, runID, llmNode, reqObj.Hash, edgeLLMRequest, "", now); err != nil {
			return n, err
		}
		if err := insertLLMEdge(db, runID, llmNode, respObj.Hash, edgeLLMResponse, "", now); err != nil {
			return n, err
		}
		// Link the decided shell commands to the syscalls that actually ran them.
		actions, err := commandMatchedActions(db, runID, t.ShellCommands)
		if err != nil {
			return n, err
		}
		for _, action := range actions {
			if err := insertLLMEdge(db, runID, llmNode, action, edgeLLMCaused, "", now); err != nil {
				return n, err
			}
		}
		n++
	}
	return n, nil
}

// transcriptTurn is one prompt→assistant exchange distilled from the transcript.
type transcriptTurn struct {
	Prompt        string   // the user prompt that led to this turn
	Model         string   // model that produced the response
	Thinking      string   // the model's reasoning blocks (the "why"/plan)
	Text          string   // the model's visible answer text
	ContentBlocks []any    // raw assistant content blocks (for the response object)
	DecidedTools  []string // readable decided tool calls ("Bash: cat x", "Read: y")
	ShellCommands []string // just the shell commands, for syscall command-match
	StopReason    string
}

// transcriptLine is the tolerant projection of one transcript JSONL row.
type transcriptLine struct {
	Type    string `json:"type"`
	Message struct {
		Role       string          `json:"role"`
		Model      string          `json:"model"`
		StopReason string          `json:"stop_reason"`
		Content    json.RawMessage `json:"content"` // string (user) OR array (assistant/tool_result)
	} `json:"message"`
}

// parseTranscript walks the JSONL, pairing each assistant message with the most
// recent real user prompt (a string content, not a tool-result array).
func parseTranscript(r io.Reader) ([]transcriptTurn, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var turns []transcriptTurn
	lastPrompt := ""
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var tl transcriptLine
		if json.Unmarshal([]byte(line), &tl) != nil {
			continue
		}
		switch tl.Type {
		case "user":
			// A user prompt is a plain string; a tool_result is an array -- only the
			// former is a real prompt that starts a turn.
			var s string
			if json.Unmarshal(tl.Message.Content, &s) == nil && strings.TrimSpace(s) != "" {
				lastPrompt = s
			}
		case "assistant":
			var blocks []any
			if json.Unmarshal(tl.Message.Content, &blocks) != nil {
				continue
			}
			turn := transcriptTurn{
				Prompt: lastPrompt, Model: tl.Message.Model, StopReason: tl.Message.StopReason,
				ContentBlocks: blocks,
			}
			collectAssistantBlocks(blocks, &turn)
			// Skip empty assistant turns (pure whitespace, no reasoning/answer/action).
			if turn.Thinking == "" && turn.Text == "" && len(turn.DecidedTools) == 0 {
				continue
			}
			turns = append(turns, turn)
		}
	}
	return turns, sc.Err()
}

// collectAssistantBlocks pulls the reasoning, decided tools, and shell commands
// out of an assistant message's content blocks.
func collectAssistantBlocks(blocks []any, turn *transcriptTurn) {
	var thinking, text []string
	for _, b := range blocks {
		m, ok := b.(map[string]any)
		if !ok {
			continue
		}
		switch m["type"] {
		case "thinking":
			if s, _ := m["thinking"].(string); s != "" {
				thinking = append(thinking, s)
			}
		case "text":
			if s, _ := m["text"].(string); s != "" {
				text = append(text, s)
			}
		case "tool_use":
			name, _ := m["name"].(string)
			input, _ := m["input"].(map[string]any)
			label, shell := describeToolUse(name, input)
			if label != "" {
				turn.DecidedTools = append(turn.DecidedTools, label)
			}
			if shell != "" {
				turn.ShellCommands = append(turn.ShellCommands, shell)
			}
		}
	}
	turn.Thinking = strings.Join(thinking, "\n")
	turn.Text = strings.Join(text, "\n")
}

// describeToolUse renders a readable label for a decided tool call and, when it
// is a shell command, the raw command for syscall matching.
func describeToolUse(name string, input map[string]any) (label, shell string) {
	str := func(k string) string { s, _ := input[k].(string); return s }
	switch name {
	case "Bash":
		cmd := str("command")
		return "Bash: " + cmd, cmd
	case "Read":
		return "Read: " + str("file_path"), ""
	case "Write", "Edit":
		return name + ": " + str("file_path"), ""
	case "SendMessage":
		return "SendMessage → " + firstNonEmpty(str("recipient"), str("to")), ""
	default:
		if name == "" {
			return "", ""
		}
		return name, ""
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
