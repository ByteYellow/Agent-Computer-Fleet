package launch

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/store"
)

// recipe is the per-harness knowledge of how to observe an agent's intent
// without instrumenting it: whether hooks can be injected, and how. Unknown
// commands get the record-only tier (no injection). This is the extension point
// for "don't pick a specific harness" -- each supported agent is a recipe, and
// the always-present record-only fallback means launch runs any command.
type recipe struct {
	tier        string // app-side tier label: "hooks(<harness>)" or "record"
	detail      string // short human note for the banner
	injectHooks bool
	// inject rewrites the agent argv to load a per-run hooks overlay and returns
	// a cleanup that removes the overlay (the hook log is kept for sealing).
	inject func(command []string, selfExe, hookLogPath string, paths store.Paths) (newCommand []string, cleanup func(), err error)
}

// detectRecipe picks the recipe for an agent command by its program basename.
func detectRecipe(command []string) recipe {
	base := strings.ToLower(filepath.Base(command[0]))
	switch base {
	case "claude", "claude-code":
		return recipe{
			tier:        "hooks(claude-code)",
			detail:      "per-run --settings overlay; ~/.claude untouched",
			injectHooks: true,
			inject:      injectClaudeCode,
		}
	default:
		return recipe{
			tier:   "record",
			detail: fmt.Sprintf("no hooks recipe for %q; execution scope only", base),
		}
	}
}

// claudeHookEvents are the Claude Code hook events launch captures. PreToolUse /
// PostToolUse carry each action's tool_input + agent_id; SubagentStart/Stop give
// delegation edges; SessionStart/UserPromptSubmit/Stop bracket the turn and
// carry transcript_path (the anchor for the future transcript-harvest step).
var claudeHookEvents = []string{
	"SessionStart",
	"UserPromptSubmit",
	"PreToolUse",
	"PostToolUse",
	"SubagentStart",
	"SubagentStop",
	"Stop",
	"SessionEnd",
}

// injectClaudeCode writes a per-run settings overlay whose hooks append every
// event's raw JSON stdin to the run's hook log, and inserts `--settings
// <overlay>` right after the `claude` program. The overlay is the highest-
// precedence non-managed settings source, so the user's ~/.claude/settings.json
// is never read for hooks and never modified. Cleanup removes the overlay.
func injectClaudeCode(command []string, selfExe, hookLogPath string, paths store.Paths) ([]string, func(), error) {
	for _, a := range command[1:] {
		if a == "--settings" || strings.HasPrefix(a, "--settings=") {
			return command, nil, fmt.Errorf("agent command already passes --settings; refusing to override")
		}
	}

	hookCmd := shQuote(selfExe) + " internal hook-log --file " + shQuote(hookLogPath)
	entry := []map[string]any{{
		"hooks": []map[string]any{{"type": "command", "command": hookCmd}},
	}}
	hooks := map[string]any{}
	for _, ev := range claudeHookEvents {
		hooks[ev] = entry
	}
	overlay := map[string]any{"hooks": hooks}

	overlayPath := strings.TrimSuffix(hookLogPath, "-hooks.jsonl") + "-settings.json"
	raw, err := json.MarshalIndent(overlay, "", "  ")
	if err != nil {
		return command, nil, err
	}
	if err := os.WriteFile(overlayPath, raw, 0o600); err != nil {
		return command, nil, err
	}

	newCommand := make([]string, 0, len(command)+2)
	newCommand = append(newCommand, command[0], "--settings", overlayPath)
	newCommand = append(newCommand, command[1:]...)
	cleanup := func() { _ = os.Remove(overlayPath) }
	return newCommand, cleanup, nil
}

// shQuote single-quotes a string for safe use in a POSIX shell command (Claude
// Code runs hook commands through a shell). Handles embedded single quotes and
// paths with spaces (e.g. "~/Documents/Agent Provenance").
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
