package launch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestDetectRecipe(t *testing.T) {
	cases := []struct {
		argv0  string
		tier   string
		inject bool
	}{
		{"claude", "hooks(claude-code)", true},
		{"/usr/local/bin/claude", "hooks(claude-code)", true},
		{"claude-code", "hooks(claude-code)", true},
		{"codex", "record", false},
		{"python3", "record", false},
	}
	for _, c := range cases {
		r := detectRecipe([]string{c.argv0, "arg"})
		if r.tier != c.tier {
			t.Errorf("%s: tier=%q want %q", c.argv0, r.tier, c.tier)
		}
		if r.injectHooks != c.inject {
			t.Errorf("%s: injectHooks=%v want %v", c.argv0, r.injectHooks, c.inject)
		}
	}
}

func TestInjectClaudeCode(t *testing.T) {
	dir := t.TempDir()
	paths := store.Paths{Logs: dir}
	hookLog := filepath.Join(dir, "launch-run-x-hooks.jsonl")

	got, cleanup, err := injectClaudeCode([]string{"claude", "--print", "hi"}, "/opt/agentprov", hookLog, paths)
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	defer cleanup()

	// --settings <overlay> must be inserted right after the program, preserving
	// the user's own args after it.
	want := []string{"claude", "--settings"}
	if got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("argv = %v; want claude --settings <overlay> ...", got)
	}
	overlayPath := got[2]
	if got[3] != "--print" || got[4] != "hi" {
		t.Fatalf("user args not preserved after injection: %v", got)
	}

	raw, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("overlay unreadable: %v", err)
	}
	var overlay struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &overlay); err != nil {
		t.Fatalf("overlay not valid JSON: %v", err)
	}
	pre, ok := overlay.Hooks["PreToolUse"]
	if !ok || len(pre) == 0 || len(pre[0].Hooks) == 0 {
		t.Fatalf("overlay missing PreToolUse hook: %s", raw)
	}
	cmd := pre[0].Hooks[0].Command
	if !strings.Contains(cmd, "internal hook-log") || !strings.Contains(cmd, hookLog) {
		t.Fatalf("hook command wrong: %q", cmd)
	}

	// Cleanup removes the overlay (the hook log is kept for sealing).
	cleanup()
	if _, err := os.Stat(overlayPath); !os.IsNotExist(err) {
		t.Fatalf("overlay not cleaned up: %v", err)
	}
}

func TestInjectRefusesExistingSettings(t *testing.T) {
	paths := store.Paths{Logs: t.TempDir()}
	if _, _, err := injectClaudeCode([]string{"claude", "--settings", "mine.json"}, "/opt/agentprov", "/tmp/h.jsonl", paths); err == nil {
		t.Fatal("expected refusal when the agent command already passes --settings")
	}
}

func TestShQuote(t *testing.T) {
	cases := map[string]string{
		"/opt/agentprov":               `'/opt/agentprov'`,
		"/Users/me/Agent Provenance/x": `'/Users/me/Agent Provenance/x'`,
		"it's":                         `'it'\''s'`,
	}
	for in, want := range cases {
		if got := shQuote(in); got != want {
			t.Errorf("shQuote(%q) = %q; want %q", in, got, want)
		}
	}
}
