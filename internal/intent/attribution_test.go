package intent

import (
	"testing"
	"time"
)

func win(agent, tc, program, start, end string) toolCallWindow {
	s, _ := time.Parse(time.RFC3339Nano, start)
	e, _ := time.Parse(time.RFC3339Nano, end)
	return toolCallWindow{agent: agent, toolCall: tc, program: program,
		start: s.Add(-30 * time.Second), end: e.Add(30 * time.Second)}
}

// TestContainingCommGate is the regression guard for the false-FLAGGED class:
// a background harness read (comm=claude) in a benign tool's window must NOT be
// attributed to that tool, while the tool's own subprocess read (comm matching
// the tool program) must be -- even when the syscall lands seconds after the
// hook window (PostToolUse fires early).
func TestContainingCommGate(t *testing.T) {
	windows := toolCallWindows{
		win("main", "tc-echo", "echo", "2026-07-06T08:45:00.000Z", "2026-07-06T08:45:00.100Z"),
		win("main", "tc-cat", "cat", "2026-07-06T08:45:12.180Z", "2026-07-06T08:45:12.331Z"),
	}

	// The cat subprocess reads the secret 3s after PostToolUse: still attributed
	// (wide window) and to the cat tool (comm match), not the echo tool.
	w, ok := windows.containing("2026-07-06T08:45:15.341Z", "cat")
	if !ok || w.toolCall != "tc-cat" {
		t.Fatalf("cat read should attribute to tc-cat, got ok=%v tc=%q", ok, w.toolCall)
	}

	// A background harness read (comm=claude) in the same window matches NO tool
	// program -> not attributed (becomes a coverage gap, never a mismatch).
	if _, ok := windows.containing("2026-07-06T08:45:13.000Z", "claude"); ok {
		t.Fatal("a comm=claude background read must not attribute to any tool call")
	}
	if _, ok := windows.containing("2026-07-06T08:45:13.000Z", "Bun Pool 1"); ok {
		t.Fatal("a comm=Bun read must not attribute to any tool call")
	}

	// No comm at all -> no time-window attribution.
	if _, ok := windows.containing("2026-07-06T08:45:15.341Z", ""); ok {
		t.Fatal("an effect with no comm must not be time-window attributed")
	}
}

func TestProgramName(t *testing.T) {
	cases := map[string]string{
		"cat /home/x/.aws/credentials": "cat",
		"/usr/bin/python3 setup.py":    "python3",
		"echo hello":                   "echo",
		"":                             "",
	}
	for in, want := range cases {
		if got := programName(in); got != want {
			t.Errorf("programName(%q)=%q want %q", in, got, want)
		}
	}
}
