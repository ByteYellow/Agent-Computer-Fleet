package provenance

import (
	"path/filepath"
	"testing"
)

// The double-attempt demo folds TWO main claude sessions (recon + team) plus the
// team's sub-agents into one run. transcriptsFromHookLog must surface every
// distinct main transcript_path AND every sub-agent agent_transcript_path -- if
// it collapsed the mains, one session's turns would be silently dropped. Verified
// against the real committed hook log, not a hand-authored fixture.
func TestTranscriptsFromRealHookLog(t *testing.T) {
	hooklog := filepath.Join("..", "..", "demo", "multiagent-provenance", "capture", "double-attempt-hooklog.jsonl")
	mains, subs, err := transcriptsFromHookLog(hooklog)
	if err != nil {
		t.Fatalf("parse real hook log: %v", err)
	}
	// Two main sessions (recon + team) and three sub-agent transcripts.
	if len(mains) != 2 {
		t.Errorf("main transcripts = %d, want 2: %v", len(mains), mains)
	}
	if len(subs) != 3 {
		t.Errorf("sub-agent transcripts = %d, want 3: %v", len(subs), subs)
	}
	// Every sub carries an agent id and a subagents/ path; no main is mistaken for a sub.
	for _, s := range subs {
		if s.AgentID == "" || s.Path == "" {
			t.Errorf("sub-agent missing id/path: %+v", s)
		}
		for _, m := range mains {
			if m == s.Path {
				t.Errorf("path %s counted as both main and sub", m)
			}
		}
	}
}
