package launch

import "testing"

func TestVerdictFor(t *testing.T) {
	cases := []struct {
		name   string
		report Report
		want   string
	}{
		{
			name:   "high risk is flagged even when degraded",
			report: Report{SysTier: "none", AppTier: "record", HighRisk: 1},
			want:   "FLAGGED",
		},
		{
			name:   "intent mismatch is flagged",
			report: Report{SysTier: "kernel", AppTier: "hooks(claude-code)", HooksIngested: 3, IntentMismatches: 1},
			want:   "FLAGGED",
		},
		{
			// The finding's exact case: record-only, no sensor, no captured
			// intent. "No findings" here is absence of evidence, not clean.
			name:   "record-only with no sensor is degraded, not clean",
			report: Report{SysTier: "none", AppTier: "record", HooksIngested: 0},
			want:   "DEGRADED",
		},
		{
			// A transcript harness that captured zero tool calls saw nothing.
			name:   "harness that captured nothing and no sensor is degraded",
			report: Report{SysTier: "none", AppTier: "transcript(codex)", HooksIngested: 0},
			want:   "DEGRADED",
		},
		{
			// mac + Claude Code: no kernel sensor, but hooks captured intent.
			name:   "hooks captured with no sensor is clean",
			report: Report{SysTier: "none", AppTier: "hooks(claude-code)", HooksIngested: 5},
			want:   "CLEAN",
		},
		{
			// Linux sensor active: kernel telemetry alone justifies clean.
			name:   "kernel telemetry alone is clean",
			report: Report{SysTier: "kernel", AppTier: "record", HooksIngested: 0},
			want:   "CLEAN",
		},
	}
	for _, c := range cases {
		if got := verdictFor(c.report); got != c.want {
			t.Errorf("%s: verdictFor = %q, want %q", c.name, got, c.want)
		}
	}
}
