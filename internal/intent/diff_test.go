package intent

import "testing"

func profiles() map[string]Profile { return DefaultProfiles() }

// findDiff returns the first diff matching a predicate, or a zero value.
func findDiff(diffs []IntentRuntimeDiff, pred func(IntentRuntimeDiff) bool) (IntentRuntimeDiff, bool) {
	for _, d := range diffs {
		if pred(d) {
			return d, true
		}
	}
	return IntentRuntimeDiff{}, false
}

// TestDiffDeclaredVsEffectMismatch: an install tool call that reads a foreign
// secret violates its contract (install does not permit secret_read).
func TestDiffDeclaredVsEffectMismatch(t *testing.T) {
	contracts := []IntentContract{{
		ID: "contract/tc1", Kind: ContractToolCall, ScopeAgent: "bob", ToolCallID: "tc1",
		Operation: "install", Profile: profileFor(profiles(), "install"), Confidence: 0.5,
	}}
	effects := []RuntimeEffect{
		{Kind: EffectProcessExec, AgentID: "bob", ToolCallID: "tc1", EventID: "e1", Confidence: 1},
		{Kind: EffectSecretRead, Target: "/root/.aws/credentials", AgentID: "bob", ToolCallID: "tc1", EventID: "e2", Confidence: 1},
	}
	diffs := Diff(contracts, effects)
	d, ok := findDiff(diffs, func(d IntentRuntimeDiff) bool { return d.Status == StatusMismatch })
	if !ok {
		t.Fatalf("expected a declared_vs_effect_mismatch, got %+v", diffs)
	}
	if !containsKind(d.Observed, EffectSecretRead) {
		t.Errorf("mismatch should cite secret_read; observed=%v", d.Observed)
	}
	if d.Confidence < 0.99 {
		t.Errorf("kernel-witnessed violation should be high confidence, got %.2f", d.Confidence)
	}
}

// TestDiffPeerMessageMismatch: a peer instruction to install, followed by the
// recipient reading a foreign secret, is a peer_message_intent_mismatch.
func TestDiffPeerMessageMismatch(t *testing.T) {
	contracts := []IntentContract{{
		ID: "contract/msg-1", Kind: ContractPeerMessage, ScopeAgent: "bob",
		Operation: "install", Target: "python3 setup.py install", Profile: profileFor(profiles(), "install"), Confidence: 0.5,
	}}
	effects := []RuntimeEffect{
		{Kind: EffectMetadataEgress, Target: "169.254.169.254", AgentID: "bob", ToolCallID: "tcx", EventID: "e9", Confidence: 1},
	}
	diffs := Diff(contracts, effects)
	d, ok := findDiff(diffs, func(d IntentRuntimeDiff) bool { return d.Finding == FindingPeerMessageMismatch })
	if !ok {
		t.Fatalf("expected peer_message_intent_mismatch, got %+v", diffs)
	}
	if d.Status != StatusMismatch {
		t.Errorf("peer mismatch should be a declared_vs_effect_mismatch, got %s", d.Status)
	}
}

// TestDiffRefusedButRuntimeHappened: an agent that refused, yet whose runtime
// produced a baseline-sensitive effect, is a refusal bypass.
func TestDiffRefusedButRuntimeHappened(t *testing.T) {
	contracts := []IntentContract{{
		ID: "contract/refusal-1", Kind: ContractRefusal, ScopeAgent: "recon", ToolCallID: "refusal-1",
		Operation: "refusal", Profile: Profile{Operation: "refusal"}, Negative: true, Confidence: 0.5,
	}}
	effects := []RuntimeEffect{
		{Kind: EffectSecretRead, Target: "/root/.aws/credentials", AgentID: "recon", ToolCallID: "tcr", EventID: "e5", Confidence: 1},
	}
	diffs := Diff(contracts, effects)
	if _, ok := findDiff(diffs, func(d IntentRuntimeDiff) bool { return d.Status == StatusRefusedBypass }); !ok {
		t.Fatalf("expected refused_but_runtime_happened, got %+v", diffs)
	}
}

// TestDiffCoverageGapNotMismatch: a foreign-secret read with NO contract for its
// scope is an honest coverage gap, never a mismatch -- the load-bearing honesty
// rule that keeps unattributed effects from reading as rogue actions.
func TestDiffCoverageGapNotMismatch(t *testing.T) {
	effects := []RuntimeEffect{
		{Kind: EffectSecretRead, Target: "/root/.aws/credentials", AgentID: "", ToolCallID: "tc-wrapper", EventID: "e7", Confidence: 1},
	}
	diffs := Diff(nil, effects)
	if _, ok := findDiff(diffs, func(d IntentRuntimeDiff) bool { return d.Status == StatusMismatch }); ok {
		t.Fatal("uncontracted effect must NOT be reported as a mismatch")
	}
	d, ok := findDiff(diffs, func(d IntentRuntimeDiff) bool { return d.Status == StatusCoverageGap })
	if !ok {
		t.Fatalf("expected intent_coverage_gap, got %+v", diffs)
	}
	if d.Confidence != 0 {
		t.Errorf("a coverage gap asserts nothing; confidence should be 0, got %.2f", d.Confidence)
	}
}

// TestDiffBenignReadNoMismatch: a read-only file tool that only reads a benign
// (non-secret) file matches its contract -- no false positive.
func TestDiffBenignReadNoMismatch(t *testing.T) {
	contracts := []IntentContract{{
		ID: "contract/tc2", Kind: ContractToolCall, ScopeAgent: "main", ToolCallID: "tc2",
		Operation: "file_read", Profile: profileFor(profiles(), "file_read"), Confidence: 0.5,
	}}
	effects := []RuntimeEffect{
		{Kind: EffectFileRead, Target: "/repo/README.md", AgentID: "main", ToolCallID: "tc2", EventID: "e8", Confidence: 1},
	}
	diffs := Diff(contracts, effects)
	if _, ok := findDiff(diffs, func(d IntentRuntimeDiff) bool { return d.Status == StatusMismatch }); ok {
		t.Fatal("a benign in-contract read must not be a mismatch")
	}
}

// TestDiffReadOnlyToolThatEgressed: a read-only tool whose runtime opened a
// network connection violates its contract even though network is benign for
// bash -- the finding is CONDITIONAL on the declared contract, which is the core
// differentiator from a global policy rule.
func TestDiffReadOnlyToolThatEgressed(t *testing.T) {
	contracts := []IntentContract{{
		ID: "contract/tc3", Kind: ContractToolCall, ScopeAgent: "main", ToolCallID: "tc3",
		Operation: "file_read", Profile: profileFor(profiles(), "file_read"), Confidence: 0.5,
	}}
	effects := []RuntimeEffect{
		{Kind: EffectNetworkConnect, Target: "1.2.3.4", AgentID: "main", ToolCallID: "tc3", EventID: "e10", Confidence: 1},
	}
	diffs := Diff(contracts, effects)
	if _, ok := findDiff(diffs, func(d IntentRuntimeDiff) bool { return d.Status == StatusMismatch }); !ok {
		t.Fatalf("read-only tool that egressed must be a mismatch, got %+v", diffs)
	}
	// And the SAME effect under a bash/exec contract is allowed -> no mismatch.
	contracts[0].Operation = "exec"
	contracts[0].Profile = profileFor(profiles(), "exec")
	if _, ok := findDiff(Diff(contracts, effects), func(d IntentRuntimeDiff) bool { return d.Status == StatusMismatch }); ok {
		t.Fatal("network egress under a bash/exec contract is permitted; must not be a mismatch")
	}
}

func containsKind(ks []EffectKind, want EffectKind) bool {
	for _, k := range ks {
		if k == want {
			return true
		}
	}
	return false
}
