package intent

import (
	"sort"
	"strings"
)

func isBaselineForbidden(k EffectKind) bool {
	for _, b := range baselineForbidden {
		if b == k {
			return true
		}
	}
	return false
}

// Diff states. v1 deliberately ships the security-relevant states and the
// honesty state, and does NOT emit executed_without_intent (which needs
// complete intent capture to avoid false positives -- an effect with no
// contract is reported as intent_coverage_gap, not as a rogue action).
const (
	StatusMismatch      = "declared_vs_effect_mismatch"  // effect violates the contract boundary
	StatusRefusedBypass = "refused_but_runtime_happened" // a refused action's effects happened anyway
	StatusExecuted      = "decided_and_executed"         // declared effects appeared, no violation
	StatusCoverageGap   = "intent_coverage_gap"          // effects seen for a scope with NO captured intent
)

// FindingPeerMessageMismatch marks a boundary violation whose intent originated
// from a peer message -- the multi-agent lateral-influence finding.
const FindingPeerMessageMismatch = "peer_message_intent_mismatch"

// IntentRuntimeDiff is one reconciliation of a contract against the effects
// attributed to its scope.
type IntentRuntimeDiff struct {
	ID             string       `json:"id"`
	RunID          string       `json:"run_id"`
	AgentID        string       `json:"agent_id"`
	ToolCallID     string       `json:"tool_call_id,omitempty"`
	ContractKind   string       `json:"contract_kind"`
	Operation      string       `json:"operation"`
	Target         string       `json:"target"`
	Status         string       `json:"status"`
	Finding        string       `json:"finding,omitempty"`
	Confidence     float64      `json:"confidence"`
	Declared       []EffectKind `json:"declared_effects"`
	Forbidden      []EffectKind `json:"forbidden_effects"`
	Observed       []EffectKind `json:"observed_effects"`
	MismatchReason string       `json:"mismatch_reason,omitempty"`
	Source         string       `json:"source"`
	EventIDs       []string     `json:"event_ids,omitempty"`
}

// Diff reconciles contracts against runtime effects and returns typed diffs.
func Diff(contracts []IntentContract, effects []RuntimeEffect) []IntentRuntimeDiff {
	byAgent := map[string][]RuntimeEffect{}
	byToolCall := map[string][]RuntimeEffect{}
	contractedAgents := map[string]bool{}
	contractedToolCalls := map[string]bool{}
	for _, e := range effects {
		byAgent[e.AgentID] = append(byAgent[e.AgentID], e)
		if e.ToolCallID != "" {
			byToolCall[e.ToolCallID] = append(byToolCall[e.ToolCallID], e)
		}
	}

	var out []IntentRuntimeDiff
	for _, c := range contracts {
		contractedAgents[c.ScopeAgent] = true
		if c.ToolCallID != "" {
			contractedToolCalls[c.ToolCallID] = true
		}

		// Scope the effects a contract is answerable for: a tool_call contract
		// owns its own tool_call's effects; a peer_message/refusal contract
		// governs everything its target agent did.
		scope := byAgent[c.ScopeAgent]
		if (c.Kind == ContractToolCall || c.Kind == ContractModelResponse) && c.ToolCallID != "" {
			if te, ok := byToolCall[c.ToolCallID]; ok {
				scope = te
			} else {
				scope = nil // no effects attributed to this specific tool call
			}
		}

		forbidden := c.Profile.forbiddenSet()
		if c.Negative {
			// A refusal forbids every baseline-sensitive effect outright.
			forbidden = map[EffectKind]bool{}
			for _, e := range baselineForbidden {
				forbidden[e] = true
			}
		}

		var violating []RuntimeEffect
		observedKinds := map[EffectKind]bool{}
		for _, e := range scope {
			observedKinds[e.Kind] = true
			if forbidden[e.Kind] {
				violating = append(violating, e)
			}
		}
		if len(violating) == 0 {
			// No boundary violation. Emit a green baseline only when the declared
			// effects actually appeared (proof the intent executed as claimed).
			if declaredObserved(c.Profile.Declared, observedKinds) && len(scope) > 0 {
				out = append(out, IntentRuntimeDiff{
					ID: "diff/" + trimContract(c.ID) + "/ok", RunID: "", AgentID: c.ScopeAgent, ToolCallID: c.ToolCallID,
					ContractKind: c.Kind, Operation: c.Operation, Target: c.Target,
					Status: StatusExecuted, Confidence: c.Confidence,
					Declared: c.Profile.Declared, Observed: kindsOf(scope), Source: c.Source,
				})
			}
			continue
		}

		status := StatusMismatch
		finding := ""
		reason := c.Operation + " produced effects it does not permit: " + joinKinds(kindsOf(violating))
		switch {
		case c.Negative:
			status = StatusRefusedBypass
			reason = "agent refused this action but its runtime produced: " + joinKinds(kindsOf(violating))
		case c.Kind == ContractPeerMessage:
			finding = FindingPeerMessageMismatch
			reason = "peer instruction '" + shorten(c.Target, 60) + "' led to forbidden effects: " + joinKinds(kindsOf(violating))
		}
		out = append(out, IntentRuntimeDiff{
			ID: "diff/" + trimContract(c.ID), AgentID: c.ScopeAgent, ToolCallID: c.ToolCallID,
			ContractKind: c.Kind, Operation: c.Operation, Target: c.Target,
			Status: status, Finding: finding, Confidence: violationConfidence(c, violating),
			Declared: c.Profile.Declared, Forbidden: sortedForbidden(forbidden), Observed: kindsOf(violating),
			MismatchReason: reason, Source: c.Source, EventIDs: eventIDsOf(violating),
		})
	}

	// Honesty: a baseline-sensitive effect (foreign-secret read, metadata egress,
	// private-CIDR reach) that we could NOT tie to any captured contract is a
	// coverage gap, NOT a rogue action -- we will not claim "executed without
	// intent" when we may simply have failed to capture the intent (in-process
	// sub-agents share one kernel scope; command-match can miss). Benign effects
	// with no contract are not reported. Grouped by the scope we could resolve
	// (agent, else the owning tool call).
	type gapBucket struct {
		effects []RuntimeEffect
		isAgent bool
	}
	gaps := map[string]*gapBucket{}
	for _, e := range effects {
		if !isBaselineForbidden(e.Kind) {
			continue
		}
		if e.AgentID != "" && contractedAgents[e.AgentID] {
			continue // its contract handled it (as match or mismatch) above
		}
		if e.ToolCallID != "" && contractedToolCalls[e.ToolCallID] {
			continue
		}
		key := "scope:" + e.ToolCallID
		isAgent := false
		if e.AgentID != "" {
			key, isAgent = "agent:"+e.AgentID, true
		}
		if gaps[key] == nil {
			gaps[key] = &gapBucket{isAgent: isAgent}
		}
		gaps[key].effects = append(gaps[key].effects, e)
	}
	for key, b := range gaps {
		d := IntentRuntimeDiff{
			ID: "diff/gap/" + shorten(key, 24), ContractKind: "none", Status: StatusCoverageGap, Confidence: 0,
			Observed:       kindsOf(b.effects),
			MismatchReason: "sensitive runtime effects observed (" + joinKinds(kindsOf(b.effects)) + ") but no intent contract was captured for this scope",
			Source:         "coverage", EventIDs: eventIDsOf(b.effects),
		}
		if b.isAgent {
			d.AgentID = strings.TrimPrefix(key, "agent:")
		} else {
			d.ToolCallID = strings.TrimPrefix(key, "scope:")
		}
		out = append(out, d)
	}

	sort.SliceStable(out, func(i, j int) bool { return statusRank(out[i].Status) < statusRank(out[j].Status) })
	return out
}

func declaredObserved(declared []EffectKind, observed map[EffectKind]bool) bool {
	if len(declared) == 0 {
		return false
	}
	for _, d := range declared {
		if !observed[d] {
			return false
		}
	}
	return true
}

func violationConfidence(c IntentContract, violating []RuntimeEffect) float64 {
	// The finding "the model claimed X but the kernel witnessed a forbidden
	// effect" is as strong as the weakest attribution among the violating
	// effects -- runtime effects are kernel-witnessed (~1.0), so a mismatch is
	// high-confidence even though the intent CLAIM itself is only asserted.
	min := 1.0
	for _, e := range violating {
		if e.Confidence < min {
			min = e.Confidence
		}
	}
	return min
}

func kindsOf(es []RuntimeEffect) []EffectKind {
	seen := map[EffectKind]bool{}
	var out []EffectKind
	for _, e := range es {
		if !seen[e.Kind] {
			seen[e.Kind] = true
			out = append(out, e.Kind)
		}
	}
	return out
}

func eventIDsOf(es []RuntimeEffect) []string {
	var out []string
	for _, e := range es {
		if e.EventID != "" {
			out = append(out, e.EventID)
		}
	}
	return out
}

func sortedForbidden(m map[EffectKind]bool) []EffectKind {
	var out []EffectKind
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func statusRank(s string) int {
	switch s {
	case StatusRefusedBypass:
		return 0
	case StatusMismatch:
		return 1
	case StatusCoverageGap:
		return 2
	case StatusExecuted:
		return 3
	}
	return 4
}
