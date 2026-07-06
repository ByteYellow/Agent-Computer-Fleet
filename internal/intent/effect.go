// Package intent turns the model/agent's declared intent and the system's
// observed runtime effects into a first-class Intent-Runtime Diff.
//
// The old model could only draw one edge: "the model said command X, and command
// X ran" (a positive match). It could not represent DIVERGENCE -- the agent said
// read-only but the network egressed, an install that read a foreign secret, a
// refusal that happened anyway. Those divergences are the whole security value.
//
// This package generalizes past shell commands to three layers:
//
//	IntentContract   -- what an action (tool call / peer message / refusal)
//	                    declares it should do and must-not do (effect sets)
//	RuntimeEffect    -- what the system actually did, normalized tool-agnostically
//	IntentRuntimeDiff-- the typed reconciliation: match, boundary violation,
//	                    refusal-bypass, or an honest coverage gap
//
// It reuses the existing pieces rather than replacing them: the eBPF/record
// events are the effect source, hooksbridge.CorrelateSyscalls provides the
// effect->agent attribution (command-match), and the security policy engine
// classifies whether a secret read is a foreign secret or the agent's own creds.
package intent

import (
	"encoding/json"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/security"
)

// EffectKind is a normalized, tool-agnostic classification of what a runtime
// event actually did. Raw telemetry is preserved in the events table; the diff
// engine reasons only over these normalized effects.
type EffectKind string

const (
	EffectProcessExec    EffectKind = "process_exec"
	EffectFileRead       EffectKind = "file_read"
	EffectFileWrite      EffectKind = "file_write"
	EffectNetworkConnect EffectKind = "network_connect"
	// EffectSecretRead is a read of a FOREIGN secret/credential path -- i.e. one
	// the policy engine does not classify as the agent's own operational creds.
	// The self-vs-foreign split is what keeps the agent reading its own
	// ~/.claude creds from flooding every run as a mismatch.
	EffectSecretRead EffectKind = "secret_read"
	// EffectMetadataEgress is egress to the link-local cloud metadata IP.
	EffectMetadataEgress EffectKind = "metadata_egress"
	EffectPrivateCIDR    EffectKind = "private_cidr_access"
)

// RuntimeEffect is one normalized effect attributed to an agent scope.
type RuntimeEffect struct {
	Kind       EffectKind `json:"kind"`
	Target     string     `json:"target"`
	AgentID    string     `json:"agent_id"`
	ToolCallID string     `json:"tool_call_id"`
	EventID    string     `json:"event_id"`
	Confidence float64    `json:"confidence"`
}

// classifyEvent maps a stored event to a normalized effect. It returns ok=false
// for events that carry no diff-relevant effect. The security engine decides
// whether a credential-shaped read is a foreign secret (a real effect) or the
// agent's own creds (benign), so classification stays consistent with policy and
// immune to self-credential noise.
func classifyEvent(eng security.Engine, eventType, payload string) (EffectKind, string, bool) {
	path, dstIP, command := extractEventFields(payload)
	switch eventType {
	case "execve":
		return EffectProcessExec, command, true
	case "metadata_ip":
		return EffectMetadataEgress, orDefault(dstIP, "169.254.169.254"), true
	case "private_cidr":
		return EffectPrivateCIDR, dstIP, true
	case "network_connect":
		return EffectNetworkConnect, dstIP, true
	case "file_write":
		return EffectFileWrite, path, true
	case "secret_path", "file_open", "openat":
		// Foreign secret vs the agent's own creds: ask the policy engine. A
		// secret_path_access (kill) verdict => foreign secret; a
		// self_credential_access (allow) verdict => benign own-creds read.
		d := eng.Evaluate(security.Event{EventType: "file_open", Path: path})
		if isForeignSecret(d) {
			return EffectSecretRead, path, true
		}
		if eventType == "secret_path" {
			return EffectFileRead, path, true
		}
		return EffectFileRead, path, true
	}
	return "", "", false
}

// isForeignSecret reports whether the policy verdict marks this read as a real
// foreign-secret access (as opposed to the agent's own credentials, which the
// self_credential_access allow rule clears).
func isForeignSecret(d security.Decision) bool {
	if d.RuleID == "self_credential_access" {
		return false
	}
	if d.RuleID == "secret_path_access" {
		return true
	}
	return security.IsEnforcingDecision(d.Decision) && strings.Contains(strings.ToLower(d.Reason), "secret")
}

// extractEventFields pulls path/dst_ip/command out of the event payload, which is
// an envelope of the shape {"rollout_id":...,"payload":{"path"|"dst_ip"|"argv"|
// "command"|"comm":...}}. Tolerant of both the enveloped and flat shapes.
func extractEventFields(payload string) (path, dstIP, command string) {
	if payload == "" {
		return "", "", ""
	}
	var top map[string]any
	if err := json.Unmarshal([]byte(payload), &top); err != nil {
		return "", "", ""
	}
	inner := top
	if p, ok := top["payload"].(map[string]any); ok {
		inner = p
	}
	// Descend one more level for the deeply-nested execve envelope
	// (payload.payload.raw.command) seen in real captures.
	raw := inner
	if r, ok := inner["raw"].(map[string]any); ok {
		raw = r
	}
	path = firstString(inner["path"], raw["path"])
	dstIP = firstString(inner["dst_ip"], raw["dst_ip"], inner["host"], raw["host"])
	command = firstString(inner["command"], raw["command"])
	if command == "" {
		command = argvToCommand(firstAny(inner["argv"], raw["argv"]))
	}
	return path, dstIP, command
}

// extractComm returns the executing process's short name (comm) from an event
// payload -- used to confirm that a time-window-attributed effect was actually
// produced by the process the tool call launched, not by a background harness
// thread that merely touched the same file in the same window.
func extractComm(payload string) string {
	if payload == "" {
		return ""
	}
	var top map[string]any
	if err := json.Unmarshal([]byte(payload), &top); err != nil {
		return ""
	}
	inner := top
	if p, ok := top["payload"].(map[string]any); ok {
		inner = p
	}
	raw := inner
	if r, ok := inner["raw"].(map[string]any); ok {
		raw = r
	}
	return firstString(inner["comm"], raw["comm"])
}

func argvToCommand(v any) string {
	arr, ok := v.([]any)
	if !ok {
		return ""
	}
	parts := make([]string, 0, len(arr))
	for _, a := range arr {
		if s, ok := a.(string); ok {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

func firstString(vals ...any) string {
	for _, v := range vals {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func firstAny(vals ...any) any {
	for _, v := range vals {
		if v != nil {
			return v
		}
	}
	return nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
