package intent

import "strings"

// baselineForbidden is the principled boundary that applies to EVERY operation
// unless its profile explicitly allows the effect: no action may read a foreign
// secret, egress to the link-local cloud-metadata IP, or reach a private CIDR
// unless it declared that intent. This is a generic security invariant, not a
// per-demo tuning -- an install that reads ~/.aws/credentials violates it for
// the same reason a read-only file tool that egresses does. That generality is
// what makes a bundle "lighting up" real evidence rather than confirmation bias.
var baselineForbidden = []EffectKind{EffectSecretRead, EffectMetadataEgress, EffectPrivateCIDR}

// Profile is a tool/operation's effect contract: what it is expected to do
// (Declared), what it may additionally do without it counting as drift
// (Allowed), and what it must not do beyond the baseline (Forbidden).
type Profile struct {
	Operation string       `yaml:"operation" json:"operation"`
	Declared  []EffectKind `yaml:"declared" json:"declared"`
	Allowed   []EffectKind `yaml:"allowed" json:"allowed"`
	Forbidden []EffectKind `yaml:"forbidden" json:"forbidden"`
}

// forbiddenSet returns the effective forbidden set: the baseline minus anything
// this operation explicitly allows, plus the profile's own extra forbiddens.
func (p Profile) forbiddenSet() map[EffectKind]bool {
	allowed := map[EffectKind]bool{}
	for _, e := range p.Allowed {
		allowed[e] = true
	}
	// Declared effects are, by definition, allowed for this operation.
	for _, e := range p.Declared {
		allowed[e] = true
	}
	out := map[EffectKind]bool{}
	for _, e := range baselineForbidden {
		if !allowed[e] {
			out[e] = true
		}
	}
	for _, e := range p.Forbidden {
		out[e] = true
	}
	return out
}

// DefaultProfiles maps an operation to its contract. bash/exec is intentionally
// broad (it may read/write/connect) -- the residual hard case where the contract
// is nearly vacuous and we fall back to command semantics -- but even bash is
// still bound by the baseline (foreign-secret read + metadata egress are drift
// for ANY operation). Structured operations (file_read, install) have tight
// contracts and are where the diff earns its keep.
func DefaultProfiles() map[string]Profile {
	return map[string]Profile{
		"file_read": {
			Operation: "file_read",
			Declared:  []EffectKind{EffectFileRead},
			Forbidden: []EffectKind{EffectFileWrite, EffectNetworkConnect},
		},
		"file_write": {
			Operation: "file_write",
			Declared:  []EffectKind{EffectFileWrite},
			Allowed:   []EffectKind{EffectFileRead},
		},
		"exec": {
			Operation: "exec",
			Declared:  []EffectKind{EffectProcessExec},
			Allowed:   []EffectKind{EffectFileRead, EffectFileWrite, EffectNetworkConnect},
		},
		"install": {
			// A dependency install runs a process, writes into the workspace, and
			// connects to a package registry. It has NO business reading foreign
			// secrets or hitting the metadata IP -- those stay baseline-forbidden.
			Operation: "install",
			Declared:  []EffectKind{EffectProcessExec, EffectFileWrite, EffectNetworkConnect},
		},
	}
}

// inferOperation classifies a tool_call command / message body into an operation
// key for the profile table. Structured labels (from hooksbridge.proposedEvent:
// "read X" / "write X") map directly; a raw shell/python command maps to exec or,
// when it looks like a dependency install, install.
func inferOperation(label string) string {
	l := strings.ToLower(strings.TrimSpace(label))
	switch {
	case strings.HasPrefix(l, "read "):
		return "file_read"
	case strings.HasPrefix(l, "write "):
		return "file_write"
	case isInstallCommand(l):
		return "install"
	default:
		return "exec"
	}
}

func isInstallCommand(l string) bool {
	for _, m := range []string{"pip install", "pip3 install", "npm install", "npm i ", "poetry add", "uv pip install", "setup.py install", "yarn add", "go install"} {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// profileFor returns the profile for an operation, defaulting to exec.
func profileFor(profiles map[string]Profile, operation string) Profile {
	if p, ok := profiles[operation]; ok {
		return p
	}
	return profiles["exec"]
}
