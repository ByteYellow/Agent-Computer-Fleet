package provenance

import (
	"fmt"
	"net/netip"
	"strings"
)

func isSecurityKind(kind string) bool {
	return kind == "policy_decision" || kind == "risk_signal" || kind == "response_action"
}

func isNetworkEvent(eventType string) bool {
	switch eventType {
	case "network_connect", "metadata_ip", "private_cidr", "dns_query", "tls_write", "tls_read":
		return true
	default:
		return false
	}
}

func isSourceEvent(eventType, path string) bool {
	if eventType == "secret_path" {
		return true
	}
	if eventType != "file_open" {
		return false
	}
	path = strings.ToLower(path)
	return strings.Contains(path, ".ssh") || strings.Contains(path, ".aws") || strings.Contains(path, "credential") || strings.Contains(path, "secret") || strings.Contains(path, "token")
}

// taintFlowScope returns the scope a (source, sink) pair shares for a sensitive
// data-flow edge — the from-node, a grouping key, the rule and confidence. It
// prefers the OS pid (an exfiltration happens within ONE process, and the
// correlated process_id can be a single coarse id for a whole captured run), then
// falls back to process_id and tool_call for events without a pid. Returns conf=0
// when the pair shares no scope (so they are not a flow).
func taintFlowScope(src, sink lensEvent, allowFallback bool) (fromNode, scopeKey, rule string, conf float64) {
	switch {
	case src.PID > 0 && sink.PID > 0:
		if src.PID != sink.PID {
			return "", "", "", 0
		}
		return fmt.Sprintf("runtime_process/pid/%d", src.PID), fmt.Sprintf("pid:%d", src.PID),
			"dataflow.same_process.secret_to_network.v1", 0.82
	case (allowFallback || endpointCorrelationAvailable(src, sink)) && src.ProcessID != "" && src.ProcessID == sink.ProcessID:
		// Endpoint captures (for example a rustls agent observed at its controlled
		// HTTP endpoint) do not have a kernel PID. They inherit the process_id
		// chosen while joining the endpoint request to the kernel evidence. Allow
		// this narrow fallback so the real source -> payload -> egress chain remains
		// visible, while ordinary coarse process IDs still require explicit opt-in.
		confidence := 0.8
		rule := "dataflow.same_process.secret_to_network.v1"
		if !allowFallback {
			confidence = 0.74
			rule = "dataflow.endpoint_process_join.secret_to_payload.v1"
		}
		return src.ProcessID, "process:" + src.ProcessID, rule, confidence
	case allowFallback && src.ToolCallID != "" && src.ToolCallID == sink.ToolCallID:
		return src.ToolCallID, "tool_call:" + src.ToolCallID, "dataflow.same_tool_call.risky_egress.v1", 0.52
	}
	return "", "", "", 0
}

func endpointCorrelationAvailable(src, sink lensEvent) bool {
	return src.Source == "endpoint_capture" || sink.Source == "endpoint_capture"
}

// isLoopbackDestination reports whether a destination is the local host (e.g. the
// systemd-resolved DNS stub 127.0.0.53) — local traffic is not exfiltration.
func isLoopbackDestination(destination string) bool {
	host := strings.Trim(strings.TrimSpace(destination), "[]")
	if i := strings.LastIndex(host, ":"); i > 0 && strings.Count(host, ":") == 1 {
		host = host[:i]
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

func isTaintSinkEvent(ev lensEvent) bool {
	// A connection to localhost is not exfiltration, even if an upstream classifier
	// tagged it private_cidr (127.0.0.0/8 is loopback, not an RFC1918 private net).
	if isLoopbackDestination(ev.Destination) {
		return false
	}
	switch ev.Type {
	case "metadata_ip", "private_cidr", "network_deny", "egress_deny":
		return true
	case "network_connect", "tls_write":
		if isMetadataOrPrivateDestination(ev.Destination) {
			return true
		}
		decision := strings.ToLower(payloadString(ev.Payload, "decision", "policy_decision", "action"))
		severity := strings.ToLower(payloadString(ev.Payload, "severity", "risk", "level"))
		return decision == "deny" || decision == "quarantine" || decision == "kill" || severity == "high" || severity == "critical"
	default:
		return false
	}
}

func isMetadataOrPrivateDestination(destination string) bool {
	destination = strings.TrimSpace(destination)
	if destination == "" {
		return false
	}
	host := strings.Trim(destination, "[]")
	if i := strings.LastIndex(host, ":"); i > 0 && strings.Count(host, ":") == 1 {
		host = host[:i]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return strings.EqualFold(host, "169.254.169.254")
	}
	if addr.Is4() && addr.String() == "169.254.169.254" {
		return true
	}
	return addr.IsPrivate()
}

func isBoundaryEvent(eventType string) bool {
	switch eventType {
	case "setuid", "setgid", "ptrace", "abnormal_process_tree", "file_rename", "file_unlink", "metadata_ip", "private_cidr":
		return true
	default:
		return false
	}
}

func riskForEventType(eventType string) string {
	switch eventType {
	case "metadata_ip", "private_cidr", "secret_path", "abnormal_process_tree", "setuid", "setgid", "ptrace":
		return "high"
	case "file_rename", "file_unlink":
		return "medium"
	default:
		return ""
	}
}

func riskForLensEvent(ev lensEvent) string {
	if ev.Type == "private_cidr" && isLoopbackDestination(ev.Destination) {
		return ""
	}
	return riskForEventType(ev.Type)
}

func isRiskyNetworkSummaryEvent(ev lensEvent) bool {
	if !isNetworkEvent(ev.Type) {
		return false
	}
	if isLoopbackDestination(ev.Destination) {
		return false
	}
	return isTaintSinkEvent(ev) || riskForLensEvent(ev) != ""
}

func riskForDecision(decision string) string {
	switch strings.ToLower(decision) {
	case "deny", "kill", "quarantine", "taint_snapshot":
		return "high"
	case "audit":
		return "medium"
	default:
		return ""
	}
}
