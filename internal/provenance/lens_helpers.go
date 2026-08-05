package provenance

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func lensEventLabel(ev lensEvent) string {
	switch ev.Type {
	case "secret_path", "file_open", "file_write":
		if p := shortPathTail(ev.Path); p != "" {
			return ev.Type + " " + p
		}
	case "metadata_ip", "private_cidr", "network_connect", "dns_query":
		if ev.Type == "network_connect" && ev.Source == "endpoint_capture" {
			decision := payloadString(ev.Payload, "policy_decision", "decision", "action")
			if decision == "deny" || decision == "blocked" {
				decision = "BLOCKED"
			} else if decision == "" {
				decision = "endpoint egress"
			}
			path := payloadString(ev.Payload, "path")
			if path != "" && ev.Destination != "" {
				return fmt.Sprintf("%s %s -> %s", decision, path, ev.Destination)
			}
			if ev.Destination != "" {
				return fmt.Sprintf("%s -> %s", decision, ev.Destination)
			}
		}
		if ev.Destination != "" {
			return ev.Type + " " + ev.Destination
		}
	case "execve":
		if c := payloadString(ev.Payload, "command", "cmdline", "comm"); c != "" {
			return shortLabel(cleanExecCommand(c), ev.Type)
		}
	}
	return ev.Type
}

// cleanExecCommand strips the AgentProvenance record-wrapper prefix the sensor
// captures ahead of the real argv (".../agentprovenance <scenario> <real cmd…>"),
// so an execve reads as "python3 ../pysnake-helper/setup" instead of the jumbled
// wrapper+argv concatenation.
func cleanExecCommand(c string) string {
	toks := strings.Fields(c)
	for i, t := range toks {
		if strings.HasSuffix(t, "/agentprovenance") || t == "agentprovenance" {
			if i+2 < len(toks) { // skip the binary + the scenario arg
				return strings.Join(toks[i+2:], " ")
			}
		}
	}
	return c
}

// shortPathTail returns the last two path segments (".aws/credentials"), enough to
// identify the file without the noisy absolute prefix.
func shortPathTail(p string) string {
	p = strings.TrimRight(p, "/")
	if p == "" {
		return ""
	}
	segs := strings.Split(p, "/")
	if len(segs) >= 2 {
		return segs[len(segs)-2] + "/" + segs[len(segs)-1]
	}
	return segs[len(segs)-1]
}

func payloadString(payload string, keys ...string) string {
	var top map[string]any
	if json.Unmarshal([]byte(payload), &top) != nil {
		return ""
	}
	if inner, ok := top["payload"].(map[string]any); ok {
		top = inner
	}
	if raw, ok := top["raw"].(map[string]any); ok {
		top = raw
	}
	for _, key := range keys {
		if v, ok := top[key]; ok {
			switch typed := v.(type) {
			case string:
				return typed
			case float64:
				return fmt.Sprintf("%.0f", typed)
			}
		}
	}
	return ""
}

func sortedBoolKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func sortedStringKeys[T any](values map[string]T) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// lensEventsInOrder returns the events sorted by (created_at, node id). Summary
// builders must iterate events through this instead of ranging the map: they
// accumulate evidence_refs, truncate to a cap, and pick drilldown focuses, so
// Go's random map order would leak into the rendered manifest.
func lensEventsInOrder(events map[string]lensEvent) []lensEvent {
	out := make([]lensEvent, 0, len(events))
	for _, ev := range events {
		out = append(out, ev)
	}
	sortLensEventsByTime(out)
	return out
}

// lensNodesInOrder is lensEventsInOrder's counterpart for the node map.
func lensNodesInOrder(nodes map[string]GraphLensNode) []GraphLensNode {
	out := make([]GraphLensNode, 0, len(nodes))
	for _, node := range nodes {
		out = append(out, node)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// sortLensEventsByTime sorts in place by (created_at, node id); the node-id
// tiebreaker keeps derived data-flow pairing stable when timestamps collide.
func sortLensEventsByTime(events []lensEvent) {
	sort.Slice(events, func(i, j int) bool {
		if events[i].CreatedAt != events[j].CreatedAt {
			return events[i].CreatedAt < events[j].CreatedAt
		}
		return events[i].NodeID < events[j].NodeID
	})
}

func capStringSlice(values []string, limit int) []string {
	if limit <= 0 || len(values) <= limit {
		return values
	}
	return append([]string{}, values[:limit]...)
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func stringsFromEdgeData(data map[string]any, key string) []string {
	if data == nil {
		return nil
	}
	value := data[key]
	switch v := value.(type) {
	case []string:
		return append([]string{}, v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func sortedProcessGroupKeys(groups map[string]*processGroup) []string {
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedRuleGroupKeys(groups map[string]*ruleGroup) []string {
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func topEventTypes(counts map[string]int, limit int) []string {
	type pair struct {
		key   string
		count int
	}
	pairs := make([]pair, 0, len(counts))
	for key, count := range counts {
		pairs = append(pairs, pair{key: key, count: count})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return pairs[i].key < pairs[j].key
	})
	if limit > 0 && len(pairs) > limit {
		pairs = pairs[:limit]
	}
	out := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		out = append(out, pair.key)
	}
	return out
}

func sumIntMap(values map[string]int) int {
	total := 0
	for _, value := range values {
		total += value
	}
	return total
}

func filePathCategory(path string) string {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "node_modules/"), strings.Contains(p, ".venv/"), strings.Contains(p, "site-packages/"), strings.Contains(p, "__pycache__/"), strings.Contains(p, ".cache/"):
		return "dependency_cache"
	case strings.HasPrefix(p, "dist/"), strings.HasPrefix(p, "build/"), strings.HasSuffix(p, ".pyc"), strings.HasSuffix(p, ".egg"), strings.HasSuffix(p, ".whl"), strings.HasSuffix(p, ".so"):
		return "build_artifact"
	case strings.Contains(p, ".ssh"), strings.Contains(p, ".aws"), strings.Contains(p, "credential"), strings.Contains(p, "secret"), strings.Contains(p, "token"), strings.HasSuffix(p, ".env"):
		return "secret_or_config"
	case strings.HasSuffix(p, ".py"), strings.HasSuffix(p, ".go"), strings.HasSuffix(p, ".js"), strings.HasSuffix(p, ".ts"), strings.HasSuffix(p, ".tsx"), strings.HasSuffix(p, ".java"), strings.HasSuffix(p, ".rs"), strings.HasSuffix(p, ".md"):
		return "source"
	default:
		return "other"
	}
}

func riskIf(ok bool) string {
	if ok {
		return "high"
	}
	return ""
}

func isHighRisk(risk string) bool {
	switch strings.ToLower(risk) {
	case "high", "critical", "tainted":
		return true
	default:
		return false
	}
}

func stringFromAny(value any) string {
	if value == nil {
		return ""
	}
	if s, ok := value.(string); ok {
		return s
	}
	return fmt.Sprint(value)
}

func valueFromMap(data map[string]any, key string) any {
	if data == nil {
		return nil
	}
	return data[key]
}

func safeGraphID(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.', r == ':':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "unknown"
	}
	if len(out) > 120 {
		return out[:120]
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func shortLabel(value, fallbackValue string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallbackValue
	}
	if len(value) > 48 {
		return value[:45] + "..."
	}
	return value
}

func lensShortRef(ref string) string {
	if idx := strings.LastIndex(ref, "/"); idx >= 0 && idx+1 < len(ref) {
		return ref[idx+1:]
	}
	return ref
}

func fallback(value, fallbackValue string) string {
	if strings.TrimSpace(value) == "" {
		return fallbackValue
	}
	return value
}
