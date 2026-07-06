package provenance

import (
	"sort"
	"strings"
)

func buildDataFlowSummaryEdges(events map[string]lensEvent) []GraphLensEdge {
	sources := make([]lensEvent, 0)
	sinks := make([]lensEvent, 0)
	for _, ev := range events {
		if isSourceEvent(ev.Type, ev.Path) {
			sources = append(sources, ev)
		}
		if isTaintSinkEvent(ev) {
			sinks = append(sinks, ev)
		}
	}
	sortLensEventsByTime(sources)
	sortLensEventsByTime(sinks)
	return deriveAggregatedDataFlowEdges(sources, sinks)
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// buildIntentDAGEdges renders the intent lifecycle as a causal DAG over the REAL
// evidence nodes (no synthetic stage boxes): each node is the actual captured
// object/event -- so clicking it shows its content -- and the ①②③④ stage is just a
// label prefixed onto that real node. Flow: run → ① prompt → LLM call → ② response
// → ③ caused exec(s) → ④ send msg.

func deriveGraphLensEdges(lens string, events map[string]lensEvent, detail string) []GraphLensEdge {
	if lens != "data-flow-taint" && lens != "security" && lens != "default" {
		return nil
	}
	sources := make([]lensEvent, 0)
	sinks := make([]lensEvent, 0)
	for _, ev := range events {
		if isSourceEvent(ev.Type, ev.Path) {
			sources = append(sources, ev)
		}
		if isTaintSinkEvent(ev) {
			sinks = append(sinks, ev)
		}
	}
	sortLensEventsByTime(sources)
	sortLensEventsByTime(sinks)
	if detail == "summary" {
		return deriveAggregatedDataFlowEdges(sources, sinks)
	}
	var derived []GraphLensEdge
	seen := map[string]bool{}
	for _, src := range sources {
		for _, sink := range sinks {
			// A data flow can only run forward in time: the secret must be read
			// before it can leave over the network. Skip sinks that happened at
			// or before the source so we never draw a temporally impossible edge
			// (e.g. an egress that preceded the secret read).
			if src.CreatedAt != "" && sink.CreatedAt != "" && sink.CreatedAt <= src.CreatedAt {
				continue
			}
			_, _, rule, conf := taintFlowScope(src, sink, true)
			if conf == 0 {
				continue
			}
			key := src.NodeID + "|" + sink.NodeID + "|" + rule
			if seen[key] {
				continue
			}
			seen[key] = true
			derived = append(derived, GraphLensEdge{
				ID:       "derived/" + key,
				FromID:   src.NodeID,
				ToID:     sink.NodeID,
				EdgeType: "possible_sensitive_data_flow",
				// Stamp the inferred flow with the sink's time so a time-scrubbed
				// replay surfaces it at the moment the data actually left.
				CreatedAt:      sink.CreatedAt,
				Derived:        true,
				DerivationRule: rule,
				Confidence:     conf,
				EvidenceRefs:   []string{src.NodeID, sink.NodeID},
			})
		}
	}
	return derived
}

func deriveAggregatedDataFlowEdges(sources, sinks []lensEvent) []GraphLensEdge {
	type flowGroup struct {
		fromID       string
		toID         string
		rule         string
		confidence   float64
		createdAt    string
		sourceRefs   map[string]bool
		sinkRefs     map[string]bool
		paths        map[string]bool
		destinations map[string]bool
	}
	groups := map[string]*flowGroup{}
	for _, src := range sources {
		for _, sink := range sinks {
			if src.CreatedAt != "" && sink.CreatedAt != "" && sink.CreatedAt <= src.CreatedAt {
				continue
			}
			scopeID, scopeKey, baseRule, conf := taintFlowScope(src, sink, false)
			if scopeID == "" {
				continue
			}
			rule := strings.Replace(baseRule, ".v1", ".aggregate.v1", 1)
			toID := "egress_group/" + safeGraphID(scopeKey)
			key := scopeKey + "|" + rule
			group := groups[key]
			if group == nil {
				group = &flowGroup{
					fromID:       scopeID,
					toID:         toID,
					rule:         rule,
					confidence:   conf,
					sourceRefs:   map[string]bool{},
					sinkRefs:     map[string]bool{},
					paths:        map[string]bool{},
					destinations: map[string]bool{},
				}
				groups[key] = group
			}
			if group.createdAt == "" || (sink.CreatedAt != "" && sink.CreatedAt > group.createdAt) {
				group.createdAt = sink.CreatedAt
			}
			group.sourceRefs[src.NodeID] = true
			group.sinkRefs[sink.NodeID] = true
			if src.Path != "" {
				group.paths[src.Path] = true
			}
			if sink.Destination != "" {
				group.destinations[sink.Destination] = true
			}
		}
	}
	out := make([]GraphLensEdge, 0, len(groups))
	for key, group := range groups {
		refs := append(sortedBoolKeys(group.sourceRefs), sortedBoolKeys(group.sinkRefs)...)
		out = append(out, GraphLensEdge{
			ID:             "derived/" + safeGraphID(key),
			FromID:         group.fromID,
			ToID:           group.toID,
			EdgeType:       "possible_sensitive_data_flow_summary",
			CreatedAt:      group.createdAt,
			Derived:        true,
			DerivationRule: group.rule,
			Confidence:     group.confidence,
			EvidenceRefs:   capStringSlice(refs, 80),
			Data: map[string]any{
				"source_count":       len(group.sourceRefs),
				"sink_count":         len(group.sinkRefs),
				"omitted_evidence":   maxInt(0, len(refs)-80),
				"sensitive_paths":    capStringSlice(sortedBoolKeys(group.paths), 12),
				"destinations":       capStringSlice(sortedBoolKeys(group.destinations), 12),
				"source_event_count": len(group.sourceRefs),
				"sink_event_count":   len(group.sinkRefs),
			},
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt < out[j].CreatedAt
		}
		return out[i].ID < out[j].ID
	})
	return out
}
