package provenance

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

func BuildGraphLens(db *sql.DB, opts GraphLensOptions) (GraphLensManifest, error) {
	opts.RunID = strings.TrimSpace(opts.RunID)
	if opts.RunID == "" {
		return GraphLensManifest{}, fmt.Errorf("--run is required")
	}
	lens := normalizeGraphLens(opts.Lens)
	detail := normalizeGraphLensDetail(opts.Detail)
	if opts.Limit <= 0 {
		// 350 keeps the graph light enough to lay out + render fast on a lens
		// switch while still fitting all the prioritized semantic edges (product
		// lineage + policy/risk/response); the runtime_event/process skeleton is
		// what gets trimmed, and it is the least informative part.
		opts.Limit = 350
	}
	nodes, events, err := graphLensNodes(db, opts.RunID)
	if err != nil {
		return GraphLensManifest{}, err
	}
	edges, err := graphLensEdges(db, opts.RunID)
	if err != nil {
		return GraphLensManifest{}, err
	}
	derived := deriveGraphLensEdges(lens, events, detail)
	allEdges := append(edges, derived...)
	filteredEdges, summarized := summaryLensEdges(opts.RunID, lens, opts.Focus, detail, nodes, events, allEdges)
	if !summarized {
		filteredEdges = filterGraphLensEdges(lens, opts.Focus, detail, nodes, events, allEdges)
	}
	manifest := GraphLensManifest{
		SchemaVersion:   graphLensSchemaVersion,
		RunID:           opts.RunID,
		Lens:            lens,
		AvailableLenses: append([]string{}, availableGraphLenses...),
		Query: GraphLensQuery{
			Focus:         opts.Focus,
			Overlays:      cleanOverlays(opts.Overlays),
			Limit:         opts.Limit,
			Detail:        detail,
			RawEventCount: len(events),
			LensRules:     graphLensRules(lens),
			LayoutHint:    graphLensLayout(lens),
		},
	}
	// Prioritize edges so that when the budget truncates the runtime_event/
	// runtime_process BULK, edges incident to semantically important nodes
	// (policy_decision / response_action / risk_signal / file / artifact /
	// tool_call / snapshot / attempt / rollout / process) survive. Without this
	// the bulk ate the whole edge budget and those nodes were returned but
	// ORPHANED -- appearing as disconnected, mis-positioned floaters.
	prioritizeLensEdges(filteredEdges, nodes)
	manifest.Edges, manifest.DerivedEdges, manifest.Query.Truncated = splitAndLimitLensEdges(filteredEdges, opts.Limit)
	// Build the visible node set from the RETURNED edges only, so no node is ever
	// shown without a connecting edge. (Previously `used` was built from every
	// pre-truncation edge, so a node whose only edge fell past the cut still
	// appeared -- floating.) Genuinely edgeless nodes are dropped rather than
	// left disconnected; drill/focus recovers detail for a specific node.
	used := map[string]bool{}
	for _, edge := range append(append([]GraphLensEdge{}, manifest.Edges...), manifest.DerivedEdges...) {
		if edge.EdgeType == "possible_sensitive_data_flow_summary" && edge.ToID != "" {
			nodes[edge.ToID] = egressGroupNode(edge)
		}
		used[edge.FromID] = true
		used[edge.ToID] = true
		// NOTE: the edge's SourceEventID is intentionally NOT added as a node --
		// it is reachable via the edge's source_event_id for drill-down, and
		// adding it as a bare node (with no edge of its own returned) reintroduces
		// a floating runtime_event. Only actual edge endpoints become nodes.
	}
	if opts.Focus != "" {
		used[opts.Focus] = true
	}
	manifest.Nodes = sortedLensNodes(nodes, used)
	manifest.Query.NodeCount = len(manifest.Nodes)
	manifest.Query.EdgeCount = len(manifest.Edges) + len(manifest.DerivedEdges)
	manifest.Query.Derived = len(manifest.DerivedEdges)
	manifest.Query.OmittedNodes = maxInt(0, len(nodes)-manifest.Query.NodeCount)
	manifest.Query.OmittedEdges = maxInt(0, len(allEdges)-manifest.Query.EdgeCount)
	manifest.Overlays = buildGraphLensOverlays(nodes, manifest.Nodes, manifest.Query.Overlays)
	manifest.Summary = []string{
		fmt.Sprintf("lens=%s layout=%s", manifest.Lens, manifest.Query.LayoutHint),
		fmt.Sprintf("detail=%s raw_events=%d nodes=%d edges=%d derived_edges=%d omitted_nodes=%d omitted_edges=%d",
			manifest.Query.Detail, manifest.Query.RawEventCount, manifest.Query.NodeCount, len(manifest.Edges), len(manifest.DerivedEdges),
			manifest.Query.OmittedNodes, manifest.Query.OmittedEdges),
	}
	return manifest, nil
}

func GraphLensJSON(db *sql.DB, opts GraphLensOptions, out io.Writer) error {
	manifest, err := BuildGraphLens(db, opts)
	if err != nil {
		return err
	}
	return PrintGraphLensManifestJSON(out, manifest)
}

func PrintGraphLensManifestJSON(out io.Writer, manifest GraphLensManifest) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(manifest)
}

func GraphLens(db *sql.DB, opts GraphLensOptions, out io.Writer) error {
	manifest, err := BuildGraphLens(db, opts)
	if err != nil {
		return err
	}
	return PrintGraphLensManifest(out, manifest)
}

func PrintGraphLensManifest(out io.Writer, manifest GraphLensManifest) error {
	fmt.Fprintf(out, "graph_lens run=%s lens=%s schema=%s nodes=%d edges=%d derived=%d layout=%s truncated=%t\n",
		manifest.RunID, manifest.Lens, manifest.SchemaVersion, manifest.Query.NodeCount,
		len(manifest.Edges), len(manifest.DerivedEdges), manifest.Query.LayoutHint, manifest.Query.Truncated)
	for _, line := range manifest.Summary {
		fmt.Fprintf(out, "  summary=%s\n", line)
	}
	for _, edge := range manifest.DerivedEdges {
		fmt.Fprintf(out, "  derived_edge=%s %s -> %s confidence=%.2f rule=%s evidence=%s\n",
			edge.EdgeType, edge.FromID, edge.ToID, edge.Confidence, edge.DerivationRule, strings.Join(edge.EvidenceRefs, ","))
	}
	for _, edge := range manifest.Edges {
		fmt.Fprintf(out, "  edge=%s %s -> %s source_event=%s\n", edge.EdgeType, edge.FromID, edge.ToID, edge.SourceEventID)
	}
	return nil
}

func normalizeGraphLens(lens string) string {
	lens = strings.ToLower(strings.TrimSpace(lens))
	if lens == "" {
		return "default"
	}
	for _, allowed := range availableGraphLenses {
		if lens == allowed {
			return lens
		}
	}
	return "default"
}

func normalizeGraphLensDetail(detail string) string {
	switch strings.ToLower(strings.TrimSpace(detail)) {
	case "raw", "expanded":
		return strings.ToLower(strings.TrimSpace(detail))
	default:
		return "summary"
	}
}
