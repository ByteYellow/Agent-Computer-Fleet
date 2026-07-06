package provenance

const graphLensSchemaVersion = "agentprovenance.graph_lens/v1"

var availableGraphLenses = []string{
	"default",
	"security",
	"process",
	"file-artifact",
	"network-egress",
	"data-flow-taint",
	"agent-intent",
	"orchestration",
	"trust-origin",
	"sandbox-boundary",
}

type GraphLensOptions struct {
	RunID    string
	Lens     string
	Focus    string
	Overlays []string
	Limit    int
	Detail   string
}

type GraphLensManifest struct {
	SchemaVersion   string             `json:"schema_version"`
	RunID           string             `json:"run_id"`
	Lens            string             `json:"lens"`
	AvailableLenses []string           `json:"available_lenses"`
	Query           GraphLensQuery     `json:"query"`
	Summary         []string           `json:"summary"`
	Nodes           []GraphLensNode    `json:"nodes"`
	Edges           []GraphLensEdge    `json:"edges"`
	DerivedEdges    []GraphLensEdge    `json:"derived_edges,omitempty"`
	Overlays        []GraphLensOverlay `json:"overlays,omitempty"`
}

type GraphLensQuery struct {
	Focus         string   `json:"focus,omitempty"`
	Overlays      []string `json:"overlays,omitempty"`
	Limit         int      `json:"limit"`
	Detail        string   `json:"detail"`
	Truncated     bool     `json:"truncated"`
	NodeCount     int      `json:"node_count"`
	EdgeCount     int      `json:"edge_count"`
	Derived       int      `json:"derived_edge_count"`
	RawEventCount int      `json:"raw_event_count"`
	OmittedNodes  int      `json:"omitted_nodes,omitempty"`
	OmittedEdges  int      `json:"omitted_edges,omitempty"`
	LensRules     []string `json:"lens_rules"`
	LayoutHint    string   `json:"layout_hint"`
}

type GraphLensNode struct {
	ID          string         `json:"id"`
	Kind        string         `json:"kind"`
	Subtype     string         `json:"subtype,omitempty"`
	Label       string         `json:"label"`
	TrustOrigin string         `json:"trust_origin,omitempty"`
	Risk        string         `json:"risk,omitempty"`
	Data        map[string]any `json:"data,omitempty"`
}

type GraphLensEdge struct {
	ID             string         `json:"id,omitempty"`
	FromID         string         `json:"from_id"`
	ToID           string         `json:"to_id"`
	EdgeType       string         `json:"edge_type"`
	SourceEventID  string         `json:"source_event_id,omitempty"`
	CreatedAt      string         `json:"created_at,omitempty"`
	Derived        bool           `json:"derived"`
	DerivationRule string         `json:"derivation_rule,omitempty"`
	Confidence     float64        `json:"confidence,omitempty"`
	EvidenceRefs   []string       `json:"evidence_refs,omitempty"`
	Data           map[string]any `json:"data,omitempty"`
}

type GraphLensOverlay struct {
	TargetID string         `json:"target_id"`
	Kind     string         `json:"kind"`
	Label    string         `json:"label"`
	Severity string         `json:"severity,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
}

type lensEvent struct {
	ID          string
	NodeID      string
	Type        string
	ProcessID   string
	ToolCallID  string
	SessionID   string
	SnapshotID  string
	PID         int64
	PPID        int64
	Source      string
	Payload     string
	CreatedAt   string
	Path        string
	Destination string
	TGID        int64
}

type processGroup struct {
	toolCall string
	pids     map[int64]bool
	events   map[string]int
	shells   int
	python   int
	git      int
	packageM int
	risky    int
	writes   int
	egress   int
}

type ruleGroup struct {
	count     int
	decision  string
	severity  string
	action    string
	evidence  []string
	eventType string
}
