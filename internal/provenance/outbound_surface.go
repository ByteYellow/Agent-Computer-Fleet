package provenance

import (
	"net"
	"sort"
	"strings"
)

// OutboundSurface is one aggregated "where data left (or tried to leave) the box"
// summary. Cards are generated from evidence, never hardcoded per demo: any run
// that produces outbound observations yields the surfaces those observations
// imply, and a run with no egress yields none. See BuildOutboundSurfaces.
type OutboundSurface struct {
	ChannelClass     string   `json:"channel_class"`     // model_inference|artifact_storage|product_analytics|external_api|database|tool_service|unknown_egress
	DataClass        string   `json:"data_class"`        // secret|source_code|conversation|behavioral_metadata|unknown
	Destination      string   `json:"destination"`       // observed host/endpoint (may be empty/unknown)
	DestinationOwner string   `json:"destination_owner"` // resolved via the owner registry
	EvidenceLevel    string   `json:"evidence_level"`    // payload_observed|connection_observed|dns_only|documented
	Decision         string   `json:"decision"`          // observed|allowed|blocked|redacted
	Risk             string   `json:"risk"`              // critical|high|medium|low (falls out of data_class+decision)
	RequestCount     int      `json:"request_count"`
	Bytes            int      `json:"bytes"`
	RiskCount        int      `json:"risk_count"`
	FirstSeen        string   `json:"first_seen"`
	LastSeen         string   `json:"last_seen"`
	Destinations     []string `json:"destinations"`  // all distinct hosts folded into this card
	EvidenceRefs     []string `json:"evidence_refs"` // node/event ids for the click-through DAG
	Note             string   `json:"note,omitempty"`
}

// OutboundObservation is one normalized egress observation. The dashboard builds
// these from whatever the run recorded (endpoint captures, llm turns, dns/connect
// events); BuildOutboundSurfaces stays free of any storage or vendor knowledge
// beyond the owner registry, so it is unit-testable in isolation.
type OutboundObservation struct {
	Kind         string // model_turn|artifact_upload|dns|network
	Host         string
	Path         string
	Bytes        int
	Blocked      bool
	Redacted     bool
	Risky        bool // metadata_ip / private_cidr / taint sink
	IsSourceCode bool // git bundle / whole-repo payload
	HasSecret    bool // canary / secret markers observed in the payload
	EvidenceRef  string
	Time         string
	Note         string
}

// BuildOutboundSurfaces classifies each observation into (channel, data, owner,
// decision) and aggregates by that composite key so 200 same-class requests
// collapse to one card carrying the totals. Cards are ordered most-severe first.
func BuildOutboundSurfaces(obs []OutboundObservation) []OutboundSurface {
	byKey := map[string]*OutboundSurface{}
	dests := map[string]map[string]bool{}
	order := []string{}
	for _, o := range obs {
		cc := outboundChannelClass(o)
		dc := outboundDataClass(o, cc)
		owner, dest := outboundDestination(o)
		key := cc + "|" + owner + "|" + dc + "|" + outboundDecision(o)
		s := byKey[key]
		if s == nil {
			s = &OutboundSurface{
				ChannelClass: cc, DataClass: dc, DestinationOwner: owner, Destination: dest,
				EvidenceLevel: outboundEvidenceLevel(o), Decision: outboundDecision(o),
				FirstSeen: o.Time, LastSeen: o.Time, Note: o.Note,
			}
			byKey[key] = s
			dests[key] = map[string]bool{}
			order = append(order, key)
		}
		s.RequestCount++
		s.Bytes += o.Bytes
		if o.Risky || o.Blocked {
			s.RiskCount++
		}
		s.EvidenceLevel = strongerEvidence(s.EvidenceLevel, outboundEvidenceLevel(o))
		if o.Time != "" {
			if s.FirstSeen == "" || o.Time < s.FirstSeen {
				s.FirstSeen = o.Time
			}
			if o.Time > s.LastSeen {
				s.LastSeen = o.Time
			}
		}
		if dest != "" {
			dests[key][dest] = true
		}
		if o.EvidenceRef != "" && len(s.EvidenceRefs) < 64 {
			s.EvidenceRefs = append(s.EvidenceRefs, o.EvidenceRef)
		}
		if s.Note == "" && o.Note != "" {
			s.Note = o.Note
		}
	}
	out := make([]OutboundSurface, 0, len(order))
	for _, key := range order {
		s := byKey[key]
		s.Destinations = sortedBoolKeys(dests[key])
		if s.Destination == "" && len(s.Destinations) > 0 {
			s.Destination = s.Destinations[0]
		}
		s.Risk = outboundRisk(s.DataClass, s.RiskCount > 0)
		out = append(out, *s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := outboundRiskRank(out[i].Risk), outboundRiskRank(out[j].Risk); ri != rj {
			return ri > rj
		}
		return out[i].ChannelClass < out[j].ChannelClass
	})
	return out
}

func outboundChannelClass(o OutboundObservation) string {
	switch o.Kind {
	case "model_turn":
		return "model_inference"
	case "artifact_upload":
		return "artifact_storage"
	}
	owner, _ := outboundDestination(o)
	switch {
	case outboundAnalyticsOwners[owner]:
		return "product_analytics"
	case outboundAPIOwners[owner]:
		return "external_api"
	default:
		return "unknown_egress"
	}
}

func outboundDataClass(o OutboundObservation, channel string) string {
	switch {
	case o.HasSecret:
		return "secret"
	case o.IsSourceCode:
		return "source_code"
	}
	switch channel {
	case "model_inference":
		return "conversation"
	case "product_analytics":
		return "behavioral_metadata"
	}
	return "unknown"
}

func outboundEvidenceLevel(o OutboundObservation) string {
	switch o.Kind {
	case "model_turn":
		return "payload_observed"
	case "artifact_upload":
		if o.Bytes > 0 {
			return "payload_observed"
		}
		return "connection_observed"
	case "dns":
		return "dns_only"
	default:
		return "connection_observed"
	}
}

func outboundDecision(o OutboundObservation) string {
	switch {
	case o.Blocked:
		return "blocked"
	case o.Redacted:
		return "redacted"
	default:
		return "observed"
	}
}

// outboundDestination resolves the owner + a display host. An empty host means the
// run did not record the endpoint (e.g. a model turn whose upstream the capture
// proxy did not write) — reported honestly as unknown rather than inferred.
func outboundDestination(o OutboundObservation) (owner, dest string) {
	host := strings.ToLower(strings.TrimSpace(o.Host))
	if host == "" {
		if o.Kind == "model_turn" {
			return "unknown", ""
		}
		return "unknown", ""
	}
	return destinationOwner(host), o.Host
}

// outboundOwnerRegistry is the single place vendor knowledge lives: a host suffix
// maps to the party that controls the destination. Extend this table to teach the
// dashboard about new destinations without touching any classifier.
var outboundOwnerRegistry = []struct{ Suffix, Owner string }{
	{"x.ai", "xAI"}, {"grok.com", "xAI"},
	{"openai.com", "OpenAI"}, {"anthropic.com", "Anthropic"},
	{"googleapis.com", "Google"}, {"google.com", "Google"},
	{"mixpanel.com", "Mixpanel"}, {"segment.io", "Segment"}, {"segment.com", "Segment"},
	{"amplitude.com", "Amplitude"}, {"sentry.io", "Sentry"}, {"datadoghq.com", "Datadog"},
	{"posthog.com", "PostHog"}, {"statsig.com", "Statsig"},
	{"github.com", "GitHub"}, {"githubusercontent.com", "GitHub"}, {"githubcopilot.com", "GitHub"},
	{"gitlab.com", "GitLab"}, {"slack.com", "Slack"}, {"bitbucket.org", "Bitbucket"},
}

var outboundAnalyticsOwners = map[string]bool{
	"Mixpanel": true, "Segment": true, "Amplitude": true, "Sentry": true,
	"Datadog": true, "PostHog": true, "Statsig": true,
}

var outboundAPIOwners = map[string]bool{
	"GitHub": true, "GitLab": true, "Slack": true, "Bitbucket": true,
}

func destinationOwner(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	for _, r := range outboundOwnerRegistry {
		if h == r.Suffix || strings.HasSuffix(h, "."+r.Suffix) {
			return r.Owner
		}
	}
	return registrableDomain(h)
}

// registrableDomain returns the last two dotted labels (a rough eTLD+1) so an
// unknown host still groups by its apex domain. Bucket names / IPs with no dot are
// returned as-is.
func registrableDomain(host string) string {
	host = strings.Trim(strings.ToLower(host), ".")
	if host == "" {
		return "unknown"
	}
	if net.ParseIP(host) != nil { // a bare IP has no registrable domain; keep it whole
		return host
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return host
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// outboundRisk derives severity from what left the box, not from any per-demo tuning:
// a secret is the worst, whole source code next, a conversation moderate, telemetry low.
func outboundRisk(dataClass string, risky bool) string {
	switch dataClass {
	case "secret":
		return "critical"
	case "source_code":
		return "high"
	case "conversation":
		return "medium"
	case "behavioral_metadata":
		return "low"
	default:
		if risky {
			return "medium"
		}
		return "low"
	}
}

func outboundRiskRank(risk string) int {
	switch risk {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

func strongerEvidence(a, b string) string {
	rank := func(s string) int {
		switch s {
		case "payload_observed":
			return 4
		case "connection_observed":
			return 3
		case "dns_only":
			return 2
		case "documented":
			return 1
		}
		return 0
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}
