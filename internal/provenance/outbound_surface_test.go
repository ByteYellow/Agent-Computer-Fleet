package provenance

import "testing"

func findSurface(ss []OutboundSurface, channel string) (OutboundSurface, bool) {
	for _, s := range ss {
		if s.ChannelClass == channel {
			return s, true
		}
	}
	return OutboundSurface{}, false
}

// The Grok exfil run must fall out of the generic model as three surfaces — none
// of them hardcoded — with honest data classes: the model turn carries a
// conversation (not a secret), the blocked upload carries source code.
func TestBuildOutboundSurfaces_GrokShape(t *testing.T) {
	obs := []OutboundObservation{
		{Kind: "model_turn", Bytes: 48914, EvidenceRef: "llm_call/ep-21", Time: "t1"},
		{Kind: "artifact_upload", Host: "api.x.ai", Path: "/traces", Bytes: 2668, Blocked: true, IsSourceCode: true, EvidenceRef: "runtime_event/evt-1", Time: "t2"},
		{Kind: "artifact_upload", Host: "api.x.ai", Path: "/traces", Bytes: 9795, Blocked: true, IsSourceCode: true, EvidenceRef: "runtime_event/evt-2", Time: "t3"},
		{Kind: "dns", Host: "api.mixpanel.com", EvidenceRef: "runtime_event/evt-3", Time: "t4"},
	}
	ss := BuildOutboundSurfaces(obs)
	if len(ss) != 3 {
		t.Fatalf("want 3 surfaces, got %d: %+v", len(ss), ss)
	}
	// Most-severe first: source_code (high) before conversation (medium) before
	// DNS-only analytics endpoint evidence (low, data class deliberately unknown).
	if ss[0].ChannelClass != "artifact_storage" || ss[len(ss)-1].ChannelClass != "product_analytics" {
		t.Fatalf("ordering wrong: %s ... %s", ss[0].ChannelClass, ss[len(ss)-1].ChannelClass)
	}

	art, _ := findSurface(ss, "artifact_storage")
	if art.DataClass != "source_code" || art.Decision != "blocked" || art.Risk != "high" {
		t.Errorf("artifact: got data=%s decision=%s risk=%s", art.DataClass, art.Decision, art.Risk)
	}
	if art.RequestCount != 2 || art.Bytes != 2668+9795 || art.RiskCount != 2 {
		t.Errorf("artifact aggregation: count=%d bytes=%d risk=%d", art.RequestCount, art.Bytes, art.RiskCount)
	}
	if art.DestinationOwner != "xAI" || art.EvidenceLevel != "payload_observed" {
		t.Errorf("artifact owner/evidence: %s / %s", art.DestinationOwner, art.EvidenceLevel)
	}

	model, _ := findSurface(ss, "model_inference")
	if model.DataClass != "conversation" || model.Risk != "medium" {
		t.Errorf("model: got data=%s risk=%s (must not be stamped secret)", model.DataClass, model.Risk)
	}
	if model.EvidenceLevel != "payload_observed" || model.DestinationOwner != "unknown" {
		t.Errorf("model evidence/owner: %s / %s (host not recorded in bundle)", model.EvidenceLevel, model.DestinationOwner)
	}

	pa, _ := findSurface(ss, "product_analytics")
	if pa.DataClass != "unknown" || pa.EvidenceLevel != "dns_only" || pa.Risk != "low" {
		t.Errorf("analytics: data=%s evidence=%s risk=%s", pa.DataClass, pa.EvidenceLevel, pa.Risk)
	}
	if pa.DestinationOwner != "Mixpanel" {
		t.Errorf("analytics owner: %s", pa.DestinationOwner)
	}
}

func TestBuildOutboundSurfaces_AnalyticsPayloadCanProveBehavioralMetadata(t *testing.T) {
	ss := BuildOutboundSurfaces([]OutboundObservation{{
		Kind: "analytics_payload", Host: "api.mixpanel.com", Bytes: 512,
		HasBehavioralMetadata: true, EvidenceRef: "runtime_event/evt-track",
	}})
	if len(ss) != 1 || ss[0].ChannelClass != "product_analytics" || ss[0].DataClass != "behavioral_metadata" || ss[0].EvidenceLevel != "payload_observed" {
		t.Fatalf("inspected analytics payload classification = %+v", ss)
	}
}

func TestBuildOutboundSurfaces_DNSSupportDoesNotCreateDuplicateOwnerCard(t *testing.T) {
	ss := BuildOutboundSurfaces([]OutboundObservation{
		{Kind: "model_turn", Host: "api.x.ai", Bytes: 100, EvidenceRef: "llm_call/1"},
		{Kind: "dns", Host: "cli-chat-proxy.grok.com", EvidenceRef: "runtime_event/dns-1"},
		{Kind: "dns", Host: "api.mixpanel.com", EvidenceRef: "runtime_event/dns-2"},
	})
	if len(ss) != 2 {
		t.Fatalf("xAI DNS should be supporting evidence, Mixpanel DNS should remain: %+v", ss)
	}
	if _, ok := findSurface(ss, "unknown_egress"); ok {
		t.Fatalf("strong model evidence must suppress a duplicate xAI DNS surface: %+v", ss)
	}
}

func TestBuildOutboundSurfaces_TelemetryIsNotArtifactStorage(t *testing.T) {
	ss := BuildOutboundSurfaces([]OutboundObservation{{Kind: "telemetry", Host: "api.vendor.example", Bytes: 900}})
	if len(ss) != 1 || ss[0].ChannelClass != "telemetry_service" || ss[0].DataClass != "unknown" {
		t.Fatalf("vendor trace traffic must remain telemetry, got %+v", ss)
	}
}

func TestBuildOutboundSurfaces_Empty(t *testing.T) {
	if ss := BuildOutboundSurfaces(nil); len(ss) != 0 {
		t.Fatalf("no observations must yield no surfaces, got %d", len(ss))
	}
}

// A secret in the payload must escalate the data class regardless of channel.
func TestBuildOutboundSurfaces_SecretEscalates(t *testing.T) {
	ss := BuildOutboundSurfaces([]OutboundObservation{
		{Kind: "model_turn", Bytes: 100, HasSecret: true, EvidenceRef: "llm_call/ep-9"},
	})
	if len(ss) != 1 || ss[0].DataClass != "secret" || ss[0].Risk != "critical" {
		t.Fatalf("secret in model context must be data=secret risk=critical, got %+v", ss)
	}
}

func TestBuildOutboundSurfaces_OneRouteKeepsMultipleDataClasses(t *testing.T) {
	ss := BuildOutboundSurfaces([]OutboundObservation{
		{Kind: "model_turn", Host: "api.x.ai", Bytes: 100},
		{Kind: "model_turn", Host: "api.x.ai", Bytes: 200, HasSecret: true},
	})
	if len(ss) != 1 || ss[0].DataClass != "secret" || ss[0].RequestCount != 2 {
		t.Fatalf("one model route should be one card with secret as primary class: %+v", ss)
	}
	if len(ss[0].DataClasses) != 2 || ss[0].DataClasses[0] != "secret" || ss[0].DataClasses[1] != "conversation" {
		t.Fatalf("all route data classes must remain visible: %+v", ss[0].DataClasses)
	}
}

func TestDestinationOwner(t *testing.T) {
	cases := map[string]string{
		"api.x.ai":                  "xAI",
		"cli-chat-proxy.grok.com":   "xAI",
		"api.mixpanel.com":          "Mixpanel",
		"raw.githubusercontent.com": "GitHub",
		"unknown-host.example.org":  "example.org",
		"grok-code-session-traces":  "grok-code-session-traces",
	}
	for host, want := range cases {
		if got := destinationOwner(host); got != want {
			t.Errorf("destinationOwner(%q)=%q want %q", host, got, want)
		}
	}
}

func TestBuildOutboundSurfaces_UnresolvedIPsShareOneCard(t *testing.T) {
	ss := BuildOutboundSurfaces([]OutboundObservation{
		{Kind: "network", Host: "203.0.113.10"},
		{Kind: "network", Host: "198.51.100.20"},
	})
	if len(ss) != 1 || ss[0].DestinationOwner != "unresolved_ip" || len(ss[0].Destinations) != 2 {
		t.Fatalf("unresolved IPs should fold into one route: %+v", ss)
	}
}
