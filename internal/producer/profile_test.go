package producer

import "testing"

func TestProfileCapabilitiesAreDeclaredHonestly(t *testing.T) {
	// Every profile must declare all three layers so the capability report never
	// leaves a layer's coverage unstated.
	for _, p := range Profiles() {
		for _, layer := range []Layer{LayerSystemTelemetry, LayerModelIntent, LayerAppContext} {
			cap, ok := p.Layers[layer]
			if !ok {
				t.Fatalf("profile %q does not declare layer %q", p.Name, layer)
			}
			if cap.Coverage != CoverageFull && cap.Note == "" {
				t.Errorf("profile %q layer %q is %q but gives no note explaining the limit", p.Name, layer, cap.Coverage)
			}
		}
	}
}

func TestK8sDaemonsetIsHonestAboutModelIntentAndScope(t *testing.T) {
	p := K8sDaemonset()
	if p.ScopeMode != ScopeModeCgroup {
		t.Fatalf("k8s-daemonset scope mode = %q, want %q", p.ScopeMode, ScopeModeCgroup)
	}
	if got := p.Layers[LayerModelIntent].Coverage; got != CoveragePartial {
		t.Errorf("k8s-daemonset model_intent = %q, want %q (pending libssl resolution)", got, CoveragePartial)
	}
	if got := p.Layers[LayerSystemTelemetry].Coverage; got != CoverageFull {
		t.Errorf("k8s-daemonset system_telemetry = %q, want full (shared node kernel)", got)
	}
	// Passive cgroup scope must read as less certain than a record-launched one.
	if p.ScopeConfidence() != 0.8 {
		t.Errorf("k8s-daemonset scope confidence = %v, want 0.8", p.ScopeConfidence())
	}
}

func TestLocalRecordIsKernelVerifiedBaseline(t *testing.T) {
	p := LocalRecord()
	if p.ScopeMode != ScopeModeRecord || p.ScopeConfidence() != 1 {
		t.Fatalf("local-record must be a kernel-verified baseline: mode=%q confidence=%v", p.ScopeMode, p.ScopeConfidence())
	}
}
