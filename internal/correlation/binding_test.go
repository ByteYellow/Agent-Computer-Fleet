package correlation

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestListBindingsFiltersToolCallScope(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	started := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := RecordBinding(db, Binding{
		RunID:         "run-1",
		SessionID:     "session-1",
		AttemptID:     "attempt-1",
		ToolCallID:    "tool-1",
		ProcessID:     "process-1",
		ContainerID:   "container-1",
		CgroupID:      "cgroup-1",
		PID:           4242,
		StartedAt:     started,
		BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordBinding(db, Binding{
		RunID:         "run-2",
		SessionID:     "session-2",
		AttemptID:     "attempt-2",
		ToolCallID:    "tool-2",
		ProcessID:     "process-2",
		StartedAt:     started,
		BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}

	bindings, err := ListBindings(db, BindingFilter{RunID: "run-1", ToolCallID: "tool-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 {
		t.Fatalf("bindings = %d, want 1", len(bindings))
	}
	binding := bindings[0]
	if binding.RunID != "run-1" || binding.ToolCallID != "tool-1" || binding.PID != 4242 {
		t.Fatalf("unexpected binding: %+v", binding)
	}
}

func TestAiAssertedBindingConfidenceCapped(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	started := time.Now().UTC().Format(time.RFC3339Nano)
	// ai_asserted: no explicit confidence -> capped at 0.5 by RecordBinding.
	if _, err := RecordBinding(db, Binding{
		RunID: "run-ai", ToolCallID: "tool-ai", ProcessID: "proc-ai",
		PID: 1111, StartedAt: started, BindingSource: "ai_asserted",
	}); err != nil {
		t.Fatal(err)
	}
	// A first-party launch binding: default confidence stays authoritative.
	if _, err := RecordBinding(db, Binding{
		RunID: "run-cp", ToolCallID: "tool-cp", ProcessID: "proc-cp",
		PID: 2222, StartedAt: started, BindingSource: "zero_sdk_record",
	}); err != nil {
		t.Fatal(err)
	}

	// Resolve by process_id (method confidence 1.0); scanOne takes the min with
	// the binding confidence, so the app-asserted join reads honestly lower.
	aiMatch, ok, err := Resolve(db, RawIdentity{RunID: "run-ai", ProcessID: "proc-ai", Timestamp: started})
	if err != nil || !ok {
		t.Fatalf("resolve ai binding: ok=%v err=%v", ok, err)
	}
	if aiMatch.Confidence != 0.5 {
		t.Errorf("ai_asserted match confidence = %v, want 0.5", aiMatch.Confidence)
	}
	cpMatch, ok, err := Resolve(db, RawIdentity{RunID: "run-cp", ProcessID: "proc-cp", Timestamp: started})
	if err != nil || !ok {
		t.Fatalf("resolve launch binding: ok=%v err=%v", ok, err)
	}
	if cpMatch.Confidence != 1.0 {
		t.Errorf("zero_sdk_record match confidence = %v, want 1.0", cpMatch.Confidence)
	}
}

func TestResolveHonorsExplicitRunID(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	started := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	if _, err := RecordBinding(db, Binding{
		RunID:         "run-a",
		SessionID:     "session-a",
		AttemptID:     "attempt-a",
		ToolCallID:    "tool-a",
		ProcessID:     "process-a",
		ContainerID:   "shared-container",
		CgroupID:      "shared-cgroup",
		PID:           4242,
		StartedAt:     started,
		BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}
	match, ok, err := Resolve(db, RawIdentity{
		RunID:       "run-b",
		ContainerID: "shared-container",
		CgroupID:    "shared-cgroup",
		PID:         4242,
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("explicit run-b should not resolve run-a binding: %+v", match)
	}
	match, ok, err = Resolve(db, RawIdentity{
		ContainerID: "shared-container",
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || match.RunID != "run-a" {
		t.Fatalf("runless lookup should still resolve by container: ok=%t match=%+v", ok, match)
	}
}

// TestStaleOpenBindingDoesNotOverMatch characterizes the dropped-CloseBinding
// failure mode on the pid tier (where pid reuse makes over-matching dangerous):
// CloseBinding is best-effort, so a binding can be left open (ended_at = "")
// indefinitely. Without the MaxOpenBindingAge guard an unrelated later execution
// reusing the pid would bind to the stale context. The guard applies to the pid
// tier only; container/cgroup anchors are intentionally long-lived (see
// TestLongLivedOpenContainerAnchorStillResolves).
func TestStaleOpenBindingDoesNotOverMatch(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// An open binding (no EndedAt) started well beyond MaxOpenBindingAge ago,
	// simulating a binding whose close was dropped.
	stale := time.Now().Add(-MaxOpenBindingAge - time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := RecordBinding(db, Binding{
		RunID: "run-stale", PID: 1000,
		StartedAt: stale, BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}

	// An event observed now (resolved by pid) must fall through to unresolved.
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, ok, err := Resolve(db, RawIdentity{PID: 1000, Timestamp: now})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("stale open pid binding over-matched an event observed beyond MaxOpenBindingAge")
	}

	// A fresh open binding for a different pid must still resolve at now.
	if _, err := RecordBinding(db, Binding{
		RunID: "run-fresh", PID: 2000,
		StartedAt: now, BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}
	match, ok, err := Resolve(db, RawIdentity{PID: 2000, Timestamp: now})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || match.RunID != "run-fresh" {
		t.Fatalf("fresh open pid binding failed to resolve: ok=%v match=%+v", ok, match)
	}
}

// TestLongLivedOpenContainerAnchorStillResolves locks the intentional pattern:
// an external-telemetry bind on a container with a far-past start and no end is
// a legitimate "match all events for this container" anchor and must keep
// resolving even far beyond MaxOpenBindingAge (the stale-open guard is pid-only).
func TestLongLivedOpenContainerAnchorStillResolves(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := RecordBinding(db, Binding{
		RunID: "run-anchor", ContainerID: "container-anchor",
		StartedAt: "2000-01-01T00:00:00.000000000Z", BindingSource: "external_telemetry",
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	match, ok, err := Resolve(db, RawIdentity{ContainerID: "container-anchor", Timestamp: now})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || match.RunID != "run-anchor" {
		t.Fatalf("long-lived container anchor should resolve: ok=%v match=%+v", ok, match)
	}
}

// TestClosedBindingWindowStillResolves confirms the refactor preserved the
// closed-interval time-window behavior: an event inside [started, ended] binds,
// one after ended does not.
func TestClosedBindingWindowStillResolves(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	start := time.Now().Add(-10 * time.Minute)
	end := time.Now().Add(-5 * time.Minute)
	if _, err := RecordBinding(db, Binding{
		RunID: "run-closed", CgroupID: "cgroup-closed", PID: 3000,
		StartedAt:     start.UTC().Format(time.RFC3339Nano),
		EndedAt:       end.UTC().Format(time.RFC3339Nano),
		BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}

	inside := start.Add(2 * time.Minute).UTC().Format(time.RFC3339Nano)
	if _, ok, err := Resolve(db, RawIdentity{CgroupID: "cgroup-closed", Timestamp: inside}); err != nil || !ok {
		t.Fatalf("event inside closed window should resolve: ok=%v err=%v", ok, err)
	}

	after := time.Now().UTC().Format(time.RFC3339Nano)
	if _, ok, err := Resolve(db, RawIdentity{CgroupID: "cgroup-closed", Timestamp: after}); err != nil || ok {
		t.Fatalf("event after closed window must not resolve: ok=%v err=%v", ok, err)
	}
}

// TestChildEventResolvesViaContainerNotPid covers async/child attribution: a
// child process whose pid differs from the binding's pid still attributes to the
// original execution scope through shared container membership (not pid lineage).
func TestChildEventResolvesViaContainerNotPid(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := RecordBinding(db, Binding{
		RunID: "run-child", SessionID: "s", ToolCallID: "tc", ProcessID: "p",
		ContainerID: "container-child", RootPID: 4000, PID: 4000,
		StartedAt: "2000-01-01T00:00:00.000000000Z", BindingSource: "external_telemetry",
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	// A child pid (4137) the binding never recorded, same container.
	match, ok, err := Resolve(db, RawIdentity{ContainerID: "container-child", PID: 4137, Timestamp: now})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || match.RunID != "run-child" || match.ToolCallID != "tc" {
		t.Fatalf("child event should attribute to scope via container: ok=%v match=%+v", ok, match)
	}
	if !strings.Contains(match.Method, "container") {
		t.Fatalf("expected container-based method for child pid, got %q", match.Method)
	}
}

func TestCloseBindingByIDOnlyClosesTarget(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	first, err := RecordBinding(db, Binding{RunID: "run-pod", SessionID: "pod", CgroupID: "101"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := RecordBinding(db, Binding{RunID: "run-pod", SessionID: "pod", CgroupID: "202"})
	if err != nil {
		t.Fatal(err)
	}
	ended := time.Now().UTC().Format(time.RFC3339Nano)
	if err := CloseBindingByID(db, first, ended); err != nil {
		t.Fatal(err)
	}

	var firstEnded, secondEnded string
	if err := db.QueryRow(`SELECT ended_at FROM execution_context_bindings WHERE id = ?`, first).Scan(&firstEnded); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT ended_at FROM execution_context_bindings WHERE id = ?`, second).Scan(&secondEnded); err != nil {
		t.Fatal(err)
	}
	if firstEnded != ended || secondEnded != "" {
		t.Fatalf("ended_at target=%q sibling=%q", firstEnded, secondEnded)
	}
}
