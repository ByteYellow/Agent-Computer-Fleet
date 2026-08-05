package k8sinformer

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type fakeResolver struct {
	mu      sync.Mutex
	results map[string]struct {
		cgroup string
		pid    int64
	}
}

func (r *fakeResolver) Resolve(_ context.Context, _ *corev1.Pod, status corev1.ContainerStatus) (string, int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	result, ok := r.results[normalizeContainerID(status.ContainerID)]
	if !ok {
		return "", 0, fmt.Errorf("container not visible in host cgroup")
	}
	return result.cgroup, result.pid, nil
}

type fakeSink struct {
	mu     sync.Mutex
	bound  []ContainerScope
	closed []string
}

func (s *fakeSink) Bind(_ context.Context, scope ContainerScope) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bound = append(s.bound, scope)
	return fmt.Sprintf("binding-%d", len(s.bound)), nil
}

func (s *fakeSink) Close(_ context.Context, bindingID, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = append(s.closed, bindingID)
	return nil
}

func TestScopeReconcilerContainerLifecycle(t *testing.T) {
	now := time.Date(2026, 8, 5, 2, 0, 0, 0, time.UTC)
	resolver := &fakeResolver{results: map[string]struct {
		cgroup string
		pid    int64
	}{
		"container-a": {cgroup: "101", pid: 1001},
		"container-b": {cgroup: "202", pid: 2002},
	}}
	sink := &fakeSink{}
	r := &ScopeReconciler{Resolver: resolver, Sink: sink, Now: func() time.Time { return now }}
	pod := testPod("containerd://container-a")

	if err := r.Upsert(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	if err := r.Upsert(context.Background(), pod.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	if got := len(sink.bound); got != 1 {
		t.Fatalf("idempotent upsert created %d bindings, want 1", got)
	}
	if got := sink.bound[0]; got.RunID != "run-explicit" || got.ContainerID != "container-a" || got.CgroupID != "101" || got.PID != 1001 {
		t.Fatalf("first binding = %+v", got)
	}

	restarted := pod.DeepCopy()
	restarted.ResourceVersion = "2"
	restarted.Status.ContainerStatuses[0].ContainerID = "containerd://container-b"
	if err := r.Upsert(context.Background(), restarted); err != nil {
		t.Fatal(err)
	}
	if got := len(sink.bound); got != 2 {
		t.Fatalf("restart bindings = %d, want 2", got)
	}
	if len(sink.closed) != 1 || sink.closed[0] != "binding-1" {
		t.Fatalf("restart closed = %v, want [binding-1]", sink.closed)
	}

	if err := r.Delete(context.Background(), "default/demo", string(pod.UID)); err != nil {
		t.Fatal(err)
	}
	if len(sink.closed) != 2 || sink.closed[1] != "binding-2" {
		t.Fatalf("delete closed = %v, want binding-2 last", sink.closed)
	}
	report := r.Report()
	if report.BindingsCreated != 2 || report.BindingsClosed != 2 || report.ContainerRestarts != 1 || report.ActiveBindings != 0 {
		t.Fatalf("report = %+v", report)
	}
}

func TestScopeReconcilerReportsResolutionFailure(t *testing.T) {
	r := &ScopeReconciler{
		Resolver: &fakeResolver{results: map[string]struct {
			cgroup string
			pid    int64
		}{}},
		Sink: &fakeSink{},
	}
	if err := r.Upsert(context.Background(), testPod("containerd://missing")); err == nil {
		t.Fatal("expected resolution failure")
	}
	if got := r.Report().ResolutionFailures; got != 1 {
		t.Fatalf("resolution_failures = %d, want 1", got)
	}
}

func testPod(containerID string) *corev1.Pod {
	created := time.Date(2026, 8, 5, 1, 59, 59, 0, time.UTC)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "demo", Namespace: "default", UID: types.UID("pod-uid"), ResourceVersion: "1",
			CreationTimestamp: metav1.NewTime(created),
			Annotations:       map[string]string{"agentprov.io/run": "run-explicit"},
			Labels:            map[string]string{"app": "demo"},
		},
		Spec: corev1.PodSpec{NodeName: "node-a", ServiceAccountName: "default"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning, PodIP: "10.42.0.10",
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "worker", Image: "busybox", ContainerID: containerID,
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(created)}},
			}},
		},
	}
}
