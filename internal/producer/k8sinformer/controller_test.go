package k8sinformer

import (
	"context"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

type recordingReconciler struct {
	mu      sync.Mutex
	upserts int
	deletes int
}

func (r *recordingReconciler) Upsert(_ context.Context, _ *corev1.Pod) error {
	r.mu.Lock()
	r.upserts++
	r.mu.Unlock()
	return nil
}

func (r *recordingReconciler) Delete(_ context.Context, _, _ string) error {
	r.mu.Lock()
	r.deletes++
	r.mu.Unlock()
	return nil
}

func (r *recordingReconciler) counts() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.upserts, r.deletes
}

func TestControllerListWatchAndDelete(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "demo", Namespace: "default", UID: types.UID("uid-1"), ResourceVersion: "1",
		Labels: map[string]string{"agentprov.io/managed": "true"},
	}, Spec: corev1.PodSpec{NodeName: "node-a"}}
	client := fake.NewSimpleClientset()
	fakeWatch := watch.NewRaceFreeFake()
	client.PrependReactor("list", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.PodList{Items: []corev1.Pod{*pod}}, nil
	})
	client.PrependWatchReactor("pods", func(action clienttesting.Action) (bool, watch.Interface, error) {
		return true, fakeWatch, nil
	})
	reconciler := &recordingReconciler{}
	controller, err := New(client, Options{
		NodeName: "node-a", LabelSelector: "agentprov.io/managed=true", Reconciler: reconciler, Resync: time.Hour,
		OnError: func(key string, err error) { t.Logf("controller error key=%s: %v", key, err) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()
	waitFor(t, func() bool {
		upserts, _ := reconciler.counts()
		return upserts == 1
	})

	fakeWatch.Delete(pod.DeepCopy())
	waitFor(t, func() bool {
		_, deletes := reconciler.counts()
		return deletes == 1
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	listSelector, labelSelector := "", ""
	for _, action := range client.Actions() {
		if action.GetVerb() == "list" && action.GetResource().Resource == "pods" {
			listSelector = action.(clienttesting.ListAction).GetListRestrictions().Fields.String()
			labelSelector = action.(clienttesting.ListAction).GetListRestrictions().Labels.String()
		}
	}
	if listSelector != "spec.nodeName=node-a" {
		t.Fatalf("pod list field selector = %q, want spec.nodeName=node-a", listSelector)
	}
	if labelSelector != "agentprov.io/managed=true" {
		t.Fatalf("pod list label selector = %q", labelSelector)
	}
	report := controller.Report()
	if !report.CacheSynced || report.Reconciled != 1 || report.Deleted != 1 || report.Failed != 0 {
		t.Fatalf("controller report = %+v", report)
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for informer reconciliation")
}
