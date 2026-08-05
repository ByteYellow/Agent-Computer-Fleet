package k8sinformer

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type PodReconciler interface {
	Upsert(context.Context, *corev1.Pod) error
	Delete(context.Context, string, string) error
}

type Options struct {
	Namespace     string
	NodeName      string
	LabelSelector string
	Resync        time.Duration
	Workers       int
	MaxRetries    int
	QueueName     string
	Reconciler    PodReconciler
	OnError       func(string, error)
}

type Report struct {
	SchemaVersion string `json:"schema_version"`
	NodeName      string `json:"node_name"`
	Namespace     string `json:"namespace,omitempty"`
	CacheSynced   bool   `json:"cache_synced"`
	Enqueued      int64  `json:"enqueued"`
	Reconciled    int64  `json:"reconciled"`
	Deleted       int64  `json:"deleted"`
	Retried       int64  `json:"retried"`
	Failed        int64  `json:"failed"`
}

type queueItem struct {
	Key     string
	UID     string
	Deleted bool
}

type Controller struct {
	client      kubernetes.Interface
	opts        Options
	informer    cache.SharedIndexInformer
	queue       workqueue.TypedRateLimitingInterface[queueItem]
	cacheSynced atomic.Bool
	enqueued    atomic.Int64
	reconciled  atomic.Int64
	deleted     atomic.Int64
	retried     atomic.Int64
	failed      atomic.Int64
}

func New(client kubernetes.Interface, opts Options) (*Controller, error) {
	if client == nil {
		return nil, fmt.Errorf("k8s informer: client is required")
	}
	if opts.Reconciler == nil {
		return nil, fmt.Errorf("k8s informer: reconciler is required")
	}
	if opts.NodeName == "" {
		return nil, fmt.Errorf("k8s informer: node name is required")
	}
	if opts.Workers <= 0 {
		opts.Workers = 1
	}
	if opts.MaxRetries <= 0 {
		opts.MaxRetries = 5
	}
	if opts.QueueName == "" {
		opts.QueueName = "agentprov-k8s-attribution"
	}
	namespace := opts.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}
	informer := v1.NewFilteredPodInformer(
		client,
		namespace,
		opts.Resync,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		func(options *metav1.ListOptions) {
			options.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", opts.NodeName).String()
			options.LabelSelector = opts.LabelSelector
		},
	)
	c := &Controller{
		client:   client,
		opts:     opts,
		informer: informer,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[queueItem](),
			workqueue.TypedRateLimitingQueueConfig[queueItem]{Name: opts.QueueName},
		),
	}
	_, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) { c.enqueue(obj, false) },
		UpdateFunc: func(oldObj, newObj any) {
			oldPod, oldOK := oldObj.(*corev1.Pod)
			newPod, newOK := newObj.(*corev1.Pod)
			if oldOK && newOK && oldPod.ResourceVersion == newPod.ResourceVersion {
				return
			}
			c.enqueue(newObj, false)
		},
		DeleteFunc: func(obj any) { c.enqueue(obj, true) },
	})
	if err != nil {
		return nil, fmt.Errorf("k8s informer: register handler: %w", err)
	}
	return c, nil
}

func (c *Controller) Run(ctx context.Context) error {
	go c.informer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), c.informer.HasSynced) {
		return fmt.Errorf("k8s informer: cache sync failed")
	}
	c.cacheSynced.Store(true)
	for i := 0; i < c.opts.Workers; i++ {
		go c.worker(ctx)
	}
	<-ctx.Done()
	c.queue.ShutDown()
	return nil
}

func (c *Controller) Report() Report {
	return Report{
		SchemaVersion: "agentprovenance.k8s_informer/v1",
		NodeName:      c.opts.NodeName,
		Namespace:     c.opts.Namespace,
		CacheSynced:   c.cacheSynced.Load(),
		Enqueued:      c.enqueued.Load(),
		Reconciled:    c.reconciled.Load(),
		Deleted:       c.deleted.Load(),
		Retried:       c.retried.Load(),
		Failed:        c.failed.Load(),
	}
}

func (c *Controller) enqueue(obj any, deleted bool) {
	pod, ok := podFromObject(obj)
	if !ok {
		return
	}
	key, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		c.reportError("key", err)
		return
	}
	c.queue.Add(queueItem{Key: key, UID: string(pod.UID), Deleted: deleted})
	c.enqueued.Add(1)
}

func podFromObject(obj any) (*corev1.Pod, bool) {
	if pod, ok := obj.(*corev1.Pod); ok {
		return pod, true
	}
	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		return nil, false
	}
	pod, ok := tombstone.Obj.(*corev1.Pod)
	return pod, ok
}

func (c *Controller) worker(ctx context.Context) {
	for c.processNext(ctx) {
	}
}

func (c *Controller) processNext(ctx context.Context) bool {
	item, shutdown := c.queue.Get()
	if shutdown {
		return false
	}
	defer c.queue.Done(item)

	err := c.reconcile(ctx, item)
	if err == nil {
		c.queue.Forget(item)
		return true
	}
	if c.queue.NumRequeues(item) < c.opts.MaxRetries {
		c.retried.Add(1)
		c.queue.AddRateLimited(item)
		c.reportError(item.Key, err)
		return true
	}
	c.queue.Forget(item)
	c.failed.Add(1)
	c.reportError(item.Key, fmt.Errorf("retry budget exhausted: %w", err))
	return true
}

func (c *Controller) reconcile(ctx context.Context, item queueItem) error {
	if item.Deleted {
		if err := c.opts.Reconciler.Delete(ctx, item.Key, item.UID); err != nil {
			return err
		}
		c.deleted.Add(1)
		return nil
	}
	obj, exists, err := c.informer.GetIndexer().GetByKey(item.Key)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return fmt.Errorf("cache object %s is %T, want *corev1.Pod", item.Key, obj)
	}
	if err := c.opts.Reconciler.Upsert(ctx, pod.DeepCopy()); err != nil {
		return err
	}
	c.reconciled.Add(1)
	return nil
}

func (c *Controller) reportError(key string, err error) {
	if c.opts.OnError != nil {
		c.opts.OnError(key, err)
	}
}
