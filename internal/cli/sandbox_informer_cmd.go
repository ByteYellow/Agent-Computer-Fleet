package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/producer"
	"github.com/byteyellow/agentprovenance/internal/producer/k8sinformer"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func sandboxWatchCmd(dataDir *string) *cobra.Command {
	var namespace, nodeName, kubeconfig, master, selector, runAnnotation, runPrefix string
	var resync, reportInterval, runFor time.Duration
	var workers, maxRetries int
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "watch this node's pods and maintain passive cgroup scope bindings",
		Long: "A lightweight client-go informer controller. It List/Watches pods scheduled on one node, " +
			"creates one passive cgroup binding per running container, closes replaced bindings after " +
			"container restart, and closes all pod bindings on deletion. It owns scope attribution only; " +
			"agentprov-sensor and telemetry ingest remain the independent data plane.",
		RunE: func(c *cobra.Command, _ []string) error {
			if nodeName == "" {
				nodeName = strings.TrimSpace(os.Getenv("NODE_NAME"))
			}
			if nodeName == "" {
				nodeName, _ = os.Hostname()
			}
			if nodeName == "" {
				return fmt.Errorf("--node or NODE_NAME is required")
			}
			cfg, err := kubeConfig(master, kubeconfig)
			if err != nil {
				return fmt.Errorf("k8s client config: %w", err)
			}
			client, err := kubernetes.NewForConfig(cfg)
			if err != nil {
				return fmt.Errorf("k8s client: %w", err)
			}
			paths, err := store.Init(*dataDir)
			if err != nil {
				return err
			}
			db, err := store.Open(paths)
			if err != nil {
				return err
			}
			defer db.Close()

			reconciler := &k8sinformer.ScopeReconciler{
				Resolver: newProcScopeResolver(), Sink: localK8sScopeSink{db: db},
				RunAnnotation: runAnnotation, RunPrefix: runPrefix,
			}
			controller, err := k8sinformer.New(client, k8sinformer.Options{
				Namespace: namespace, NodeName: nodeName, LabelSelector: selector, Resync: resync,
				Workers: workers, MaxRetries: maxRetries, Reconciler: reconciler,
				OnError: func(key string, err error) {
					fmt.Fprintf(c.ErrOrStderr(), "informer: key=%s error=%v\n", key, err)
				},
			})
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(c.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if runFor > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, runFor)
				defer cancel()
			}
			if !jsonOut {
				fmt.Fprintf(c.OutOrStdout(), "k8s informer starting node=%s namespace=%s scope_source=k8s_cgroup\n", nodeName, displayNamespace(namespace))
			}
			done := make(chan error, 1)
			go func() { done <- controller.Run(ctx) }()
			var ticker *time.Ticker
			if reportInterval > 0 && !jsonOut {
				ticker = time.NewTicker(reportInterval)
				defer ticker.Stop()
			}
			for {
				select {
				case err := <-done:
					report := informerReport{Controller: controller.Report(), Attribution: reconciler.Report()}
					if jsonOut {
						return writeJSON(c.OutOrStdout(), report)
					}
					printInformerReport(c, report)
					return err
				case <-tickerChan(ticker):
					printInformerReport(c, informerReport{Controller: controller.Report(), Attribution: reconciler.Report()})
				}
			}
		},
	}
	cmd.Flags().StringVar(&namespace, "namespace", "", "watch one namespace; empty watches all namespaces")
	cmd.Flags().StringVar(&nodeName, "node", "", "Kubernetes node name; defaults to NODE_NAME or hostname")
	cmd.Flags().StringVar(&selector, "selector", "", "optional Kubernetes label selector for observed pods")
	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "kubeconfig path; empty uses in-cluster config, then normal loading rules")
	cmd.Flags().StringVar(&master, "master", "", "Kubernetes API server override")
	cmd.Flags().StringVar(&runAnnotation, "run-annotation", "agentprov.io/run", "pod annotation containing the target run id")
	cmd.Flags().StringVar(&runPrefix, "auto-run-prefix", "auto-", "run id prefix when the pod has no run annotation")
	cmd.Flags().DurationVar(&resync, "resync", 10*time.Minute, "full informer resync interval")
	cmd.Flags().DurationVar(&reportInterval, "report-interval", 30*time.Second, "human status report interval; 0 disables periodic reports")
	cmd.Flags().DurationVar(&runFor, "run-for", 0, "stop after this duration; 0 runs until interrupted")
	cmd.Flags().IntVar(&workers, "workers", 2, "reconcile workers")
	cmd.Flags().IntVar(&maxRetries, "max-retries", 5, "rate-limited retries per pod event")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the final machine-readable controller report")
	return cmd
}

type procScopeResolver struct {
	root         string
	mu           sync.Mutex
	byContainer  map[string]string
	lastRefresh  time.Time
	refreshEvery time.Duration
}

func newProcScopeResolver() *procScopeResolver {
	return &procScopeResolver{
		root: "/sys/fs/cgroup", byContainer: map[string]string{}, refreshEvery: time.Second,
	}
}

func (r *procScopeResolver) Resolve(_ context.Context, pod *corev1.Pod, status corev1.ContainerStatus) (string, int64, error) {
	cgroupID, err := r.resolveContainer(status.ContainerID)
	if err != nil {
		return "", 0, err
	}
	pid, err := findPodPID(string(pod.UID), status.ContainerID)
	if err != nil {
		return "", 0, err
	}
	return cgroupID, int64(pid), nil
}

func (r *procScopeResolver) resolveContainer(containerID string) (string, error) {
	containerID = normalizeRuntimeContainerID(containerID)
	if containerID == "" {
		return "", fmt.Errorf("empty container id")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if cgroupID := r.byContainer[containerID]; cgroupID != "" {
		return cgroupID, nil
	}
	if r.lastRefresh.IsZero() || time.Since(r.lastRefresh) >= r.refreshEvery {
		r.refreshLocked()
	}
	if cgroupID := r.byContainer[containerID]; cgroupID != "" {
		return cgroupID, nil
	}
	return "", fmt.Errorf("container %s has no host cgroup", containerID)
}

func (r *procScopeResolver) refreshLocked() {
	next := map[string]string{}
	_ = filepath.WalkDir(r.root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || !entry.IsDir() {
			return nil
		}
		scope, ok := producer.ParseCgroupScope(path)
		if !ok || scope.ContainerID == "" {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			next[scope.ContainerID] = fmt.Sprintf("%d", stat.Ino)
		}
		return nil
	})
	r.byContainer = next
	r.lastRefresh = time.Now()
}

func normalizeRuntimeContainerID(value string) string {
	if i := strings.LastIndex(value, "://"); i >= 0 {
		return value[i+3:]
	}
	return strings.TrimSpace(value)
}

type localK8sScopeSink struct{ db *sql.DB }

func (s localK8sScopeSink) Bind(ctx context.Context, scope k8sinformer.ContainerScope) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	id, err := correlation.RecordBinding(s.db, correlation.Binding{
		RunID: scope.RunID, SessionID: scope.SessionID, ContainerID: scope.ContainerID,
		CgroupID: scope.CgroupID, PID: scope.PID, StartedAt: scope.StartedAt,
		BindingSource: correlation.BindingSourceK8sCgroup,
	})
	if err != nil {
		return "", err
	}
	meta := podMeta{
		Name: scope.PodName, Namespace: scope.Namespace, UID: scope.PodUID,
		Node: scope.NodeName, Container: scope.ContainerName, Image: scope.Image,
		ServiceAccount: scope.ServiceAccount, Labels: labelsText(scope.Labels),
		PodIP: scope.PodIP, CgroupID: scope.CgroupID,
	}
	if err := writePodMetadataEvent(s.db, scope.RunID, meta); err != nil {
		_ = correlation.CloseBindingByID(s.db, id, scope.ObservedAt)
		return "", err
	}
	return id, nil
}

func (s localK8sScopeSink) Close(ctx context.Context, bindingID, endedAt string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return correlation.CloseBindingByID(s.db, bindingID, endedAt)
}

type informerReport struct {
	SchemaVersion string                       `json:"schema_version"`
	Controller    k8sinformer.Report           `json:"controller"`
	Attribution   k8sinformer.ReconcilerReport `json:"attribution"`
}

func printInformerReport(c *cobra.Command, report informerReport) {
	r := report.Controller
	a := report.Attribution
	fmt.Fprintf(c.OutOrStdout(), "k8s informer node=%s synced=%t enqueued=%d reconciled=%d retries=%d failed=%d bindings=%d active=%d closed=%d restarts=%d resolution_failures=%d attribution_p95_ms=%.1f\n",
		r.NodeName, r.CacheSynced, r.Enqueued, r.Reconciled, r.Retried, r.Failed,
		a.BindingsCreated, a.ActiveBindings, a.BindingsClosed, a.ContainerRestarts, a.ResolutionFailures, a.AttributionLatencyP95MS)
}

func kubeConfig(master, kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" || master != "" {
		return clientcmd.BuildConfigFromFlags(master, kubeconfig)
	}
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
}

func labelsText(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+labels[key])
	}
	return strings.Join(parts, ",")
}

func displayNamespace(namespace string) string {
	if namespace == "" {
		return "*"
	}
	return namespace
}

func tickerChan(ticker *time.Ticker) <-chan time.Time {
	if ticker == nil {
		return nil
	}
	return ticker.C
}

func writeJSON(out interface{ Write([]byte) (int, error) }, value any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}
