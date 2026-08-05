package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/producer"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
	"github.com/spf13/cobra"
)

// sandboxPollingWatchCmd keeps the original finite-window kubectl polling path
// as a diagnostic fallback. The public `sandbox watch` command is the informer
// controller in sandbox_informer_cmd.go.
func sandboxPollingWatchCmd(dataDir *string) *cobra.Command {
	var namespace, kubectl, sensorBin string
	var window, rounds int
	cmd := &cobra.Command{
		Use:   "watch-poll",
		Short: "diagnostic fallback: poll pods and capture finite node-sensor windows",
		Long: "Compatibility path for zero-touch attribution using kubectl polling. " +
			"The production-shaped `sandbox watch` command uses a client-go informer. One sensor window per round covers all " +
			"bound cgroups, so — unlike `sandbox capture` — it does NOT set a per-pod " +
			"AGENTPROV_SSL_LIB/AGENTPROV_LIBC_LIB, so model-intent (TLS) and DNS-domain " +
			"coverage are weaker here; use `sandbox capture` for full per-pod model intent.",
		RunE: func(c *cobra.Command, _ []string) error {
			if sensorBin == "" {
				return fmt.Errorf("--sensor (path to agentprov-sensor) is required")
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
			kc := strings.Fields(kubectl)
			out, stderr := c.OutOrStdout(), c.ErrOrStderr()

			boundCgroup := map[string]string{} // cgroup_id -> run (already bound)
			for round := 0; rounds == 0 || round < rounds; round++ {
				pods, err := listPods(kc, namespace)
				if err != nil {
					fmt.Fprintf(stderr, "watch: list pods: %v\n", err)
					time.Sleep(time.Duration(window) * time.Second)
					continue
				}
				// Resolve + bind any pod on THIS node not yet bound. findPodPID
				// fails for pods on other nodes, which we simply skip.
				roundPods := map[string]podMeta{} // cgroup_id -> meta (bound this session)
				for _, p := range pods {
					meta, err := resolvePodMetadata(kc, p.name, p.namespace)
					if err != nil {
						continue
					}
					pid, err := findPodPID(meta.UID, "")
					if err != nil {
						continue // not on this node (or not running)
					}
					cg, err := cgroupInodeForPID(pid)
					if err != nil {
						continue
					}
					meta.CgroupID = cg
					run := boundCgroup[cg]
					if run == "" {
						run = podRunID(kc, p.name, p.namespace, meta.UID)
						started := time.Now().UTC().Format(time.RFC3339Nano)
						if _, err := producer.BindCgroupScope(db, cg, producer.RunScope{RunID: run, SessionID: meta.UID, StartedAt: started}); err != nil {
							fmt.Fprintf(stderr, "watch: bind %s/%s: %v\n", p.namespace, p.name, err)
							continue
						}
						_ = writePodMetadataEvent(db, run, meta)
						boundCgroup[cg] = run
						fmt.Fprintf(out, "bound %s/%s cgroup=%s -> run=%s\n", p.namespace, p.name, cg, run)
					}
					roundPods[cg] = meta
				}
				if len(roundPods) == 0 {
					time.Sleep(time.Duration(window) * time.Second)
					continue
				}
				// One sensor window covers every bound cgroup. NOTE: because a single
				// sensor serves all pods this round, it can't target one pod's libssl/
				// libc (pid=0, sslLib=""), so model-intent/DNS coverage is weaker than
				// `sandbox capture` — system telemetry + cgroup scope are the focus here.
				raw := filepath.Join(paths.Logs, fmt.Sprintf("watch-r%d-sensor.jsonl", round))
				if err := runSensorWindow(sensorBin, raw, "", 0, window, stderr); err != nil {
					fmt.Fprintf(stderr, "watch: sensor: %v\n", err)
					continue
				}
				for cg, meta := range roundPods {
					scoped := raw + "." + cg
					if _, err := filterByCgroup(raw, scoped, cg); err != nil {
						continue
					}
					res, err := telemetry.IngestJSONL(db, telemetry.JSONLIngestOptions{Format: "native", Path: scoped, RunID: boundCgroup[cg]})
					if err != nil {
						fmt.Fprintf(stderr, "watch: ingest %s: %v\n", meta.Name, err)
						continue
					}
					if res.Ingested > 0 {
						fmt.Fprintf(out, "attributed %s/%s: %d events -> run=%s\n", meta.Namespace, meta.Name, res.Ingested, boundCgroup[cg])
					}
				}
				_ = os.Remove(raw)
			}
			return nil
		},
	}
	cmd.Hidden = true
	cmd.Flags().StringVar(&namespace, "namespace", "", "limit to one namespace (default: all)")
	cmd.Flags().StringVar(&kubectl, "kubectl", "kubectl", "kubectl command (e.g. \"k3s kubectl\")")
	cmd.Flags().StringVar(&sensorBin, "sensor", "", "path to agentprov-sensor (required)")
	cmd.Flags().IntVar(&window, "window", 30, "sensor capture window per round (seconds)")
	cmd.Flags().IntVar(&rounds, "rounds", 0, "number of rounds; 0 = run until stopped")
	return cmd
}

type podRef struct{ namespace, name string }

// listPods returns running pods (all namespaces or one). Pods not on this node
// are filtered out later by findPodPID failing to resolve them.
func listPods(kc []string, namespace string) ([]podRef, error) {
	args := []string{"get", "pods", "--field-selector=status.phase=Running",
		"-o", "jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name}{\"\\n\"}{end}"}
	if namespace != "" {
		args = append([]string{"get", "pods", "-n", namespace}, args[2:]...)
	} else {
		args = append(args, "--all-namespaces")
	}
	out, err := runKubectl(kc, args...)
	if err != nil {
		return nil, err
	}
	var pods []podRef
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if i := strings.IndexByte(line, '/'); i > 0 {
			pods = append(pods, podRef{line[:i], line[i+1:]})
		}
	}
	return pods, nil
}

// podRunID reads the pod's agentprov.io/run annotation (explicit opt-in to a
// named run) or falls back to an auto-run keyed by the pod UID.
func podRunID(kc []string, pod, namespace, uid string) string {
	out, err := runKubectl(kc, "get", "pod", pod, "-n", namespace,
		"-o", "jsonpath={.metadata.annotations.agentprov\\.io/run}")
	if run := strings.TrimSpace(out); err == nil && run != "" {
		return run
	}
	return "auto-" + uid
}
