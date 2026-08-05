package cli

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/producer"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
	"github.com/spf13/cobra"
)

// sandboxCaptureCmd is phase 1 of zero-touch k8s attribution (see
// docs/design-k8s-auto-attribution.md): one node-side command that collapses the
// manual demo flow for one running pod — resolve pid/cgroup + pull pod metadata
// from the K8s API, run the node sensor for a window, bind the pod's cgroup to a
// run, and ingest its telemetry. No manual bind-cgroup / kubectl glue.
func sandboxCaptureCmd(dataDir *string) *cobra.Command {
	var runID, pod, namespace, kubectl, sensorBin, sslLib, container string
	var seconds, pid int
	cmd := &cobra.Command{
		Use:   "capture",
		Short: "one-shot: attribute a running k8s pod's node-observed telemetry to a run",
		RunE: func(c *cobra.Command, _ []string) error {
			if pod == "" || namespace == "" {
				return fmt.Errorf("--pod and --namespace are required")
			}
			if sensorBin == "" {
				return fmt.Errorf("--sensor (path to agentprov-sensor) is required")
			}
			if runID == "" {
				runID = ids.New("run")
			}
			stderr := c.ErrOrStderr()
			kc := strings.Fields(kubectl)

			meta, err := resolvePodMetadata(kc, pod, namespace)
			if err != nil {
				return fmt.Errorf("resolve pod metadata: %w", err)
			}
			if pid == 0 {
				cid := ""
				if container != "" {
					// Pin to a named container in a multi-container pod.
					cid, _ = runKubectl(kc, "get", "pod", pod, "-n", namespace,
						"-o", "jsonpath={.status.containerStatuses[?(@.name==\""+container+"\")].containerID}")
					meta.Container = container
				}
				pid, err = findPodPID(meta.UID, cid)
				if err != nil {
					return fmt.Errorf("resolve pod pid (pass --pid): %w", err)
				}
			}
			cgroupID, err := cgroupInodeForPID(pid)
			if err != nil {
				return fmt.Errorf("resolve pod cgroup: %w", err)
			}
			meta.CgroupID = cgroupID
			fmt.Fprintf(c.OutOrStdout(), "pod=%s/%s uid=%s pid=%d cgroup=%s node=%s\n", namespace, pod, meta.UID, pid, cgroupID, meta.Node)

			paths, err := store.Init(*dataDir)
			if err != nil {
				return err
			}
			db, err := store.Open(paths)
			if err != nil {
				return err
			}
			defer db.Close()

			started := time.Now().UTC().Format(time.RFC3339Nano)
			raw := filepath.Join(paths.Logs, "capture-"+runID+"-sensor.jsonl")
			if err := runSensorWindow(sensorBin, raw, sslLib, pid, seconds, stderr); err != nil {
				return fmt.Errorf("run sensor: %w", err)
			}
			scoped := raw + ".pod"
			kept, err := filterByCgroup(raw, scoped, cgroupID)
			if err != nil {
				return fmt.Errorf("filter pod events: %w", err)
			}

			if _, err := producer.BindCgroupScope(db, cgroupID, producer.RunScope{RunID: runID, SessionID: meta.UID, StartedAt: started}); err != nil {
				return fmt.Errorf("bind cgroup: %w", err)
			}
			if err := writePodMetadataEvent(db, runID, meta); err != nil {
				fmt.Fprintf(stderr, "capture: pod metadata event: %v\n", err)
			}
			res, err := telemetry.IngestJSONL(db, telemetry.JSONLIngestOptions{Format: "native", Path: scoped, RunID: runID})
			if err != nil {
				return fmt.Errorf("ingest: %w", err)
			}
			fmt.Fprintf(c.OutOrStdout(), "captured=%d ingested=%d run=%s scope=k8s_cgroup confidence=0.8\n", kept, res.Ingested, runID)
			return nil
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "run id to attribute the pod to (default: generated)")
	cmd.Flags().StringVar(&pod, "pod", "", "pod name (required)")
	cmd.Flags().StringVar(&container, "container", "", "container name to pin to (multi-container pods); default: the pod's first non-pause process")
	cmd.Flags().StringVar(&namespace, "namespace", "", "pod namespace (required)")
	cmd.Flags().StringVar(&kubectl, "kubectl", "kubectl", "kubectl command (e.g. \"k3s kubectl\")")
	cmd.Flags().StringVar(&sensorBin, "sensor", "", "path to agentprov-sensor (required)")
	cmd.Flags().StringVar(&sslLib, "ssl-lib", "", "libssl path for model-intent uprobe; empty = pod's own libssl via /proc/<pid>/root")
	cmd.Flags().IntVar(&seconds, "seconds", 45, "sensor capture window")
	cmd.Flags().IntVar(&pid, "pid", 0, "pod's main pid (default: auto-resolved from the pod cgroup)")
	return cmd
}

type podMeta struct {
	Name, Namespace, UID, Node, Container, Image, ServiceAccount, Labels, PodIP, CgroupID string
}

// resolvePodMetadata pulls the pod's identity from the K8s API in one kubectl call.
func resolvePodMetadata(kc []string, pod, namespace string) (podMeta, error) {
	m := podMeta{Name: pod, Namespace: namespace}
	jsonpath := "{.metadata.uid}|{.spec.nodeName}|{.spec.containers[0].name}|" +
		"{.spec.containers[0].image}|{.spec.serviceAccountName}|{.status.podIP}"
	out, err := runKubectl(kc, "get", "pod", pod, "-n", namespace, "-o", "jsonpath="+jsonpath)
	if err != nil {
		return m, err
	}
	f := strings.Split(strings.TrimSpace(out), "|")
	for len(f) < 6 {
		f = append(f, "")
	}
	m.UID, m.Node, m.Container, m.Image, m.ServiceAccount, m.PodIP = f[0], f[1], f[2], f[3], f[4], f[5]
	if labels, err := runKubectl(kc, "get", "pod", pod, "-n", namespace, "-o", "jsonpath={.metadata.labels}"); err == nil {
		m.Labels = strings.TrimSpace(labels)
	}
	return m, nil
}

func runKubectl(kc []string, args ...string) (string, error) {
	if len(kc) == 0 {
		kc = []string{"kubectl"}
	}
	cmd := exec.Command(kc[0], append(kc[1:], args...)...)
	out, err := cmd.Output()
	return string(out), err
}

// findPodPID scans /proc for the pod's APP process — one whose cgroup path names
// this pod UID (kubepods…/pod<uid>, dashes underscore-normalized by the kubelet)
// but is NOT the `pause` sandbox container, whose cgroup leaf differs from the
// app container's and carries none of the workload's syscalls.
func findPodPID(uid, containerID string) (int, error) {
	if uid == "" {
		return 0, fmt.Errorf("empty pod uid")
	}
	needles := []string{"pod" + strings.ReplaceAll(uid, "-", "_"), "pod" + uid}
	// A multi-container pod has one cgroup leaf per container; when a specific
	// container is requested, pin to the process whose cgroup names its id, not
	// merely the first non-pause process in the pod.
	containerID = strings.TrimSpace(containerID)
	if i := strings.LastIndex(containerID, "/"); i >= 0 {
		containerID = containerID[i+1:] // strip a containerd://<id> scheme
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var p int
		if _, err := fmt.Sscanf(e.Name(), "%d", &p); err != nil || p == 0 {
			continue
		}
		cg, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cgroup"))
		if err != nil {
			continue
		}
		matched := false
		for _, n := range needles {
			if strings.Contains(string(cg), n) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if containerID != "" && !strings.Contains(string(cg), containerID) {
			continue // not the requested container's cgroup leaf
		}
		comm, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if strings.TrimSpace(string(comm)) == "pause" {
			continue // the sandbox container — not where the workload runs
		}
		return p, nil
	}
	if containerID != "" {
		return 0, fmt.Errorf("no process found in container %s of pod uid %s on this node", containerID, uid)
	}
	return 0, fmt.Errorf("no app process found in cgroup for pod uid %s (is the pod running on this node?)", uid)
}

// cgroupInodeForPID resolves the kernel cgroup id (the inode the sensor stamps)
// for a pid from its cgroup2 path.
func cgroupInodeForPID(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	rel := ""
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.Index(line, "::"); i >= 0 {
			rel = line[i+2:]
			break
		}
	}
	if rel == "" {
		return "", fmt.Errorf("no cgroup2 path in /proc/%d/cgroup", pid)
	}
	info, err := os.Stat(hostCgroupPath(rel))
	if err != nil {
		return "", err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d", st.Ino), nil
	}
	return "", fmt.Errorf("cannot read cgroup inode")
}

// hostCgroupPath anchors a /proc/<pid>/cgroup path at the host cgroup mount.
// A hostPID container still has its own cgroup namespace, so host process paths
// may be reported as ../../kubepods.... Cleaning after prepending '/' removes
// those namespace-relative parents without allowing the path to escape the
// read-only host cgroup root.
func hostCgroupPath(rel string) string {
	clean := filepath.Clean("/" + strings.TrimSpace(rel))
	return filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(clean, "/"))
}

// runSensorWindow runs the node sensor for a fixed window, writing raw JSONL. It
// points the model-intent uprobe at the pod's own libssl (reached via
// /proc/<pid>/root) unless an explicit --ssl-lib is given.
func runSensorWindow(sensorBin, out, sslLib string, pid, seconds int, stderr io.Writer) error {
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	proc := exec.Command(sensorBin)
	proc.Stdout = f
	if ef, e := os.Create(out + ".err"); e == nil {
		proc.Stderr = ef
		defer ef.Close()
	}
	proc.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	proc.Env = os.Environ()
	if sslLib == "" && pid > 0 {
		for _, cand := range []string{
			fmt.Sprintf("/proc/%d/root/usr/lib/aarch64-linux-gnu/libssl.so.3", pid),
			fmt.Sprintf("/proc/%d/root/usr/lib/x86_64-linux-gnu/libssl.so.3", pid),
		} {
			if _, e := os.Stat(cand); e == nil {
				sslLib = cand
				break
			}
		}
	}
	if sslLib != "" {
		proc.Env = append(proc.Env, "AGENTPROV_SSL_LIB="+sslLib)
	}
	if pid > 0 {
		// Point the getaddrinfo DNS uprobe at the pod's own libc so egress gets
		// resolved by NAME (not just IP) node-side, mirroring the libssl trick.
		for _, cand := range []string{
			fmt.Sprintf("/proc/%d/root/usr/lib/aarch64-linux-gnu/libc.so.6", pid),
			fmt.Sprintf("/proc/%d/root/usr/lib/x86_64-linux-gnu/libc.so.6", pid),
			fmt.Sprintf("/proc/%d/root/lib/aarch64-linux-gnu/libc.so.6", pid),
		} {
			if _, e := os.Stat(cand); e == nil {
				proc.Env = append(proc.Env, "AGENTPROV_LIBC_LIB="+cand)
				break
			}
		}
	}
	if err := proc.Start(); err != nil {
		return err
	}
	time.Sleep(time.Duration(seconds) * time.Second)
	if proc.Process != nil {
		_ = syscall.Kill(-proc.Process.Pid, syscall.SIGINT)
	}
	_ = proc.Wait()
	return nil
}

func writePodMetadataEvent(db *sql.DB, runID string, m podMeta) error {
	payload, _ := json.Marshal(map[string]any{
		"pod_name": m.Name, "namespace": m.Namespace, "pod_uid": m.UID, "cgroup_id": m.CgroupID,
		"cluster": "", "node": m.Node, "container": m.Container, "image": m.Image,
		"service_account": m.ServiceAccount, "labels": m.Labels, "pod_ip": m.PodIP,
	})
	_, err := db.Exec(`INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, '', '', 'k8s', 'pod_metadata', ?, ?)`,
		ids.New("evt"), runID, m.UID, string(payload), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func filterByCgroup(src, dst, cgroupID string) (int, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	needle := `"cgroup_id":"` + cgroupID + `"`
	n := 0
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		if strings.Contains(sc.Text(), needle) {
			fmt.Fprintln(out, sc.Text())
			n++
		}
	}
	return n, sc.Err()
}
