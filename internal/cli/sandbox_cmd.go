package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/producer"
	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
	"github.com/spf13/cobra"
)

// sandboxCmd is the in-sandbox Producer Profile runner (v0.7): the Go-native
// form of the proven batch flow. It runs INSIDE a sandbox (microVM guest, Kata
// pod, or plain container) and, in one command, wraps a workload with full
// provenance capture, then exports a forensics bundle so a short-lived sandbox
// does not lose its evidence. The correlation backbone is producer.BindSelfCgroup:
// bind the sandbox's own cgroup to the run scope, then batch-ingest the sensor's
// telemetry dropping anything outside that scope, so the exported bundle imports
// and verifies clean centrally.
func sandboxCmd(dataDir *string) *cobra.Command {
	cmd := &cobra.Command{Use: "sandbox", Short: "in-sandbox producer profile: capture a workload and export a verifiable bundle"}

	var out, runID, workdir, sensorBin, sslLib string
	var noSensor bool
	run := &cobra.Command{
		Use:   "run -- <command...>",
		Short: "run a workload with full provenance capture, then export a forensics bundle",
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("a command is required after --")
			}
			// Bind window opens here (before the sensor starts) so every sandbox
			// event falls inside it.
			agentStart := time.Now().UTC().Format(time.RFC3339Nano)
			if runID == "" {
				runID = ids.New("run")
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
			stderr := c.ErrOrStderr()

			// record needs a real working directory; an empty one leaves the
			// workload's cwd at "/", which record cannot snapshot/exec cleanly.
			if workdir == "" {
				if tmp, terr := os.MkdirTemp("", "agentprov-sandbox-"); terr == nil {
					workdir = tmp
					defer os.RemoveAll(tmp)
				}
			}

			// Model-intent auto-discovery: unless --ssl-lib is given, inspect the
			// workload's executable and point the TLS uprobes at its stack (Go
			// crypto/tls, static OpenSSL like node, or dynamic libssl) so intent
			// capture works out of the box instead of needing a hand-picked path.
			goTLSBin := ""
			tlsStack := "none"
			if sslLib == "" {
				if exe, lerr := exec.LookPath(args[0]); lerr == nil {
					t := producer.DetectTLSTarget(exe)
					sslLib, goTLSBin, tlsStack = t.SSLLib, t.GoTLSBin, t.Stack
				}
			} else {
				tlsStack = "explicit"
			}

			// 1) system telemetry: start the sensor as a raw-JSONL subprocess.
			sysTier := "collecting"
			sensorJSONL := filepath.Join(paths.Logs, "sandbox-"+runID+"-sensor.jsonl")
			var sensorProc *exec.Cmd
			var sensorFile *os.File
			if noSensor {
				sysTier = "disabled"
			} else if f, ferr := os.Create(sensorJSONL); ferr != nil {
				return ferr
			} else {
				sensorFile = f
				sensorProc = exec.Command(sensorBin)
				sensorProc.Stdout = f
				if errf, eerr := os.Create(sensorJSONL + ".err"); eerr == nil {
					sensorProc.Stderr = errf
					defer errf.Close()
				}
				sensorProc.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
				sensorProc.Env = os.Environ()
				if sslLib != "" {
					sensorProc.Env = append(sensorProc.Env, "AGENTPROV_SSL_LIB="+sslLib)
				}
				if goTLSBin != "" {
					sensorProc.Env = append(sensorProc.Env, "AGENTPROV_GO_TLS_BIN="+goTLSBin)
				}
				fmt.Fprintf(stderr, "sandbox: model-intent tls stack=%s ssl_lib=%q go_tls_bin=%q\n", tlsStack, sslLib, goTLSBin)
				if serr := sensorProc.Start(); serr != nil {
					fmt.Fprintf(stderr, "sandbox: sensor unavailable (%v); degrading to record-only\n", serr)
					f.Close()
					sensorProc, sensorFile, sysTier = nil, nil, "unavailable"
				} else {
					time.Sleep(time.Second) // let the probes attach before the workload runs
				}
			}

			// 2) app context + scope: run the workload under record.
			result, rerr := (record.Service{DB: db, Paths: paths}).Run(record.Request{
				RunID: runID, Name: "sandbox", Workdir: workdir, Command: args,
			})
			stopSensorProc(sensorProc, sensorFile)
			if rerr != nil {
				return fmt.Errorf("run workload: %w", rerr)
			}

			// 3) passive scope binding: tie the sandbox's own cgroup to this run's
			// scope so kernel telemetry correlates even when record could not create
			// a kernel-verified cgroup (externally-scheduled / no cgroup delegation).
			telemetryScope := "none"
			if sensorProc != nil {
				if _, bound, berr := producer.BindSelfCgroup(db, producer.RunScope{
					RunID: runID, SessionID: result.SessionID, AttemptID: result.AttemptID,
					ToolCallID: result.ToolCallID, ProcessID: result.ProcessID, StartedAt: agentStart,
				}); berr != nil {
					fmt.Fprintf(stderr, "sandbox: cgroup scope bind: %v\n", berr)
				} else if bound {
					telemetryScope = "k8s_cgroup"
				}
			}

			// 4) batch-ingest the sensor telemetry AFTER the binding exists, dropping
			// anything outside this sandbox's scope (host-wide noise on a shared
			// kernel resolves to no binding and is discarded).
			scopedEvents := 0
			if sensorProc != nil {
				if f, oerr := os.Open(sensorJSONL); oerr == nil {
					opts := telemetry.JSONLIngestOptions{Format: "native", RunID: runID, DropUncorrelated: true}
					if abs, aerr := filepath.Abs(*dataDir); aerr == nil {
						opts.ExcludePathPrefixes = []string{abs}
					}
					res, ierr := telemetry.IngestJSONLReader(db, opts, f)
					f.Close()
					if ierr != nil {
						fmt.Fprintf(stderr, "sandbox: telemetry ingest: %v\n", ierr)
					} else {
						scopedEvents = res.Ingested
					}
				}
			}

			// 5) teardown durability: export a forensics bundle (optionally to a
			// mounted --out dir).
			info, xerr := (forensics.Service{DB: db, Paths: paths}).ExportBundle(runID)
			if xerr != nil {
				return fmt.Errorf("export bundle: %w", xerr)
			}
			bundleDest := info.Path
			if out != "" {
				if mkerr := os.MkdirAll(out, 0o755); mkerr == nil {
					dest := filepath.Join(out, runID+".forensics.json")
					if cerr := copyFileContents(info.Path, dest); cerr == nil {
						bundleDest = dest
					}
				}
			}

			fmt.Fprintf(c.OutOrStdout(),
				"sandbox: run=%s workload_exit=%d system_telemetry=%s telemetry_scope=%s scoped_events=%d bundle=%s bytes=%d signed=%t\n",
				runID, result.ExitCode, sysTier, telemetryScope, scopedEvents, bundleDest, info.SizeBytes, info.Signed)
			return nil
		},
	}
	// bind-cgroup: register a passive k8s_cgroup scope binding for a pod's cgroup
	// observed from the node, so the node sensor's telemetry for that pod
	// correlates to a run. Then `telemetry ingest-jsonl --run <id>` + `forensics
	// export` + `graph verify` produce a verifiable bundle for an externally-
	// scheduled pod (no `record` wrap).
	var bcRun, bcCgroup, bcSession, bcStarted, bcPodName, bcNamespace, bcLabels, bcCluster, bcNode, bcImage, bcServiceAccount, bcContainer, bcPodIP string
	bindCgroup := &cobra.Command{
		Use:   "bind-cgroup",
		Short: "bind a pod's cgroup to a run scope for node-observed telemetry (k8s-daemonset)",
		RunE: func(c *cobra.Command, _ []string) error {
			if bcRun == "" || bcCgroup == "" {
				return fmt.Errorf("--run and --cgroup-id are required")
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
			id, err := producer.BindCgroupScope(db, bcCgroup, producer.RunScope{RunID: bcRun, SessionID: bcSession, StartedAt: bcStarted})
			if err != nil {
				return err
			}
			// Optional pod metadata enrichment (lightweight alternative to a
			// client-go informer): record what the caller resolved from the K8s
			// API as a pod_metadata context event on the run. source=k8s and no
			// correlation_method, so it is not treated as runtime telemetry by verify.
			if bcPodName != "" || bcNamespace != "" || bcLabels != "" {
				payload, _ := json.Marshal(map[string]any{
					"pod_name": bcPodName, "namespace": bcNamespace, "labels": bcLabels,
					"cgroup_id": bcCgroup, "pod_uid": bcSession,
					"cluster": bcCluster, "node": bcNode, "image": bcImage,
					"service_account": bcServiceAccount, "container": bcContainer, "pod_ip": bcPodIP,
				})
				now := time.Now().UTC().Format(time.RFC3339Nano)
				if _, eerr := db.Exec(`INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, created_at)
					VALUES (?, ?, ?, '', '', 'k8s', 'pod_metadata', ?, ?)`,
					ids.New("evt"), bcRun, bcSession, string(payload), now); eerr != nil {
					fmt.Fprintf(c.ErrOrStderr(), "sandbox: pod metadata event: %v\n", eerr)
				}
			}
			fmt.Fprintf(c.OutOrStdout(), "bound cgroup=%s run=%s session=%s binding=%s source=k8s_cgroup confidence=0.8\n", bcCgroup, bcRun, bcSession, id)
			return nil
		},
	}
	bindCgroup.Flags().StringVar(&bcRun, "run", "", "run id to attribute the pod's telemetry to")
	bindCgroup.Flags().StringVar(&bcCgroup, "cgroup-id", "", "the pod's cgroup id as the sensor stamps it (kernel cgroup inode)")
	bindCgroup.Flags().StringVar(&bcSession, "session", "", "session id (e.g. the pod UID)")
	bindCgroup.Flags().StringVar(&bcStarted, "started-at", "", "binding window start (RFC3339); empty = now")
	bindCgroup.Flags().StringVar(&bcPodName, "pod-name", "", "pod name for metadata enrichment (from kubectl)")
	bindCgroup.Flags().StringVar(&bcNamespace, "namespace", "", "pod namespace for metadata enrichment")
	bindCgroup.Flags().StringVar(&bcLabels, "labels", "", "pod labels (free-form; e.g. app=x,team=y) for metadata enrichment")
	bindCgroup.Flags().StringVar(&bcCluster, "cluster", "", "cluster name/context for metadata enrichment")
	bindCgroup.Flags().StringVar(&bcNode, "node", "", "node name for metadata enrichment")
	bindCgroup.Flags().StringVar(&bcContainer, "container", "", "container name for metadata enrichment")
	bindCgroup.Flags().StringVar(&bcImage, "image", "", "container image for metadata enrichment")
	bindCgroup.Flags().StringVar(&bcServiceAccount, "service-account", "", "service account for metadata enrichment")
	bindCgroup.Flags().StringVar(&bcPodIP, "pod-ip", "", "pod IP for cross-pod influence edges (substrate lens)")
	cmd.AddCommand(bindCgroup)

	run.Flags().SetInterspersed(false)
	run.Flags().StringVar(&out, "out", "", "directory to copy the exported bundle into (mounted volume for teardown durability)")
	run.Flags().StringVar(&runID, "run", "", "run id (default generated)")
	run.Flags().StringVar(&workdir, "workdir", "", "workload working directory")
	run.Flags().StringVar(&sensorBin, "sensor-bin", "agentprov-sensor", "path to the eBPF sensor binary")
	run.Flags().StringVar(&sslLib, "ssl-lib", "", "libssl path to enable model-intent TLS capture")
	run.Flags().BoolVar(&noSensor, "no-sensor", false, "disable the eBPF sensor (record/app-context only)")
	cmd.AddCommand(run)
	return cmd
}

func stopSensorProc(proc *exec.Cmd, f *os.File) {
	if proc != nil && proc.Process != nil {
		_ = syscall.Kill(-proc.Process.Pid, syscall.SIGTERM)
		_ = proc.Wait()
	}
	if f != nil {
		f.Close()
	}
}

func copyFileContents(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	dstf, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstf.Close()
	_, err = io.Copy(dstf, in)
	return err
}
