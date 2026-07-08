// Package launch is the one-command porcelain entry point for AgentProvenance.
//
//	agentprov launch -- claude          # or codex, or any agent command
//
// It orchestrates the existing plumbing into a single zero-friction run: create
// a run scope, start the read-only dashboard, inject a per-run hooks overlay
// into the agent (Claude Code today) without touching the user's settings, start
// the kernel sensor when the host can (else degrade honestly), exec the agent in
// a dedicated cgroup, and on exit fold every source into one signed, verifiable
// evidence graph and print a one-line verdict.
//
// The design principle is honest degradation: the evidence level is two
// independent axes -- application side (transcript/hooks vs record-only) and
// system side (kernel telemetry vs none) -- printed up front so the operator
// always knows what this particular run can and cannot prove.
package launch

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/byteyellow/agentprovenance/internal/dashboard"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/hooksbridge"
	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/intent"
	"github.com/byteyellow/agentprovenance/internal/observability"
	"github.com/byteyellow/agentprovenance/internal/producer"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/store"

	"crypto/ed25519"
	"github.com/byteyellow/agentprovenance/internal/attest"
)

// Options configures a launch run.
type Options struct {
	DataDir       string   // AgentProvenance data dir (root --data-dir)
	Command       []string // the agent argv, e.g. ["claude", "-p", "..."]
	Workdir       string   // agent working directory; "" = current dir
	Dashboard     bool     // serve the read-only dashboard and keep it live after exit
	DashboardAddr string   // dashboard listen address (host:port); falls back to ephemeral if busy
	Sensor        string   // "auto" (Linux + capable) or "off"
	SignKeyPath   string   // optional hex ed25519 private key; when set, the sealed bundle is signed
	FileDiff      bool     // capture the working-tree file diff (off by default; expensive in big repos)
	SelfExe       string   // absolute path to this agentprov binary (for the sensor subprocess + hook commands)

	Stdout io.Writer
	Stderr io.Writer
}

// Report is the machine-readable outcome of a launch run.
type Report struct {
	RunID              string `json:"run_id"`
	ExitCode           int    `json:"exit_code"`
	Status             string `json:"status"`
	AppTier            string `json:"app_tier"`
	AppDetail          string `json:"app_detail,omitempty"`
	SysTier            string `json:"sys_tier"`
	SysDegradeReason   string `json:"sys_degrade_reason,omitempty"`
	Events             int    `json:"events"`
	HighRisk           int    `json:"high_risk"`
	Signals            int    `json:"signals"`
	Verdict            string `json:"verdict"`
	BundlePath         string `json:"bundle_path,omitempty"`
	Signed             bool   `json:"signed"`
	AttestationPath    string `json:"attestation_path,omitempty"`
	DashboardURL       string `json:"dashboard_url,omitempty"`
	HooksIngested      int    `json:"hooks_ingested"`
	IntentMismatches   int    `json:"intent_mismatches"`
	IntentCoverageGaps int    `json:"intent_coverage_gaps"`
	TranscriptTurns    int    `json:"transcript_turns"`
}

// transcriptPathFromHookLog returns the first transcript_path found in a run's
// hook log. Every Claude Code hook event carries it; it is stable across a
// session, so the first non-empty value is the session transcript.
func transcriptPathFromHookLog(hookLogPath string) string {
	if hookLogPath == "" {
		return ""
	}
	f, err := os.Open(hookLogPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		var ev struct {
			TranscriptPath string `json:"transcript_path"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) == nil && ev.TranscriptPath != "" {
			return ev.TranscriptPath
		}
	}
	return ""
}

// Run executes the full launch lifecycle and returns its Report. The returned
// error is a launch-infrastructure error only; a nonzero agent exit is reported
// via Report.ExitCode, not as an error, so the caller can propagate it.
func Run(opts Options) (Report, error) {
	if len(opts.Command) == 0 {
		return Report{}, fmt.Errorf("launch: a command is required after --")
	}
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.SelfExe == "" {
		if exe, err := os.Executable(); err == nil {
			opts.SelfExe = exe
		} else {
			opts.SelfExe = "agentprov"
		}
	}
	preflight := Preflight(opts)
	PrintPreflight(opts.Stderr, preflight)

	paths, err := store.Init(opts.DataDir)
	if err != nil {
		return Report{}, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return Report{}, err
	}
	defer db.Close()

	runID := ids.New("run")
	report := Report{RunID: runID, Verdict: "UNKNOWN"}

	// --- Application-side recipe: how (if at all) we can observe this agent's
	// intent without instrumenting it. Recognized harnesses get a per-run hooks
	// overlay; anything else runs record-only (execution scope + process tree).
	recipe := detectRecipe(opts.Command)
	report.AppTier = recipe.tier
	report.AppDetail = recipe.detail
	hookLogPath := ""
	var cleanupInjection func()
	command := opts.Command
	if recipe.injectHooks {
		hookLogPath = paths.Logs + string(os.PathSeparator) + "launch-" + runID + "-hooks.jsonl"
		injected, cleanup, ierr := recipe.inject(command, opts.SelfExe, hookLogPath, paths)
		if ierr != nil {
			fmt.Fprintf(opts.Stderr, "launch: hooks injection skipped: %v (app-side degrades to record-only)\n", ierr)
			report.AppTier = "record"
			report.AppDetail = "hooks injection failed: " + ierr.Error()
			hookLogPath = ""
		} else {
			command = injected
			cleanupInjection = cleanup
		}
	}
	if cleanupInjection != nil {
		defer cleanupInjection()
	}

	// --- System-side sensor: kernel telemetry when the host can provide it.
	sensorProc := (*sensorProcess)(nil)
	if opts.Sensor != "off" {
		// Model-intent auto-discovery: point the sensor's TLS uprobes at the
		// agent's own TLS stack (Go crypto/tls, static OpenSSL like node, or a
		// dynamic libssl) resolved from its executable, so intent is captured
		// without a hand-configured libssl path.
		var tlsEnv []string
		if exe, lerr := exec.LookPath(command[0]); lerr == nil {
			if t := producer.DetectTLSTarget(exe); t.Stack != "" {
				if t.SSLLib != "" {
					tlsEnv = append(tlsEnv, "AGENTPROV_SSL_LIB="+t.SSLLib)
				}
				if t.GoTLSBin != "" {
					tlsEnv = append(tlsEnv, "AGENTPROV_GO_TLS_BIN="+t.GoTLSBin)
				}
				fmt.Fprintf(opts.Stderr, "launch: model-intent tls stack=%s ssl_lib=%q go_tls_bin=%q\n", t.Stack, t.SSLLib, t.GoTLSBin)
			}
		}
		sp, tier, reason := startSensor(opts.SelfExe, opts.DataDir, opts.Stderr, tlsEnv)
		report.SysTier = tier
		report.SysDegradeReason = reason
		sensorProc = sp
	} else {
		report.SysTier = "none"
		report.SysDegradeReason = "disabled via --sensor=off"
	}
	if sensorProc != nil {
		defer sensorProc.stop()
	}

	// --- Dashboard: live throughout the run and kept alive after exit so the
	// printed URL is real.
	var dashListener net.Listener
	if opts.Dashboard {
		ln, url := startDashboard(db, opts.DashboardAddr, opts.Stderr)
		if ln != nil {
			dashListener = ln
			report.DashboardURL = url
			defer dashListener.Close()
		}
	}

	printBanner(opts.Stderr, report, command)

	// Keep launch alive across the interactive agent's Ctrl-C: the agent shares
	// our process group and receives SIGINT directly, so we only need to stop
	// Go's default terminate-without-defers behavior. Buffered so a burst of
	// signals never blocks; drained before we reuse the channel for the
	// post-run dashboard wait.
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	// --- Exec the agent in a dedicated cgroup (kernel telemetry auto-joins by
	// cgroup_id). record.Run blocks until the agent exits.
	result, rerr := (record.Service{DB: db, Paths: paths}).Run(record.Request{
		RunID:           runID,
		Name:            "launch",
		Workdir:         opts.Workdir,
		Command:         command,
		DisableSnapshot: !opts.FileDiff,
	})
	if rerr != nil {
		return report, fmt.Errorf("launch: exec agent: %w", rerr)
	}
	report.ExitCode = result.ExitCode
	report.Status = result.Status

	// Stop the sensor before sealing so its final correlated events are flushed.
	if sensorProc != nil {
		sensorProc.stop()
		sensorProc = nil
	}

	// --- Seal: fold every source into the graph, apply policy, summarize, sign.
	seal(db, paths, runID, hookLogPath, opts.SignKeyPath, &report, opts.Stderr)

	printVerdict(opts.Stdout, report)

	// --- Keep the dashboard live for inspection until the operator quits.
	if dashListener != nil {
		drain(sigCh)
		fmt.Fprintf(opts.Stdout, "\ndashboard live at %s  (Ctrl-C to exit)\n", report.DashboardURL)
		<-sigCh
	}
	return report, nil
}

// seal folds the run's hook log, LLM traffic, and policy verdict into the signed
// evidence graph and fills the risk/bundle fields of report. Best-effort: a
// failure in any stage is reported to stderr but does not abort the others, so
// the operator always gets whatever evidence was capturable.
func seal(db *sql.DB, paths store.Paths, runID, hookLogPath, signKeyPath string, report *Report, stderr io.Writer) {
	if hookLogPath != "" {
		if f, err := os.Open(hookLogPath); err == nil {
			sum, ierr := hooksbridge.Ingest(db, f, hooksbridge.Options{
				RunID:   runID,
				Objects: provenance.ObjectStore{DB: db, Paths: paths},
			})
			f.Close()
			if ierr != nil {
				fmt.Fprintf(stderr, "launch: hooks ingest: %v\n", ierr)
			} else {
				report.HooksIngested = sum.ToolCalls
				if _, cerr := hooksbridge.CorrelateSyscalls(db, runID); cerr != nil {
					fmt.Fprintf(stderr, "launch: syscall correlation: %v\n", cerr)
				}
			}
		}
	}

	// Materialize any captured TLS bodies into llm_call nodes (a no-op without
	// --ssl-lib), then harvest the Claude Code session transcript into the SAME
	// llm_call model -- the model's real prompt, reasoning, and tool decisions
	// (the cognitive-intent axis), zero-instrumentation and platform-independent.
	if _, err := provenance.MaterializeLLMCalls(provenance.ObjectStore{DB: db, Paths: paths}, db, runID); err != nil {
		fmt.Fprintf(stderr, "launch: materialize llm: %v\n", err)
	}
	if tp := transcriptPathFromHookLog(hookLogPath); tp != "" {
		if turns, err := provenance.HarvestTranscript(provenance.ObjectStore{DB: db, Paths: paths}, db, runID, tp); err != nil {
			fmt.Fprintf(stderr, "launch: harvest transcript: %v\n", err)
		} else {
			report.TranscriptTurns = turns
		}
	}

	// Reconcile declared intent (hook tool calls) against observed runtime
	// effects: a boundary violation (e.g. an exec that read a foreign secret) or
	// a refusal bypass is the intent-layer finding the raw risk count alone
	// cannot express.
	if idr, err := intent.Materialize(db, runID); err != nil {
		fmt.Fprintf(stderr, "launch: intent diff: %v\n", err)
	} else {
		report.IntentMismatches = idr.Mismatches
		report.IntentCoverageGaps = idr.CoverageGaps
	}

	// Apply policy to the captured events so the verdict reads policy-applied
	// risk (the self_credential_access allow rule keeps the agent's own creds
	// reads from flooding every run as FLAGGED), then summarize.
	if _, _, err := security.ReevaluateRun(db, runID, security.DefaultEngine()); err != nil {
		fmt.Fprintf(stderr, "launch: policy reevaluate: %v\n", err)
	}
	summary, err := observability.BuildSummary(db, observability.SummaryOptions{RunID: runID})
	if err != nil {
		fmt.Fprintf(stderr, "launch: summary: %v\n", err)
	} else {
		report.Events = summary.Runtime.Events
		report.Signals = summary.Risk.Signals
		report.HighRisk = summary.Risk.BySeverity["high"] + summary.Risk.BySeverity["critical"]
	}
	if report.HighRisk > 0 || report.IntentMismatches > 0 {
		report.Verdict = "FLAGGED"
	} else {
		report.Verdict = "CLEAN"
	}

	// Export a signed, verifiable bundle -- the durable replayable artifact that
	// outlives the local store.
	svc := forensics.Service{DB: db, Paths: paths}
	if signKeyPath != "" {
		if key, kerr := attest.LoadPrivateKeyHex(signKeyPath); kerr != nil {
			fmt.Fprintf(stderr, "launch: load sign key: %v\n", kerr)
		} else {
			svc.SignKey = key
			svc.SignKeyID = attest.KeyID(key.Public().(ed25519.PublicKey))
		}
	}
	bundle, berr := svc.ExportBundle(runID)
	if berr != nil {
		fmt.Fprintf(stderr, "launch: export bundle: %v\n", berr)
	} else {
		report.BundlePath = bundle.Path
		report.Signed = bundle.Signed
		report.AttestationPath = bundle.AttestationPath
	}
}

func startDashboard(db *sql.DB, addr string, stderr io.Writer) (net.Listener, string) {
	if addr == "" {
		addr = "127.0.0.1:7396"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		// Preferred port busy: fall back to an ephemeral port so launch never
		// fails just because a prior dashboard is up.
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Fprintf(stderr, "launch: dashboard listen failed: %v (continuing without dashboard)\n", err)
			return nil, ""
		}
	}
	url := fmt.Sprintf("http://%s/", ln.Addr().String())
	srv := &http.Server{Handler: dashboard.Server{DB: db}.Handler()}
	go func() { _ = srv.Serve(ln) }()
	return ln, url
}

func printBanner(w io.Writer, r Report, command []string) {
	fmt.Fprintf(w, "\nagentprov launch  run=%s\n", r.RunID)
	fmt.Fprintf(w, "  agent      : %s\n", strings.Join(command, " "))
	app := r.AppTier
	if r.AppDetail != "" {
		app += "  (" + r.AppDetail + ")"
	}
	fmt.Fprintf(w, "  app  side  : %s\n", app)
	sys := r.SysTier
	if r.SysDegradeReason != "" {
		sys += "  (" + r.SysDegradeReason + ")"
	}
	fmt.Fprintf(w, "  sys  side  : %s\n", sys)
	fmt.Fprintf(w, "  evidence   : %s\n", evidenceLevel(r))
	if r.DashboardURL != "" {
		fmt.Fprintf(w, "  dashboard  : %s\n", r.DashboardURL)
	}
	fmt.Fprintln(w, "  ────────────────────────────────────────")
}

// PrintPreflight renders the same readiness checks used by `agentprov doctor`.
// Warn/skip states are not fatal: launch is intentionally degradation-friendly.
func PrintPreflight(w io.Writer, r PreflightReport) {
	if w == nil {
		return
	}
	fmt.Fprintln(w, "\nagentprov preflight")
	for _, c := range r.Checks {
		mark := "✓"
		switch c.Status {
		case CheckWarn:
			mark = "!"
		case CheckFail:
			mark = "x"
		case CheckSkip:
			mark = "-"
		}
		fmt.Fprintf(w, "  %s %-16s %s\n", mark, c.Name+":", c.Detail)
		if c.Fix != "" {
			fmt.Fprintf(w, "    fix: %s\n", c.Fix)
		}
	}
}

// evidenceLevel names the combined tier in plain terms so the operator is never
// misled about what a run can prove.
func evidenceLevel(r Report) string {
	kernel := r.SysTier == "kernel"
	hooks := r.AppTier != "record" && r.AppTier != ""
	switch {
	case kernel && hooks:
		return "full: kernel telemetry + agent intent (hooks)"
	case kernel:
		return "kernel telemetry only (no agent-intent hooks)"
	case hooks:
		return "app-side only: agent intent (hooks) + execution scope, no kernel telemetry"
	default:
		return "record-only: execution scope + process tree"
	}
}

func printVerdict(w io.Writer, r Report) {
	mark := "✓"
	if r.Verdict != "CLEAN" {
		mark = "⚠"
	}
	signed := "unsigned"
	if r.Signed {
		signed = "signed"
	}
	fmt.Fprintf(w, "\n%s  %s  run=%s exit=%d  events=%d signals=%d high_risk=%d intent_mismatch=%d\n",
		mark, r.Verdict, r.RunID, r.ExitCode, r.Events, r.Signals, r.HighRisk, r.IntentMismatches)
	if r.BundlePath != "" {
		fmt.Fprintf(w, "   bundle=%s (%s)\n", r.BundlePath, signed)
	}
	if r.DashboardURL != "" {
		fmt.Fprintf(w, "   dashboard=%s\n", r.DashboardURL)
	}
}

// drain empties any buffered signals so a Ctrl-C used to stop the agent does not
// immediately fall through the post-run dashboard wait.
func drain(ch chan os.Signal) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// scanReady reports true when it sees the sensor's ready banner on the given
// reader, or false if the reader closes first. It always drains the reader into
// buf so a failure's stderr is available for the degrade reason.
func scanReady(r io.Reader, ready chan<- struct{}, buf *strings.Builder) {
	sc := bufio.NewScanner(r)
	seen := false
	for sc.Scan() {
		line := sc.Text()
		buf.WriteString(line)
		buf.WriteByte('\n')
		if !seen && strings.Contains(line, "ready probes-attached") {
			seen = true
			select {
			case ready <- struct{}{}:
			default:
			}
		}
	}
}
