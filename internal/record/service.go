package record

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/redact"
	"github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/substrate/state"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

type Service struct {
	DB    *sql.DB
	Paths store.Paths
}

type Request struct {
	RunID            string   `json:"run_id"`
	Name             string   `json:"name"`
	Workdir          string   `json:"workdir"`
	Command          []string `json:"command"`
	SampleIntervalMS int64    `json:"sample_interval_ms"`
	PostRootGraceMS  int64    `json:"post_root_grace_ms"`
}

type Result struct {
	RunID            string            `json:"run_id"`
	RolloutID        string            `json:"rollout_id"`
	BaseSnapshotID   string            `json:"base_snapshot_id"`
	AttemptID        string            `json:"attempt_id"`
	SessionID        string            `json:"session_id"`
	ToolCallID       string            `json:"tool_call_id"`
	ProcessID        string            `json:"process_id"`
	Workdir          string            `json:"workdir"`
	Command          string            `json:"command"`
	ExitCode         int               `json:"exit_code"`
	Status           string            `json:"status"`
	WallMS           int64             `json:"wall_ms"`
	ChangedFiles     []string          `json:"changed_files"`
	RootPID          int64             `json:"root_pid"`
	Observed         []ObservedProcess `json:"observed"`
	OrphanPolicy     string            `json:"orphan_policy"`
	SampleIntervalMS int64             `json:"sample_interval_ms"`
	PostRootGraceMS  int64             `json:"post_root_grace_ms"`
	CWD              string            `json:"cwd"`
	StartedAt        string            `json:"started_at"`
	EndedAt          string            `json:"ended_at"`
	FailureReason    string            `json:"failure_reason"`
}

type ObservedProcess struct {
	PID          int64  `json:"pid"`
	PPID         int64  `json:"ppid"`
	Command      string `json:"command"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
	OutlivedRoot bool   `json:"outlived_root"`
}

func (s Service) Run(req Request) (Result, error) {
	if len(req.Command) == 0 {
		return Result{}, fmt.Errorf("command is required after --")
	}
	workdir := strings.TrimSpace(req.Workdir)
	if workdir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return Result{}, err
		}
		workdir = cwd
	}
	absWorkdir, err := filepath.Abs(workdir)
	if err != nil {
		return Result{}, err
	}
	if req.RunID == "" {
		req.RunID = ids.New("run")
	}
	if req.Name == "" {
		req.Name = "record"
	}
	sampleInterval := time.Duration(req.SampleIntervalMS) * time.Millisecond
	if sampleInterval <= 0 {
		sampleInterval = 25 * time.Millisecond
	}
	postRootGrace := time.Duration(req.PostRootGraceMS) * time.Millisecond
	if postRootGrace <= 0 {
		postRootGrace = 250 * time.Millisecond
	}
	commandText := strings.Join(req.Command, " ")
	now := time.Now().UTC().Format(time.RFC3339Nano)

	baseSnapshotID := ids.New("snap")
	baseDir := filepath.Join(s.Paths.Snapshots, baseSnapshotID)
	// Exclude .git/.agentprov from the base snapshot, matching the diff path's
	// ignoredPath. This keeps the snapshot clean and (with the dst-subtree guard
	// in CopyDirFiltered) prevents self-recursion when the .agentprov data dir
	// lives inside the workdir being recorded.
	if err := state.CopyDirFiltered(absWorkdir, baseDir, ignoredPath); err != nil {
		return Result{}, err
	}
	baseManifest, err := state.BuildManifest(baseDir)
	if err != nil {
		return Result{}, err
	}
	_, err = s.DB.Exec(`INSERT INTO snapshots
		(id, name, kind, source, path, manifest_hash, file_count, bytes, snapshot_semantic_type, snapshot_physical_type, logical_bytes, physical_bytes, dirty_bytes_estimate, inode_estimate, storage_amplification_ratio, status, created_at)
		VALUES (?, ?, 'ready', 'record', ?, ?, ?, ?, 'directory', 'copy', ?, ?, ?, ?, 1, 'ready', ?)`,
		baseSnapshotID, req.Name+"-base", baseDir, baseManifest.Hash, baseManifest.Files, baseManifest.Bytes, baseManifest.Bytes, baseManifest.Bytes, baseManifest.Bytes, baseManifest.Files, now)
	if err != nil {
		return Result{}, err
	}

	rolloutID := ids.New("rollout")
	attemptID := ids.New("attempt")
	sessionID := "record-" + attemptID
	leaseID := "lease-" + attemptID
	toolCallID := ids.New("tool")
	processID := ids.New("proc")
	_, err = s.DB.Exec(`INSERT INTO leases (id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES (?, ?, ?, '{}', 'allocated', ?, ?)`, leaseID, req.RunID, "record:"+absWorkdir, now, now)
	if err != nil {
		return Result{}, err
	}
	_, err = s.DB.Exec(`INSERT INTO sessions
		(id, lease_id, run_id, container_id, workspace_host_path, runtime, parent_snapshot_id, status, startup_cold_ms, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 'record', ?, 'running', 0, ?, ?)`,
		sessionID, leaseID, req.RunID, "agentprov-record-"+attemptID, absWorkdir, baseSnapshotID, now, now)
	if err != nil {
		return Result{}, err
	}
	_, err = s.DB.Exec(`INSERT INTO rollouts
		(id, run_id, task_path, base_snapshot_id, status, fanout, risk_status, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'running', 1, 'pending', ?, ?)`,
		rolloutID, req.RunID, "record:"+absWorkdir, baseSnapshotID, now, now)
	if err != nil {
		return Result{}, err
	}
	_, err = s.DB.Exec(`INSERT INTO fork_attempts
		(id, rollout_id, tool_call_id, snapshot_id, workspace_path, fork_ms, strategy, command, status, risk_status, created_at)
		VALUES (?, ?, ?, ?, ?, 0, 'zero-sdk-record', ?, 'running', 'clean', ?)`,
		attemptID, rolloutID, toolCallID, baseSnapshotID, absWorkdir, commandText, now)
	if err != nil {
		return Result{}, err
	}
	_, err = s.DB.Exec(`INSERT INTO tool_calls
		(id, run_id, rollout_id, attempt_id, session_id, command, args_hash, status, policy_decision, created_at, started_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'running', 'allow', ?, ?)`,
		toolCallID, req.RunID, rolloutID, attemptID, sessionID, commandText, argsHash(commandText), now, now)
	if err != nil {
		return Result{}, err
	}
	_, err = s.DB.Exec(`INSERT INTO processes
		(id, session_id, tool_call_id, command, status, started_at)
		VALUES (?, ?, ?, ?, 'running', ?)`, processID, sessionID, toolCallID, commandText, now)
	if err != nil {
		return Result{}, err
	}
	s.insertGraphEdges(req.RunID, rolloutID, baseSnapshotID, attemptID, sessionID, toolCallID, processID, now)

	cmd := exec.Command(req.Command[0], req.Command[1:]...)
	cmd.Dir = absWorkdir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	// Place the child (and, by inheritance, its whole subtree) into a dedicated
	// cgroup so independent kernel telemetry auto-joins to this scope by
	// cgroup_id at 0.98 -- no pid polling, no pid-reuse window. On Linux this
	// returns the real cgroup inode (== bpf_get_current_cgroup_id); elsewhere it
	// falls back to the synthetic logical id, preserving prior behavior. See
	// cgroup_linux.go / cgroup_other.go.
	scopeCgroupID, scopeCleanup := prepareScopeCgroup(cmd, attemptID)
	defer scopeCleanup()
	start := time.Now()
	startedAt := start.UTC().Format(time.RFC3339Nano)
	if err := cmd.Start(); err != nil {
		endedAt := time.Now().UTC().Format(time.RFC3339Nano)
		_ = s.markFailed(req.RunID, rolloutID, attemptID, sessionID, toolCallID, processID, err.Error())
		_, _ = correlation.RecordBinding(s.DB, correlation.Binding{
			RunID:         req.RunID,
			SessionID:     sessionID,
			AttemptID:     attemptID,
			ToolCallID:    toolCallID,
			ProcessID:     processID,
			ContainerID:   "agentprov-record-" + attemptID,
			CgroupID:      scopeCgroupID,
			StartedAt:     startedAt,
			EndedAt:       endedAt,
			BindingSource: "zero_sdk_record",
		})
		return Result{
			RunID:          req.RunID,
			RolloutID:      rolloutID,
			BaseSnapshotID: baseSnapshotID,
			AttemptID:      attemptID,
			SessionID:      sessionID,
			ToolCallID:     toolCallID,
			ProcessID:      processID,
			Workdir:        absWorkdir,
			Command:        commandText,
			ExitCode:       125,
			Status:         "failed",
			WallMS:         time.Since(start).Milliseconds(),
			CWD:            absWorkdir,
			StartedAt:      startedAt,
			EndedAt:        endedAt,
			FailureReason:  err.Error(),
		}, nil
	}
	pid := int64(cmd.Process.Pid)
	_, _ = correlation.RecordBinding(s.DB, correlation.Binding{
		RunID:         req.RunID,
		SessionID:     sessionID,
		AttemptID:     attemptID,
		ToolCallID:    toolCallID,
		ProcessID:     processID,
		ContainerID:   "agentprov-record-" + attemptID,
		CgroupID:      scopeCgroupID,
		RootPID:       pid,
		PID:           pid,
		StartedAt:     startedAt,
		BindingSource: "zero_sdk_record",
	})
	_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, source, event_type, pid, ppid, payload, created_at)
		VALUES (?, ?, ?, ?, ?, 'record', 'exec_start', ?, ?, ?, ?)`,
		ids.New("evt"), req.RunID, sessionID, toolCallID, processID, pid, int64(os.Getpid()), fmt.Sprintf(`{"attempt_id":%q,"command":%q,"mode":"zero_sdk"}`, attemptID, commandText), startedAt)

	stopSampler := make(chan struct{})
	samplerDone := make(chan []ObservedProcess, 1)
	go sampleProcessTree(pid, sampleInterval, stopSampler, samplerDone)

	err = cmd.Wait()
	postRootGraceStarted := time.Now()
	time.Sleep(postRootGrace)
	close(stopSampler)
	observed := markOutlivedRoot(<-samplerDone, postRootGraceStarted.UTC().Format(time.RFC3339Nano))
	wallMS := time.Since(start).Milliseconds()
	exitCode := 0
	status := "passed"
	if err != nil {
		status = "failed"
		exitCode = 1
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
	}
	endedAt := time.Now().UTC().Format(time.RFC3339Nano)
	for _, proc := range observed {
		_, _ = correlation.RecordBinding(s.DB, correlation.Binding{
			RunID:         req.RunID,
			SessionID:     sessionID,
			AttemptID:     attemptID,
			ToolCallID:    toolCallID,
			ProcessID:     processID,
			ContainerID:   "agentprov-record-" + attemptID,
			CgroupID:      scopeCgroupID,
			RootPID:       pid,
			PID:           proc.PID,
			StartedAt:     proc.FirstSeen,
			EndedAt:       proc.LastSeen,
			BindingSource: "zero_sdk_record_descendant",
			Confidence:    0.9,
		})
		payload, _ := json.Marshal(observedProcessPayload(proc, pid, absWorkdir, "root_pid_descendants+cwd+time_window"))
		_, _ = telemetry.IngestFiltered(s.DB, telemetry.IngestEvent{
			RunID:       req.RunID,
			RolloutID:   rolloutID,
			AttemptID:   attemptID,
			SessionID:   sessionID,
			ToolCallID:  toolCallID,
			ProcessID:   processID,
			SnapshotID:  baseSnapshotID,
			RawEventID:  fmt.Sprintf("record-process-%d", proc.PID),
			ContainerID: "agentprov-record-" + attemptID,
			CgroupID:    scopeCgroupID,
			PID:         proc.PID,
			TGID:        proc.PID,
			PPID:        proc.PPID,
			Timestamp:   proc.FirstSeen,
			Source:      "record_process_sample",
			EventType:   "process_observed",
			Payload:     string(payload),
		})
		if proc.OutlivedRoot {
			_ = s.persistOrphanDecision(req.RunID, rolloutID, attemptID, sessionID, toolCallID, processID, proc, string(payload))
		}
	}
	changed, diffErr := changedFiles(baseDir, absWorkdir)
	if diffErr != nil {
		changed = append(changed, "diff_error:"+diffErr.Error())
	}
	for _, path := range changed {
		if strings.HasPrefix(path, "diff_error:") {
			continue
		}
		_, _ = telemetry.IngestFiltered(s.DB, telemetry.IngestEvent{
			RunID:       req.RunID,
			RolloutID:   rolloutID,
			AttemptID:   attemptID,
			SessionID:   sessionID,
			ToolCallID:  toolCallID,
			ProcessID:   processID,
			SnapshotID:  baseSnapshotID,
			RawEventID:  "record-file-" + path,
			ContainerID: "agentprov-record-" + attemptID,
			CgroupID:    scopeCgroupID,
			PID:         pid,
			TGID:        pid,
			PPID:        int64(os.Getpid()),
			Timestamp:   endedAt,
			Source:      "record_file_diff",
			EventType:   "file_write",
			Payload:     fmt.Sprintf(`{"path":%q,"op":"record_diff","mode":"zero_sdk"}`, path),
		})
		// Objectify the changed file's CONTENT as an artifact object so the
		// dashboard Side Panel can preview "what the agent actually produced"
		// (the file_write event above only records that it changed, not the
		// bytes). Previously a manual post-capture script did this and was easy
		// to forget -- making it built-in is the root fix for empty Artifacts /
		// no previewable products.
		s.objectifyArtifact(req.RunID, rolloutID, absWorkdir, path)
	}
	_, _ = s.DB.Exec(`UPDATE processes SET status = ?, exit_code = ?, ended_at = ? WHERE id = ?`, processStatus(status), exitCode, endedAt, processID)
	_, _ = s.DB.Exec(`UPDATE sessions SET status = 'stopped', updated_at = ? WHERE id = ?`, endedAt, sessionID)
	_, _ = s.DB.Exec(`UPDATE tool_calls SET status = ?, exit_code = ?, wall_ms = ?, cost_estimate = ?, ended_at = ? WHERE id = ?`,
		status, exitCode, wallMS, float64(wallMS)/1000.0*0.001, endedAt, toolCallID)
	_, _ = s.DB.Exec(`UPDATE fork_attempts SET status = ?, exit_code = ?, wall_ms = ?, score = ?, cost_estimate = ?, output_summary = ?, is_winner = 1 WHERE id = ?`,
		status, exitCode, wallMS, score(exitCode, wallMS), float64(wallMS)/1000.0*0.001, fmt.Sprintf("changed_files=%d", len(changed)), attemptID)
	_, _ = s.DB.Exec(`UPDATE rollouts SET status = 'completed', winner_attempt_id = ?, cost_estimate = ?, risk_status = 'clean', updated_at = ? WHERE id = ?`,
		attemptID, float64(wallMS)/1000.0*0.001, endedAt, rolloutID)
	_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, source, event_type, pid, ppid, payload, created_at)
		VALUES (?, ?, ?, ?, ?, 'record', 'exec_end', ?, ?, ?, ?)`,
		ids.New("evt"), req.RunID, sessionID, toolCallID, processID, pid, int64(os.Getpid()), fmt.Sprintf(`{"attempt_id":%q,"exit_code":%d,"status":%q,"wall_ms":%d,"changed_files":%d}`, attemptID, exitCode, status, wallMS, len(changed)), endedAt)
	_ = correlation.CloseBinding(s.DB, processID, endedAt)
	return Result{
		RunID:            req.RunID,
		RolloutID:        rolloutID,
		BaseSnapshotID:   baseSnapshotID,
		AttemptID:        attemptID,
		SessionID:        sessionID,
		ToolCallID:       toolCallID,
		ProcessID:        processID,
		Workdir:          absWorkdir,
		Command:          commandText,
		ExitCode:         exitCode,
		Status:           status,
		WallMS:           wallMS,
		ChangedFiles:     changed,
		RootPID:          pid,
		Observed:         observed,
		OrphanPolicy:     "observe_only",
		SampleIntervalMS: sampleInterval.Milliseconds(),
		PostRootGraceMS:  postRootGrace.Milliseconds(),
		CWD:              absWorkdir,
		StartedAt:        startedAt,
		EndedAt:          endedAt,
	}, nil
}

func observedProcessPayload(proc ObservedProcess, rootPID int64, cwd, boundary string) map[string]any {
	return map[string]any{
		"pid":             proc.PID,
		"ppid":            proc.PPID,
		"root_pid":        rootPID,
		"command":         proc.Command,
		"first_seen":      proc.FirstSeen,
		"last_seen":       proc.LastSeen,
		"outlived_root":   proc.OutlivedRoot,
		"cwd":             cwd,
		"scope_boundary":  boundary,
		"correlation_key": "pid+root_pid+cwd+time_window",
		"mode":            "zero_sdk",
	}
}

func (s Service) persistOrphanDecision(runID, rolloutID, attemptID, sessionID, toolCallID, processID string, proc ObservedProcess, payload string) error {
	record, err := security.PersistDecision(s.DB, security.Event{
		Source:     "zero_sdk_record",
		EventType:  "abnormal_process_tree",
		RunID:      runID,
		SessionID:  sessionID,
		ToolCallID: toolCallID,
		ProcessID:  processID,
		Args:       []string{proc.Command},
	}, payload, security.Decision{
		RuleID:   "zero_sdk_orphan_observe_only",
		Decision: "audit",
		Reason:   fmt.Sprintf("observed descendant pid %d outlived root; policy=observe_only", proc.PID),
	})
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = s.DB.Exec(`INSERT INTO evidence_events
		(id, run_id, rollout_id, attempt_id, session_id, tool_call_id, event_type, priority, payload, status, created_at, processed_at)
		VALUES (?, ?, ?, ?, ?, ?, 'orphan_lifecycle_decision', 'normal', ?, 'processed', ?, ?)`,
		ids.New("evidence"), runID, rolloutID, attemptID, sessionID, toolCallID,
		fmt.Sprintf(`{"policy_decision_id":%q,"rule_id":"zero_sdk_orphan_observe_only","decision":"audit","action":"observe_only","pid":%d,"payload":%s}`, record.ID, proc.PID, payload),
		now, now)
	return nil
}

func markOutlivedRoot(procs []ObservedProcess, rootEndedAt string) []ObservedProcess {
	table, _ := processTable()
	alive := map[int64]bool{}
	for _, proc := range table {
		alive[proc.PID] = true
	}
	for i := range procs {
		if procs[i].LastSeen >= rootEndedAt || alive[procs[i].PID] {
			procs[i].OutlivedRoot = true
		}
	}
	return procs
}

func sampleProcessTree(rootPID int64, interval time.Duration, stop <-chan struct{}, done chan<- []ObservedProcess) {
	seen := map[int64]ObservedProcess{}
	var mu sync.Mutex
	record := func() {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		procs, err := processTable()
		if err != nil {
			return
		}
		descendants := descendantsOf(rootPID, procs)
		mu.Lock()
		defer mu.Unlock()
		for _, proc := range descendants {
			if proc.PID == rootPID {
				continue
			}
			prev, ok := seen[proc.PID]
			if !ok {
				proc.FirstSeen = now
				proc.LastSeen = now
				seen[proc.PID] = proc
				continue
			}
			prev.PPID = proc.PPID
			prev.Command = proc.Command
			prev.LastSeen = now
			seen[proc.PID] = prev
		}
	}
	record()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			record()
		case <-stop:
			record()
			out := make([]ObservedProcess, 0, len(seen))
			for _, proc := range seen {
				out = append(out, proc)
			}
			sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
			done <- out
			return
		}
	}
}

func processTable() ([]ObservedProcess, error) {
	out, err := exec.Command("ps", "-Ao", "pid=,ppid=,command=").Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(out), "\n")
	var procs []ObservedProcess
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		var pid, ppid int64
		if _, err := fmt.Sscanf(fields[0], "%d", &pid); err != nil {
			continue
		}
		if _, err := fmt.Sscanf(fields[1], "%d", &ppid); err != nil {
			continue
		}
		command := ""
		if len(fields) > 2 {
			command = strings.Join(fields[2:], " ")
		}
		procs = append(procs, ObservedProcess{PID: pid, PPID: ppid, Command: command})
	}
	return procs, nil
}

func descendantsOf(rootPID int64, procs []ObservedProcess) []ObservedProcess {
	children := map[int64][]ObservedProcess{}
	for _, proc := range procs {
		children[proc.PPID] = append(children[proc.PPID], proc)
	}
	var out []ObservedProcess
	queue := []int64{rootPID}
	seen := map[int64]bool{rootPID: true}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		for _, child := range children[parent] {
			if seen[child.PID] {
				continue
			}
			seen[child.PID] = true
			out = append(out, child)
			queue = append(queue, child.PID)
		}
	}
	return out
}

func (s Service) insertGraphEdges(runID, rolloutID, snapshotID, attemptID, sessionID, toolCallID, processID, createdAt string) {
	edges := [][3]string{
		{rolloutID, attemptID, "rollout_attempt"},
		{snapshotID, attemptID, "snapshot_attempt"},
		{attemptID, toolCallID, "attempt_tool_call"},
		{attemptID, sessionID, "attempt_session"},
		{toolCallID, sessionID, "tool_call_session"},
		{toolCallID, processID, "tool_call_process"},
	}
	for _, edge := range edges {
		_, _ = s.DB.Exec(`INSERT INTO graph_edges (id, run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at)
			VALUES (?, ?, ?, ?, ?, ?, 'record', ?)`,
			ids.New("edge"), runID, rolloutID, edge[0], edge[1], edge[2], createdAt)
	}
}

func (s Service) markFailed(runID, rolloutID, attemptID, sessionID, toolCallID, processID, reason string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = s.DB.Exec(`UPDATE processes SET status = 'failed', exit_code = 125, ended_at = ? WHERE id = ?`, now, processID)
	_, _ = s.DB.Exec(`UPDATE sessions SET status = 'stopped', updated_at = ? WHERE id = ?`, now, sessionID)
	_, _ = s.DB.Exec(`UPDATE tool_calls SET status = 'failed', exit_code = 125, result_ref = ?, ended_at = ? WHERE id = ?`, reason, now, toolCallID)
	_, _ = s.DB.Exec(`UPDATE fork_attempts SET status = 'failed', exit_code = 125, output_summary = ? WHERE id = ?`, reason, attemptID)
	_, _ = s.DB.Exec(`UPDATE rollouts SET status = 'failed', updated_at = ? WHERE id = ?`, now, rolloutID)
	_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, ?, ?, 'record', 'exec_error', ?, ?)`,
		ids.New("evt"), runID, sessionID, toolCallID, processID, fmt.Sprintf(`{"reason":%q}`, reason), now)
	return nil
}

// maxObjectifyBytes bounds how large a changed file we objectify for preview.
// The Side Panel reads up to 8MiB, but storing every large/binary blob inline
// would bloat the object store; files above this cap keep their file_write event
// (so the change is still recorded) but are not content-objectified.
const maxObjectifyBytes = 1 << 20

// objectifyArtifact stores a changed file's content as a content-addressed
// "artifact" provenance object keyed to the lens node id (workspace_file/<rel>),
// so the dashboard resolves and previews it. Best-effort: any failure (missing,
// oversized, unreadable) is skipped silently -- the file_write event still
// records that the file changed.
//
// The envelope is written inline (not via provenance.ObjectStore) to avoid an
// import cycle: record -> provenance would cycle because provenance's tests
// import record. It reproduces the exact schema the dashboard preview unwraps
// (schema/type/payload.content) and that `graph verify` accepts -- the same
// canonical, key-sorted JSON the object store and the prior manual objectify
// script produced.
func (s Service) objectifyArtifact(runID, rolloutID, workdir, rel string) {
	fp := filepath.Join(workdir, rel)
	info, err := os.Stat(fp)
	if err != nil || info.IsDir() || info.Size() > maxObjectifyBytes {
		return
	}
	data, err := os.ReadFile(fp)
	if err != nil {
		return
	}
	// json.Marshal sorts map keys, matching the canonical form the object store
	// hashes; the hash is over these exact bytes, so verify stays consistent.
	raw, err := json.Marshal(map[string]any{
		"schema":    "agentprov.provenance.object.v1",
		"type":      "artifact",
		"source_id": "workspace_file/" + rel,
		"run_id":    runID,
		"payload":   map[string]any{"path": rel, "size": len(data), "content": string(data)},
	})
	if err != nil {
		return
	}
	// Mask secrets before the file content is hashed and stored: an agent can
	// write a key into a file, and this content becomes a previewable, exportable,
	// content-addressed object. Redact before the hash so the object stays
	// self-consistent (stored hash matches the stored, masked bytes on import).
	if red, changed := redact.Redact(string(raw)); changed {
		raw = []byte(red)
	}
	sum := sha256.Sum256(raw)
	h := hex.EncodeToString(sum[:])
	provRoot := s.Paths.Provenance
	if provRoot == "" {
		provRoot = filepath.Join(s.Paths.Root, "provenance")
	}
	objDir := filepath.Join(provRoot, "objects", "sha256", h[:2])
	if err := os.MkdirAll(objDir, 0o755); err != nil {
		return
	}
	objPath := filepath.Join(objDir, h+".json")
	if err := os.WriteFile(objPath, raw, 0o644); err != nil {
		return
	}
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO provenance_objects
		(hash, object_type, source_id, run_id, rollout_id, parent_hashes, path, size_bytes, created_at)
		VALUES (?, 'artifact', ?, ?, ?, '', ?, ?, ?)`,
		"sha256:"+h, "workspace_file/"+rel, runID, rolloutID, objPath, len(raw), time.Now().UTC().Format(time.RFC3339Nano))
}

func changedFiles(baseDir, workdir string) ([]string, error) {
	base, err := state.BuildFileManifest(baseDir)
	if err != nil {
		return nil, err
	}
	current, err := state.BuildFileManifest(workdir)
	if err != nil {
		return nil, err
	}
	changedSet := map[string]bool{}
	baseByPath := map[string]state.FileEntry{}
	for _, entry := range base {
		baseByPath[entry.Path] = entry
	}
	currentByPath := map[string]state.FileEntry{}
	for _, entry := range current {
		currentByPath[entry.Path] = entry
	}
	for path, entry := range currentByPath {
		if ignoredPath(path) {
			continue
		}
		if before, ok := baseByPath[path]; !ok || before.Hash != entry.Hash {
			changedSet[path] = true
		}
	}
	for path := range baseByPath {
		if ignoredPath(path) {
			continue
		}
		if _, ok := currentByPath[path]; !ok {
			changedSet[path] = true
		}
	}
	changed := make([]string, 0, len(changedSet))
	for path := range changedSet {
		changed = append(changed, path)
	}
	sort.Strings(changed)
	return changed, nil
}

func ignoredPath(path string) bool {
	return path == ".git" || strings.HasPrefix(path, ".git/") ||
		path == ".agentprov" || strings.HasPrefix(path, ".agentprov") ||
		strings.HasPrefix(path, "agentprov.db")
}

func argsHash(command string) string {
	sum := sha256.Sum256([]byte(command))
	return hex.EncodeToString(sum[:])
}

func processStatus(status string) string {
	if status == "passed" {
		return "exited"
	}
	return status
}

func score(exitCode int, wallMS int64) float64 {
	if exitCode != 0 {
		return -1000 - float64(exitCode)
	}
	return 1000 - float64(wallMS)/1000
}
