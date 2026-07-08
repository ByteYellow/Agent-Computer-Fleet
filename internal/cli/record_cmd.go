package cli

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func recordCmd(dataDir *string) *cobra.Command {
	var runID string
	var name string
	var workdir string
	var sampleIntervalMS int64
	var postRootGraceMS int64
	var withJSON bool
	cmd := &cobra.Command{
		Use:   "record -- <command...>",
		Short: "record a command as a zero-SDK agent execution",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := store.Init(*dataDir)
			if err != nil {
				return err
			}
			db, err := store.Open(paths)
			if err != nil {
				return err
			}
			defer db.Close()
			daemon.WarnIfDaemonActive(*dataDir, cmd.ErrOrStderr())
			result, err := (record.Service{DB: db, Paths: paths}).Run(record.Request{
				RunID:            runID,
				Name:             name,
				Workdir:          workdir,
				Command:          args,
				SampleIntervalMS: sampleIntervalMS,
				PostRootGraceMS:  postRootGraceMS,
			})
			if err != nil {
				return err
			}
			if withJSON {
				return printRecordJSON(cmd, result)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "run_id=%s trajectory_id=%s base_state=%s execution_scope=%s substrate_scope=%s tool_call=%s process=%s status=%s exit=%d wall_ms=%d changed_files=%d workdir=%s\n",
				result.RunID, result.RolloutID, result.BaseSnapshotID, result.AttemptID, result.SessionID, result.ToolCallID, result.ProcessID, result.Status, result.ExitCode, result.WallMS, len(result.ChangedFiles), result.Workdir)
			for _, file := range result.ChangedFiles {
				fmt.Fprintf(cmd.OutOrStdout(), "changed_file=%s\n", file)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().StringVar(&name, "name", "record", "recording name")
	cmd.Flags().StringVar(&workdir, "workdir", "", "working directory; defaults to current directory")
	cmd.Flags().Int64Var(&sampleIntervalMS, "sample-interval-ms", 25, "zero-SDK process tree sampling interval in milliseconds")
	cmd.Flags().Int64Var(&postRootGraceMS, "post-root-grace-ms", 250, "time to keep sampling after root process exit")
	cmd.Flags().BoolVar(&withJSON, "json", false, "emit machine-readable zero-SDK record manifest")
	cmd.AddCommand(recordBatchCmd(dataDir))
	return cmd
}

func recordBatchCmd(dataDir *string) *cobra.Command {
	var file string
	var withJSON bool
	var continueOnError bool
	var sampleIntervalMS int64
	var postRootGraceMS int64
	var concurrency int
	cmd := &cobra.Command{
		Use:   "batch",
		Short: "record many zero-SDK jobs from a JSONL batch file",
		RunE: func(cmd *cobra.Command, args []string) error {
			jobs, inputHash, err := readRecordBatchJobs(file)
			if err != nil {
				return err
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
			daemon.WarnIfDaemonActive(*dataDir, cmd.ErrOrStderr())
			service := record.Service{DB: db, Paths: paths}
			startedAt := time.Now().UTC().Format(time.RFC3339Nano)
			items := make([]recordBatchItem, 0, len(jobs))
			statusCounts := map[string]int{}
			runIDs := make([]string, 0, len(jobs))
			shards := map[string]int{}
			if concurrency > 1 {
				// Parallel recording for evaluator/benchmark throughput. Jobs run in a
				// bounded worker pool; results are reassembled in input order.
				// continue-on-error is implied here (one failed execution must not
				// abort the batch); the SQLite store serializes writes via WAL +
				// busy_timeout (see store.Open).
				items = runRecordBatchParallel(service, jobs, concurrency, sampleIntervalMS, postRootGraceMS)
				for _, item := range items {
					statusCounts[item.Status]++
					if item.Status != "failed" {
						runIDs = append(runIDs, item.RunID)
						if item.ShardID != "" {
							shards[item.ShardID]++
						}
					}
				}
			} else {
				for index, job := range jobs {
					item := runRecordBatchJob(service, job, index, sampleIntervalMS, postRootGraceMS)
					statusCounts[item.Status]++
					if item.Status == "failed" {
						items = append(items, item)
						if !continueOnError {
							manifest := buildRecordBatchManifest(inputHash, startedAt, items, statusCounts, runIDs, shards)
							_ = storeRecordBatch(db, manifest)
							if withJSON {
								_ = printJSON(cmd.OutOrStdout(), manifest)
							}
							return fmt.Errorf("%s", item.Error)
						}
						continue
					}
					runIDs = append(runIDs, item.RunID)
					if item.ShardID != "" {
						shards[item.ShardID]++
					}
					items = append(items, item)
				}
			}
			manifest := buildRecordBatchManifest(inputHash, startedAt, items, statusCounts, runIDs, shards)
			if err := storeRecordBatch(db, manifest); err != nil {
				return err
			}
			if withJSON {
				return printJSON(cmd.OutOrStdout(), manifest)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "schema=%s batch_id=%s jobs=%d passed=%d failed=%d result_set=%s page_hash=%s\n",
				manifest.SchemaVersion, manifest.BatchID, manifest.JobCount, manifest.Passed, manifest.Failed, manifest.ResultSetID, manifest.PageHash)
			for _, item := range manifest.Items {
				fmt.Fprintf(cmd.OutOrStdout(), "job=%s shard=%s run=%s status=%s exit=%d changed_files=%d wall_ms=%d\n",
					item.JobID, item.ShardID, item.RunID, item.Status, item.ExitCode, item.ChangedFileCount, item.WallMS)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "JSONL batch file; use - for stdin")
	cmd.Flags().BoolVar(&withJSON, "json", false, "emit machine-readable batch manifest")
	cmd.Flags().BoolVar(&continueOnError, "continue-on-error", true, "continue recording later jobs when one job fails")
	cmd.Flags().IntVar(&concurrency, "concurrency", 1, "number of jobs to record in parallel (>1 implies continue-on-error)")
	cmd.Flags().Int64Var(&sampleIntervalMS, "sample-interval-ms", 25, "default zero-SDK process tree sampling interval in milliseconds")
	cmd.Flags().Int64Var(&postRootGraceMS, "post-root-grace-ms", 250, "default time to keep sampling after root process exit")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

// runRecordBatchJob records one batch job and returns its result item (with
// Status="failed" and Error set on failure). Shared by the sequential and
// parallel batch paths.
func runRecordBatchJob(service record.Service, job recordBatchJob, index int, defIntervalMS, defGraceMS int64) recordBatchItem {
	if job.Name == "" {
		job.Name = "record-batch"
	}
	if job.SampleIntervalMS == 0 {
		job.SampleIntervalMS = defIntervalMS
	}
	if job.PostRootGraceMS == 0 {
		job.PostRootGraceMS = defGraceMS
	}
	item := recordBatchItem{
		Index:   index,
		JobID:   job.JobID,
		ShardID: job.ShardID,
		RunID:   job.RunID,
		Workdir: job.Workdir,
		Command: strings.Join(job.Command, " "),
	}
	result, runErr := service.Run(record.Request{
		RunID:            job.RunID,
		Name:             job.Name,
		Workdir:          job.Workdir,
		Command:          job.Command,
		SampleIntervalMS: job.SampleIntervalMS,
		PostRootGraceMS:  job.PostRootGraceMS,
	})
	if runErr != nil {
		item.Status = "failed"
		item.Error = runErr.Error()
		return item
	}
	item.RunID = result.RunID
	item.AttemptID = result.AttemptID
	item.ToolCallID = result.ToolCallID
	item.ProcessID = result.ProcessID
	item.Status = result.Status
	item.ExitCode = result.ExitCode
	item.WallMS = result.WallMS
	item.ChangedFileCount = len(result.ChangedFiles)
	item.ChangedFiles = result.ChangedFiles
	item.EvidenceManifestCommand = "evidence manifest --run " + result.RunID + " --json"
	item.EvalContextCommand = "signal context --run " + result.RunID
	item.ExplainCommand = "graph explain --run " + result.RunID + " --json"
	return item
}

// runRecordBatchParallel records jobs through a bounded worker pool, returning
// results in input order. Each goroutine writes a distinct results index, and
// record.Service is safe for concurrent use (shared *sql.DB, read-only Paths).
func runRecordBatchParallel(service record.Service, jobs []recordBatchJob, concurrency int, defIntervalMS, defGraceMS int64) []recordBatchItem {
	if concurrency < 1 {
		concurrency = 1
	}
	results := make([]recordBatchItem, len(jobs))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for index, job := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(index int, job recordBatchJob) {
			defer wg.Done()
			defer func() { <-sem }()
			results[index] = runRecordBatchJob(service, job, index, defIntervalMS, defGraceMS)
		}(index, job)
	}
	wg.Wait()
	return results
}

type recordBatchJob struct {
	JobID            string   `json:"job_id"`
	ShardID          string   `json:"shard_id"`
	RunID            string   `json:"run_id"`
	Name             string   `json:"name"`
	Workdir          string   `json:"workdir"`
	Command          []string `json:"command"`
	SampleIntervalMS int64    `json:"sample_interval_ms"`
	PostRootGraceMS  int64    `json:"post_root_grace_ms"`
}

type recordBatchItem struct {
	BatchID                 string   `json:"batch_id,omitempty"`
	Index                   int      `json:"index"`
	JobID                   string   `json:"job_id,omitempty"`
	ShardID                 string   `json:"shard_id,omitempty"`
	RunID                   string   `json:"run_id,omitempty"`
	AttemptID               string   `json:"attempt_id,omitempty"`
	ToolCallID              string   `json:"tool_call_id,omitempty"`
	ProcessID               string   `json:"process_id,omitempty"`
	Workdir                 string   `json:"workdir,omitempty"`
	Command                 string   `json:"command,omitempty"`
	Status                  string   `json:"status"`
	ExitCode                int      `json:"exit_code"`
	WallMS                  int64    `json:"wall_ms"`
	ChangedFileCount        int      `json:"changed_file_count"`
	ChangedFiles            []string `json:"changed_files,omitempty"`
	Error                   string   `json:"error,omitempty"`
	EvidenceManifestCommand string   `json:"evidence_manifest_command,omitempty"`
	EvalContextCommand      string   `json:"eval_context_command,omitempty"`
	ExplainCommand          string   `json:"explain_command,omitempty"`
}

type recordBatchManifest struct {
	SchemaVersion string            `json:"schema_version"`
	BatchID       string            `json:"batch_id"`
	InputSHA256   string            `json:"input_sha256"`
	StartedAt     string            `json:"started_at"`
	EndedAt       string            `json:"ended_at"`
	JobCount      int               `json:"job_count"`
	Passed        int               `json:"passed"`
	Failed        int               `json:"failed"`
	Skipped       int               `json:"skipped"`
	StatusCounts  map[string]int    `json:"status_counts"`
	RunIDs        []string          `json:"run_ids"`
	Shards        map[string]int    `json:"shards,omitempty"`
	Items         []recordBatchItem `json:"items"`
	ResultSetID   string            `json:"result_set_id"`
	PageHash      string            `json:"page_hash"`
}

func readRecordBatchJobs(path string) ([]recordBatchJob, string, error) {
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	inputHash := "sha256:" + hex.EncodeToString(sum[:])
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var jobs []recordBatchJob
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var job recordBatchJob
		if err := json.Unmarshal([]byte(line), &job); err != nil {
			return nil, "", fmt.Errorf("parse batch JSONL line %d: %w", lineNo, err)
		}
		if len(job.Command) == 0 {
			return nil, "", fmt.Errorf("batch JSONL line %d missing command", lineNo)
		}
		if job.JobID == "" {
			job.JobID = fmt.Sprintf("job-%06d", len(jobs)+1)
		}
		jobs = append(jobs, job)
	}
	if err := scanner.Err(); err != nil {
		return nil, "", err
	}
	if len(jobs) == 0 {
		return nil, "", fmt.Errorf("batch file has no jobs")
	}
	return jobs, inputHash, nil
}

func buildRecordBatchManifest(inputHash, startedAt string, items []recordBatchItem, statusCounts map[string]int, runIDs []string, shards map[string]int) recordBatchManifest {
	endedAt := time.Now().UTC().Format(time.RFC3339Nano)
	runIDs = append([]string(nil), runIDs...)
	sort.Strings(runIDs)
	statusCounts = copyStringIntMap(statusCounts)
	shards = copyStringIntMap(shards)
	manifest := recordBatchManifest{
		SchemaVersion: "agentprovenance.record_batch/v1",
		InputSHA256:   inputHash,
		StartedAt:     startedAt,
		EndedAt:       endedAt,
		JobCount:      len(items),
		Passed:        statusCounts["passed"],
		Failed:        statusCounts["failed"],
		Skipped:       statusCounts["skipped"],
		StatusCounts:  statusCounts,
		RunIDs:        runIDs,
		Shards:        shards,
		Items:         items,
	}
	manifest.BatchID = digestMap("record_batch_id", map[string]any{
		"input_sha256": inputHash,
		"run_ids":      runIDs,
		"job_count":    manifest.JobCount,
		"started_at":   startedAt,
	})
	manifest.ResultSetID = digestMap("record_batch_result_set", map[string]any{
		"schema_version": manifest.SchemaVersion,
		"batch_id":       manifest.BatchID,
		"input_sha256":   inputHash,
		"run_ids":        runIDs,
	})
	manifest.PageHash = digestMap("record_batch_page", map[string]any{
		"schema_version": manifest.SchemaVersion,
		"batch_id":       manifest.BatchID,
		"items":          manifest.Items,
		"status_counts":  manifest.StatusCounts,
	})
	return manifest
}

func storeRecordBatch(db *sql.DB, manifest recordBatchManifest) error {
	statusCountsJSON, err := json.Marshal(manifest.StatusCounts)
	if err != nil {
		return err
	}
	runIDsJSON, err := json.Marshal(manifest.RunIDs)
	if err != nil {
		return err
	}
	shardsJSON, err := json.Marshal(manifest.Shards)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT OR REPLACE INTO record_batches
		(id, input_sha256, started_at, ended_at, job_count, passed, failed, skipped, status_counts_json, run_ids_json, shards_json, result_set_id, page_hash, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		manifest.BatchID, manifest.InputSHA256, manifest.StartedAt, manifest.EndedAt, manifest.JobCount,
		manifest.Passed, manifest.Failed, manifest.Skipped, string(statusCountsJSON), string(runIDsJSON), string(shardsJSON),
		manifest.ResultSetID, manifest.PageHash, now); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM record_batch_items WHERE batch_id = ?`, manifest.BatchID); err != nil {
		return err
	}
	for _, item := range manifest.Items {
		changedFilesJSON, err := json.Marshal(item.ChangedFiles)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO record_batch_items
			(batch_id, idx, job_id, shard_id, run_id, attempt_id, tool_call_id, process_id, workdir, command, status, exit_code, wall_ms, changed_file_count, changed_files_json, error, evidence_manifest_command, eval_context_command, explain_command, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			manifest.BatchID, item.Index, item.JobID, item.ShardID, item.RunID, item.AttemptID, item.ToolCallID, item.ProcessID,
			item.Workdir, item.Command, item.Status, item.ExitCode, item.WallMS, item.ChangedFileCount, string(changedFilesJSON), item.Error,
			item.EvidenceManifestCommand, item.EvalContextCommand, item.ExplainCommand, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func copyStringIntMap(in map[string]int) map[string]int {
	out := map[string]int{}
	for key, value := range in {
		if key != "" {
			out[key] = value
		}
	}
	return out
}

func digestMap(kind string, value map[string]any) string {
	value["kind"] = kind
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func printJSON(out io.Writer, value any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func printRecordJSON(cmd *cobra.Command, result record.Result) error {
	processTreeCount := 0
	if result.RootPID != 0 {
		processTreeCount = 1 + len(result.Observed)
	}
	manifest := map[string]any{
		"schema_version":     "agentprovenance.record/v1",
		"run_id":             result.RunID,
		"trajectory_id":      result.RolloutID,
		"base_state_id":      result.BaseSnapshotID,
		"execution_scope_id": result.AttemptID,
		"substrate_scope_id": result.SessionID,
		"rollout_id":         result.RolloutID,
		"base_snapshot_id":   result.BaseSnapshotID,
		"attempt_id":         result.AttemptID,
		"session_id":         result.SessionID,
		"tool_call_id":       result.ToolCallID,
		"process_id":         result.ProcessID,
		"workdir":            result.Workdir,
		"command":            result.Command,
		"status":             result.Status,
		"exit_code":          result.ExitCode,
		"wall_ms":            result.WallMS,
		"changed_files":      result.ChangedFiles,
		"changed_file_count": len(result.ChangedFiles),
		"context_mode":       "zero_sdk",
		"root_pid":           result.RootPID,
		"observed_processes": result.Observed,
		"orphan_policy":      result.OrphanPolicy,
		"sample_interval_ms": result.SampleIntervalMS,
		"post_root_grace_ms": result.PostRootGraceMS,
		"cwd":                result.CWD,
		"process_tree_count": processTreeCount,
		"time_window": map[string]any{
			"started_at": result.StartedAt,
			"ended_at":   result.EndedAt,
		},
		"scope_inference": map[string]any{
			"method":             "zero_sdk_root_process+cwd+time_window+file_diff",
			"root_pid":           result.RootPID,
			"process_tree_count": processTreeCount,
			"cwd":                result.CWD,
			"changed_file_count": len(result.ChangedFiles),
			"observed_processes": len(result.Observed),
			"boundary":           "root_pid_descendants+cwd+time_window+file_diff",
			"orphan_policy":      result.OrphanPolicy,
			"sample_interval_ms": result.SampleIntervalMS,
			"post_root_grace_ms": result.PostRootGraceMS,
		},
	}
	if result.FailureReason != "" {
		manifest["failure_reason"] = result.FailureReason
	}
	return printJSON(cmd.OutOrStdout(), manifest)
}
