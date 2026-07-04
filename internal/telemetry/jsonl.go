package telemetry

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
)

type JSONLIngestOptions struct {
	Format     string
	Path       string
	RunID      string
	SessionID  string
	AttemptID  string
	ToolCallID string
	ProcessID  string
	SnapshotID string
	RolloutID  string
	// ExcludePathPrefixes drops file-oriented events whose path is under any of
	// these prefixes. Used to keep the streaming sensor from observing (and
	// ingesting, and thereby generating more of) AgentProvenance's OWN I/O --
	// its data-dir snapshot copies and store DB writes -- which otherwise forms
	// a self-feedback storm that buries and drops real scope events.
	ExcludePathPrefixes []string
	// ExcludeCgroupIDs drops events whose cgroup id matches -- typically the
	// supervisor's own cgroup, so the sensor never ingests its own process's
	// activity. A second, cgroup-granular guard alongside ExcludePathPrefixes.
	ExcludeCgroupIDs []string
	// DropUncorrelated, when set, discards events that resolve to no tracked
	// scope (method unresolved / confidence 0). The always-on streaming sensor
	// sees host-wide activity; events belonging to no ToolCallScope are host
	// noise. Persisting them pollutes the store and -- because the ingest batch
	// references them -- fails per-run graph verify. Dropping them keeps a
	// capture clean and verifiable. Off by default (a per-node security
	// deployment may want unattributed activity retained).
	DropUncorrelated bool
}

// excludeEvent reports whether a mapped event is self-noise that must not be
// ingested: it originates from AgentProvenance's own cgroup, or it touches a
// path under the data-dir (snapshot copies, DB files). Excluding it is honest --
// it is counted as Excluded, not silently dropped.
// isUncorrelatedRecord reports whether a stored event resolved to no tracked
// scope -- host noise the always-on sensor happened to see. Mirrors the
// "uncorrelated" CorrelationClass without importing it.
func isUncorrelatedRecord(record EventRecord) bool {
	m := strings.TrimSpace(record.CorrelationMethod)
	return m == "" || m == "unresolved" || record.CorrelationConfidence == 0
}

func (o JSONLIngestOptions) excludeEvent(raw map[string]any, event IngestEvent) bool {
	if event.CgroupID != "" {
		for _, cg := range o.ExcludeCgroupIDs {
			if cg != "" && event.CgroupID == cg {
				return true
			}
		}
	}
	if len(o.ExcludePathPrefixes) == 0 {
		return false
	}
	path := firstNonEmpty(stringAt(raw, "path"), stringAt(raw, "file"), stringAt(raw, "filename"))
	if path == "" {
		return false
	}
	for _, prefix := range o.ExcludePathPrefixes {
		if prefix != "" && strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

type FalcoIngestOptions struct {
	Path       string
	RunID      string
	SessionID  string
	AttemptID  string
	ToolCallID string
	ProcessID  string
	SnapshotID string
	RolloutID  string
}

type JSONLIngestResult struct {
	BatchID           string          `json:"batch_id,omitempty"`
	Format            string          `json:"format"`
	Path              string          `json:"path"`
	FileSHA256        string          `json:"file_sha256,omitempty"`
	Read              int             `json:"read"`
	Ingested          int             `json:"ingested"`
	Skipped           int             `json:"skipped"`
	Failed            int             `json:"failed"`
	EventIDs          []string        `json:"event_ids,omitempty"`
	EventIDsSHA256    string          `json:"event_ids_sha256,omitempty"`
	Excluded          int             `json:"excluded,omitempty"`
	Dropped           int             `json:"dropped_uncorrelated,omitempty"`
	PolicyDecisions   int             `json:"policy_decisions"`
	PolicyDecisionIDs []string        `json:"policy_decision_ids,omitempty"`
	ReceiverSummary   ReceiverSummary `json:"receiver_summary"`
	Rows              []RowResult     `json:"row_results,omitempty"`
	RowsTruncated     bool            `json:"row_results_truncated,omitempty"`
	Errors            []string        `json:"errors,omitempty"`
}

type ReceiverSummary struct {
	DetectedFormats map[string]int `json:"detected_formats,omitempty"`
	EventTypes      map[string]int `json:"event_types,omitempty"`
	IdentityKeys    map[string]int `json:"identity_keys,omitempty"`
	Resolved        int            `json:"resolved"`
	Unresolved      int            `json:"unresolved"`
	Skipped         int            `json:"skipped"`
	Failed          int            `json:"failed"`
}

type RowResult struct {
	Line              int      `json:"line"`
	Status            string   `json:"status"`
	DetectedFormat    string   `json:"detected_format,omitempty"`
	EventID           string   `json:"event_id,omitempty"`
	EventType         string   `json:"event_type,omitempty"`
	Source            string   `json:"source,omitempty"`
	RawEventID        string   `json:"raw_event_id,omitempty"`
	IdentityKeys      []string `json:"identity_keys,omitempty"`
	CorrelationMethod string   `json:"correlation_method,omitempty"`
	Error             string   `json:"error,omitempty"`
}

func IngestJSONL(db *sql.DB, opts JSONLIngestOptions) (JSONLIngestResult, error) {
	if strings.TrimSpace(opts.Path) == "" {
		return JSONLIngestResult{}, fmt.Errorf("jsonl path is required")
	}
	if opts.Path == "-" {
		return IngestJSONLReader(db, opts, os.Stdin)
	}
	file, err := os.Open(opts.Path)
	if err != nil {
		return JSONLIngestResult{}, err
	}
	defer file.Close()
	return IngestJSONLReader(db, opts, file)
}

// IngestJSONLReader ingests JSONL telemetry from any reader, so the agentprov
// sensor (or any substrate) can pipe its stdout straight into the receiver
// (`--file -`) instead of staging a file first. FileSHA256 is computed over the
// exact bytes streamed, so a pipe and the equivalent saved file hash identically.
func IngestJSONLReader(db *sql.DB, opts JSONLIngestOptions, input io.Reader) (JSONLIngestResult, error) {
	opts.Format = strings.TrimSpace(opts.Format)
	if opts.Format == "" {
		opts.Format = "auto"
	}
	hasher := sha256.New()
	result := JSONLIngestResult{Format: opts.Format, Path: opts.Path}
	scanner := bufio.NewScanner(io.TeeReader(input, hasher))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		result.Read++
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			result.Failed++
			msg := fmt.Sprintf("line %d: invalid JSON: %v", lineNo, err)
			result.Errors = append(result.Errors, msg)
			appendRowResult(&result, RowResult{Line: lineNo, Status: "failed", Error: msg})
			continue
		}
		detected := detectedJSONLFormat(opts, raw)
		event, ok, err := mapJSONLEvent(opts, raw, lineNo)
		if err != nil {
			result.Failed++
			msg := fmt.Sprintf("line %d: %v", lineNo, err)
			result.Errors = append(result.Errors, msg)
			appendRowResult(&result, RowResult{Line: lineNo, Status: "failed", DetectedFormat: detected, Error: msg})
			continue
		}
		if !ok {
			result.Skipped++
			appendRowResult(&result, RowResult{Line: lineNo, Status: "skipped", DetectedFormat: detected})
			continue
		}
		if opts.excludeEvent(raw, event) {
			result.Excluded++
			appendRowResult(&result, RowResult{Line: lineNo, Status: "excluded", DetectedFormat: detected})
			continue
		}
		id, err := IngestFiltered(db, event)
		if err != nil {
			result.Failed++
			msg := fmt.Sprintf("line %d: ingest failed: %v", lineNo, err)
			result.Errors = append(result.Errors, msg)
			appendRowResult(&result, rowResultForEvent(lineNo, "failed", detected, event, "", "", msg))
			continue
		}
		record, err := eventRecordByID(db, id)
		if err != nil {
			result.Failed++
			msg := fmt.Sprintf("line %d: readback failed: %v", lineNo, err)
			result.Errors = append(result.Errors, msg)
			appendRowResult(&result, rowResultForEvent(lineNo, "failed", detected, event, id, "", msg))
			continue
		}
		if opts.DropUncorrelated && isUncorrelatedRecord(record) {
			// Host noise belonging to no scope: remove it so it neither pollutes
			// the store nor gets referenced by the ingest batch (which would fail
			// per-run verify). Deleted post-insert because correlation is only
			// known after IngestFiltered resolves it.
			_, _ = db.Exec(`DELETE FROM events WHERE id = ?`, id)
			result.Dropped++
			appendRowResult(&result, RowResult{Line: lineNo, Status: "dropped_uncorrelated", DetectedFormat: detected})
			continue
		}
		result.Ingested++
		result.EventIDs = append(result.EventIDs, id)
		appendRowResult(&result, rowResultForRecord(lineNo, "ingested", detected, record, ""))
	}
	if err := scanner.Err(); err != nil {
		return result, err
	}
	result.FileSHA256 = hex.EncodeToString(hasher.Sum(nil))
	result.EventIDsSHA256 = hashStrings(result.EventIDs)
	if err := persistJSONLBatch(db, opts, &result); err != nil {
		return result, err
	}
	if _, err := RebuildEventWindows(db, resultRunID(db, opts.RunID, result.EventIDs)); err != nil {
		return result, err
	}
	return result, nil
}

func IngestFalco(db *sql.DB, opts FalcoIngestOptions, input io.Reader) (JSONLIngestResult, error) {
	if input == nil {
		return JSONLIngestResult{}, fmt.Errorf("falco input reader is required")
	}
	path := strings.TrimSpace(opts.Path)
	if path == "" {
		path = "stdin"
	}
	jsonlOpts := JSONLIngestOptions{
		Format:     "falco",
		Path:       path,
		RunID:      opts.RunID,
		SessionID:  opts.SessionID,
		AttemptID:  opts.AttemptID,
		ToolCallID: opts.ToolCallID,
		ProcessID:  opts.ProcessID,
		SnapshotID: opts.SnapshotID,
		RolloutID:  opts.RolloutID,
	}
	hasher := sha256.New()
	result := JSONLIngestResult{Format: "falco", Path: path}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		rawLine := scanner.Bytes()
		_, _ = hasher.Write(rawLine)
		_, _ = hasher.Write([]byte{'\n'})
		line := strings.TrimSpace(string(rawLine))
		if line == "" {
			continue
		}
		result.Read++
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			result.Failed++
			msg := fmt.Sprintf("line %d: invalid JSON: %v", lineNo, err)
			result.Errors = append(result.Errors, msg)
			appendRowResult(&result, RowResult{Line: lineNo, Status: "failed", Error: msg})
			continue
		}
		detected := detectedJSONLFormat(jsonlOpts, raw)
		event, ok, err := mapJSONLEvent(jsonlOpts, raw, lineNo)
		if err != nil {
			result.Failed++
			msg := fmt.Sprintf("line %d: %v", lineNo, err)
			result.Errors = append(result.Errors, msg)
			appendRowResult(&result, RowResult{Line: lineNo, Status: "failed", DetectedFormat: detected, Error: msg})
			continue
		}
		if !ok {
			result.Skipped++
			appendRowResult(&result, RowResult{Line: lineNo, Status: "skipped", DetectedFormat: detected})
			continue
		}
		id, err := IngestFiltered(db, event)
		if err != nil {
			result.Failed++
			msg := fmt.Sprintf("line %d: ingest failed: %v", lineNo, err)
			result.Errors = append(result.Errors, msg)
			appendRowResult(&result, rowResultForEvent(lineNo, "failed", detected, event, "", "", msg))
			continue
		}
		record, err := eventRecordByID(db, id)
		if err != nil {
			result.Failed++
			msg := fmt.Sprintf("line %d: readback failed: %v", lineNo, err)
			result.Errors = append(result.Errors, msg)
			appendRowResult(&result, rowResultForEvent(lineNo, "failed", detected, event, id, "", msg))
			continue
		}
		result.Ingested++
		result.EventIDs = append(result.EventIDs, id)
		appendRowResult(&result, rowResultForRecord(lineNo, "ingested", detected, record, ""))
	}
	if err := scanner.Err(); err != nil {
		return result, err
	}
	result.FileSHA256 = hex.EncodeToString(hasher.Sum(nil))
	result.EventIDsSHA256 = hashStrings(result.EventIDs)
	if err := persistJSONLBatch(db, jsonlOpts, &result); err != nil {
		return result, err
	}
	if _, err := RebuildEventWindows(db, resultRunID(db, jsonlOpts.RunID, result.EventIDs)); err != nil {
		return result, err
	}
	return result, nil
}

func persistJSONLBatch(db *sql.DB, opts JSONLIngestOptions, result *JSONLIngestResult) error {
	if result == nil {
		return nil
	}
	batchID := ids.New("telbatch")
	eventIDsJSON, err := json.Marshal(result.EventIDs)
	if err != nil {
		return err
	}
	runID := strings.TrimSpace(opts.RunID)
	if runID == "" {
		inferred, err := inferSingleRunID(db, result.EventIDs)
		if err != nil {
			return err
		}
		runID = inferred
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO telemetry_batches
		(id, run_id, format, path, file_sha256, read_count, ingested_count, skipped_count, failed_count, event_ids_json, event_ids_sha256, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		batchID, runID, result.Format, result.Path, result.FileSHA256, result.Read, result.Ingested, result.Skipped, result.Failed, string(eventIDsJSON), result.EventIDsSHA256, now); err != nil {
		return err
	}
	result.BatchID = batchID
	return nil
}

func detectedJSONLFormat(opts JSONLIngestOptions, raw map[string]any) string {
	if opts.Format != "" && opts.Format != "auto" {
		return opts.Format
	}
	return detectFormat(raw)
}

func eventRecordByID(db *sql.DB, id string) (EventRecord, error) {
	var record EventRecord
	err := db.QueryRow(`SELECT id, COALESCE(run_id, ''), COALESCE(session_id, ''), COALESCE(tool_call_id, ''),
		COALESCE(process_id, ''), COALESCE(snapshot_id, ''), COALESCE(raw_event_id, ''),
		COALESCE(correlation_method, ''), COALESCE(correlation_confidence, 0),
		COALESCE(container_id, ''), COALESCE(cgroup_id, ''), COALESCE(pid, 0),
		COALESCE(tgid, 0), COALESCE(ppid, 0), source, event_type, payload, created_at
		FROM events WHERE id = ?`, id).Scan(&record.ID, &record.RunID, &record.SessionID, &record.ToolCallID,
		&record.ProcessID, &record.SnapshotID, &record.RawEventID, &record.CorrelationMethod, &record.CorrelationConfidence,
		&record.ContainerID, &record.CgroupID, &record.PID, &record.TGID, &record.PPID, &record.Source,
		&record.EventType, &record.Payload, &record.CreatedAt)
	return record, err
}

func rowResultForEvent(line int, status, detected string, event IngestEvent, eventID, method, errMsg string) RowResult {
	return RowResult{
		Line:              line,
		Status:            status,
		DetectedFormat:    detected,
		EventID:           eventID,
		EventType:         event.EventType,
		Source:            event.Source,
		RawEventID:        event.RawEventID,
		IdentityKeys:      ingestEventIdentityKeys(event),
		CorrelationMethod: method,
		Error:             errMsg,
	}
}

func rowResultForRecord(line int, status, detected string, record EventRecord, errMsg string) RowResult {
	return RowResult{
		Line:              line,
		Status:            status,
		DetectedFormat:    detected,
		EventID:           record.ID,
		EventType:         record.EventType,
		Source:            record.Source,
		RawEventID:        record.RawEventID,
		IdentityKeys:      eventIdentityKeys(record),
		CorrelationMethod: record.CorrelationMethod,
		Error:             errMsg,
	}
}

func appendRowResult(result *JSONLIngestResult, row RowResult) {
	const maxRowResults = 1000
	if result.ReceiverSummary.DetectedFormats == nil {
		result.ReceiverSummary.DetectedFormats = map[string]int{}
	}
	if result.ReceiverSummary.EventTypes == nil {
		result.ReceiverSummary.EventTypes = map[string]int{}
	}
	if result.ReceiverSummary.IdentityKeys == nil {
		result.ReceiverSummary.IdentityKeys = map[string]int{}
	}
	if row.DetectedFormat != "" {
		result.ReceiverSummary.DetectedFormats[row.DetectedFormat]++
	}
	if row.EventType != "" {
		result.ReceiverSummary.EventTypes[row.EventType]++
	}
	for _, key := range row.IdentityKeys {
		result.ReceiverSummary.IdentityKeys[key]++
	}
	switch row.Status {
	case "ingested":
		if row.CorrelationMethod == "unresolved" || row.CorrelationMethod == "" {
			result.ReceiverSummary.Unresolved++
		} else {
			result.ReceiverSummary.Resolved++
		}
	case "skipped":
		result.ReceiverSummary.Skipped++
	case "failed":
		result.ReceiverSummary.Failed++
	}
	if len(result.Rows) < maxRowResults {
		result.Rows = append(result.Rows, row)
		return
	}
	result.RowsTruncated = true
}

func ingestEventIdentityKeys(event IngestEvent) []string {
	record := EventRecord{
		ProcessID:   event.ProcessID,
		ContainerID: event.ContainerID,
		CgroupID:    event.CgroupID,
		PID:         event.PID,
		TGID:        event.TGID,
		PPID:        event.PPID,
	}
	return eventIdentityKeys(record)
}

func inferSingleRunID(db *sql.DB, eventIDs []string) (string, error) {
	if len(eventIDs) == 0 {
		return "", nil
	}
	runIDs := map[string]struct{}{}
	for _, eventID := range eventIDs {
		var runID string
		if err := db.QueryRow(`SELECT COALESCE(run_id, '') FROM events WHERE id = ?`, eventID).Scan(&runID); err != nil {
			return "", err
		}
		if strings.TrimSpace(runID) != "" {
			runIDs[runID] = struct{}{}
		}
	}
	if len(runIDs) != 1 {
		return "", nil
	}
	for runID := range runIDs {
		return runID, nil
	}
	return "", nil
}

func resultRunID(db *sql.DB, configured string, eventIDs []string) string {
	configured = strings.TrimSpace(configured)
	if configured != "" {
		return configured
	}
	runID, err := inferSingleRunID(db, eventIDs)
	if err != nil {
		return ""
	}
	return runID
}

func mapJSONLEvent(opts JSONLIngestOptions, raw map[string]any, lineNo int) (IngestEvent, bool, error) {
	format := opts.Format
	if format == "auto" {
		format = detectFormat(raw)
	}
	var event IngestEvent
	var ok bool
	var err error
	switch format {
	case "tetragon":
		event, ok, err = mapTetragon(raw)
	case "falco":
		event, ok, err = mapFalco(raw)
	case "loongcollector":
		event, ok, err = mapLoongCollector(raw)
	case "native":
		event, ok, err = mapNative(raw)
	default:
		return IngestEvent{}, false, fmt.Errorf("unsupported telemetry jsonl format %q", opts.Format)
	}
	if err != nil || !ok {
		return event, ok, err
	}
	event.RunID = firstNonEmpty(event.RunID, opts.RunID)
	event.RolloutID = firstNonEmpty(event.RolloutID, opts.RolloutID)
	event.AttemptID = firstNonEmpty(event.AttemptID, opts.AttemptID)
	event.SessionID = firstNonEmpty(event.SessionID, opts.SessionID)
	event.ToolCallID = firstNonEmpty(event.ToolCallID, opts.ToolCallID)
	event.ProcessID = firstNonEmpty(event.ProcessID, opts.ProcessID)
	event.SnapshotID = firstNonEmpty(event.SnapshotID, opts.SnapshotID)
	if event.RawEventID == "" {
		event.RawEventID = fmt.Sprintf("%s:%d", format, lineNo)
	}
	return event, true, nil
}

func detectFormat(raw map[string]any) string {
	if _, ok := raw["process_exec"]; ok {
		return "tetragon"
	}
	if _, ok := raw["process_exit"]; ok {
		return "tetragon"
	}
	if _, ok := raw["output_fields"]; ok {
		return "falco"
	}
	if stringAt(raw, "source") == "agentprov_ebpf" {
		return "native"
	}
	if stringAt(raw, "source") == "loongcollector" || stringAt(raw, "__tag__:__path__") != "" {
		return "loongcollector"
	}
	return "loongcollector"
}

// mapNative maps the normalized schema emitted by the self-owned agentprov eBPF
// sensor (internal/sensor) into an IngestEvent. The sensor already writes one
// flat JSON object per line with source="agentprov_ebpf"; we apply the same
// security classification as the Falco mapper so own-sensor telemetry drives the
// identical correlation -> risk -> unified-signal path. The sensor captures file
// writes and, now, sensitive READS (mode=read on the event); a secret-looking
// path -- read or write -- maps to secret_path so the policy engine flags it.
func mapNative(raw map[string]any) (IngestEvent, bool, error) {
	event := baseMappedEvent(raw, "agentprov_ebpf")
	comm := stringAt(raw, "comm")
	switch strings.ToLower(firstNonEmpty(stringAt(raw, "event_type"), stringAt(raw, "type"))) {
	case "execve", "exec", "process_exec":
		event.EventType = "execve"
		path := stringAt(raw, "path")
		// Prefer the real argv (sensor "command" field) so command-line args
		// (e.g. a metadata-IP URL) reach the policy ArgsContains rule; fall back
		// to the binary path / comm when argv was not captured.
		command := stringAt(raw, "command")
		argv := splitCommand(command)
		if len(argv) == 0 {
			if path != "" {
				argv = []string{path}
			} else if comm != "" {
				argv = []string{comm}
			} else {
				argv = []string{"unknown"}
			}
		}
		if command == "" {
			command = strings.Join(argv, " ")
		}
		event.Payload = mustJSON(map[string]any{
			"argv":    argv,
			"command": command,
			"comm":    comm,
		})
	case "network_connect", "connect":
		host := stringAt(raw, "dst_ip")
		port := stringAt(raw, "dst_port")
		event.EventType = "network_connect"
		if host == "169.254.169.254" {
			event.EventType = "metadata_ip"
		} else if privateIP(host) {
			event.EventType = "private_cidr"
		}
		event.Payload = mustJSON(map[string]any{
			"dst_ip": host,
			"host":   host,
			"port":   port,
			"comm":   comm,
		})
	case "file_open", "open", "openat", "file_write":
		path := stringAt(raw, "path")
		mode := firstNonEmpty(stringAt(raw, "mode"), "write")
		// A READ of a secret-looking path is the new secret_path signal (reading a
		// credential file used to be invisible); a plain read is file_open. Writes
		// keep their existing mapping (file_write; the policy engine still flags a
		// secret-path write via its path rules) so write behavior is unchanged.
		switch {
		case mode == "read" && secretPath(path):
			event.EventType = "secret_path"
		case mode == "read":
			event.EventType = "file_open"
		default:
			event.EventType = "file_write"
		}
		event.Payload = mustJSON(map[string]any{
			"path": path,
			"mode": mode,
			"comm": comm,
		})
	case "process_exit", "exit":
		event.EventType = "process_exit"
		event.Payload = mustJSON(map[string]any{
			"exit_code": intAt(raw, "exit_code"),
			"comm":      comm,
		})
	case "setuid":
		event.EventType = "setuid"
		event.Payload = mustJSON(map[string]any{"uid": intAt(raw, "uid"), "comm": comm})
	case "setgid":
		event.EventType = "setgid"
		event.Payload = mustJSON(map[string]any{"gid": intAt(raw, "gid"), "comm": comm})
	case "ptrace":
		event.EventType = "ptrace"
		event.Payload = mustJSON(map[string]any{
			"request": intAt(raw, "request"), "target_pid": intAt(raw, "target_pid"), "comm": comm,
		})
	case "file_rename", "rename", "renameat", "renameat2":
		event.EventType = "file_rename"
		event.Payload = mustJSON(map[string]any{"path": stringAt(raw, "path"), "comm": comm})
	case "file_unlink", "unlink", "unlinkat":
		event.EventType = "file_unlink"
		event.Payload = mustJSON(map[string]any{"path": stringAt(raw, "path"), "comm": comm})
	case "dns_query", "dns", "getaddrinfo":
		event.EventType = "dns_query"
		event.Payload = mustJSON(map[string]any{"host": stringAt(raw, "host"), "comm": comm})
	case "resource_pressure":
		event.EventType = "resource_pressure"
		event.Payload = mustJSON(map[string]any{
			"resource":      firstNonEmpty(stringAt(raw, "resource"), "sensor_ringbuf"),
			"signal":        firstNonEmpty(stringAt(raw, "signal"), "event_drop"),
			"dropped":       intAt(raw, "dropped"),
			"dropped_delta": intAt(raw, "dropped_delta"),
		})
	case "tls_write":
		event.EventType = "tls_write"
		event.Payload = sslPayload(raw, comm, "request")
	case "tls_read":
		event.EventType = "tls_read"
		event.Payload = sslPayload(raw, comm, "response")
	default:
		return IngestEvent{}, false, nil
	}
	return event, true, nil
}

// sslPayload normalizes a captured TLS plaintext preview. By default it stores a
// sha256 of the captured bytes plus a short human-triage preview (NOT the full
// plaintext), since prompt/response text is sensitive; the full preview length
// is recorded for context. It also derives privacy-safe HTTP provenance metadata
// (endpoint/model/streaming) under "http" via tlsMeta, which reads only the
// allow-listed head of the request/response, never the body. direction is
// "request" (tls_write) or "response" (tls_read).
func sslPayload(raw map[string]any, comm, direction string) string {
	data := stringAt(raw, "data")
	sum := sha256.Sum256([]byte(data))
	payload := map[string]any{
		"preview_sha256": hex.EncodeToString(sum[:]),
		"preview":        truncatePreview(data, 80),
		"length":         intAt(raw, "length"),
		"comm":           comm,
	}
	if m := stringAt(raw, "model"); m != "" {
		payload["model"] = m
	}
	// Privacy: the full reassembled body (the model's actual prompt/completion) is
	// kept ONLY under an explicit opt-in, so `MaterializeLLMCalls` can objectify it
	// as verifiable evidence. Default keeps just the hash + short preview.
	if data != "" && os.Getenv("AGENTPROV_TLS_CAPTURE_BODY") == "1" {
		payload["content"] = data
	}
	if meta := tlsMeta(data, direction); meta != nil {
		payload["http"] = meta
	}
	return mustJSON(payload)
}

func truncatePreview(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func mapTetragon(raw map[string]any) (IngestEvent, bool, error) {
	event := baseMappedEvent(raw, "tetragon_jsonl")
	if exec, ok := nestedMap(raw, "process_exec"); ok {
		proc, _ := nestedMap(exec, "process")
		event.EventType = "execve"
		event.PID = firstInt(event.PID, intAt(proc, "pid"))
		event.PPID = firstInt(event.PPID, intAt(proc, "parent_exec_id"))
		event.ContainerID = firstNonEmpty(event.ContainerID, stringAt(proc, "docker"))
		argv := tetragonArgv(proc)
		event.Payload = mustJSON(map[string]any{"argv": argv})
		return event, true, nil
	}
	if exit, ok := nestedMap(raw, "process_exit"); ok {
		proc, _ := nestedMap(exit, "process")
		event.EventType = "process_exit"
		event.PID = firstInt(event.PID, intAt(proc, "pid"))
		event.Payload = mustJSON(map[string]any{"exit_code": intAt(exit, "status")})
		return event, true, nil
	}
	return event, false, nil
}

func tetragonArgv(proc map[string]any) []string {
	binary := stringAt(proc, "binary")
	args := splitCommand(stringAt(proc, "arguments"))
	if binary != "" {
		return append([]string{binary}, args...)
	}
	if len(args) > 0 {
		return args
	}
	return []string{"unknown"}
}

func mapFalco(raw map[string]any) (IngestEvent, bool, error) {
	fields, ok := nestedMap(raw, "output_fields")
	if !ok {
		return IngestEvent{}, false, nil
	}
	event := baseMappedEvent(raw, "falco_jsonl")
	event.PID = firstInt(event.PID, intAt(fields, "proc.pid"))
	event.PPID = firstInt(event.PPID, intAt(fields, "proc.ppid"))
	event.ContainerID = firstNonEmpty(event.ContainerID, stringAt(fields, "container.id"))
	event.CgroupID = firstNonEmpty(event.CgroupID, stringAt(fields, "container.cgroup"), stringAt(fields, "proc.cgroup"))
	evtType := strings.ToLower(firstNonEmpty(stringAt(fields, "evt.type"), stringAt(raw, "evt.type")))
	switch evtType {
	case "execve", "execveat", "spawned_process":
		event.EventType = "execve"
		argv := splitCommand(firstNonEmpty(stringAt(fields, "proc.cmdline"), stringAt(fields, "proc.exepath")))
		if len(argv) == 0 {
			argv = []string{"unknown"}
		}
		event.Payload = mustJSON(map[string]any{
			"argv":       argv,
			"command":    strings.Join(argv, " "),
			"rule":       firstNonEmpty(stringAt(raw, "rule"), stringAt(raw, "output")),
			"priority":   stringAt(raw, "priority"),
			"falco_time": stringAt(raw, "time"),
		})
	case "open", "openat", "openat2", "creat":
		path := firstNonEmpty(stringAt(fields, "fd.name"), stringAt(fields, "evt.arg.path"), stringAt(fields, "evt.arg.name"))
		flags := firstNonEmpty(stringAt(fields, "evt.arg.flags"), stringAt(fields, "evt.args"))
		if secretPath(path) {
			event.EventType = "secret_path"
		} else if writeOpenFlags(flags) {
			event.EventType = "file_write"
		} else {
			event.EventType = "file_open"
		}
		event.Payload = mustJSON(map[string]any{
			"path":       path,
			"flags":      flags,
			"rule":       firstNonEmpty(stringAt(raw, "rule"), stringAt(raw, "output")),
			"priority":   stringAt(raw, "priority"),
			"falco_time": stringAt(raw, "time"),
		})
	case "connect":
		event.EventType = "network_connect"
		dst := firstNonEmpty(stringAt(fields, "fd.rip"), stringAt(fields, "fd.name"), stringAt(fields, "fd.sip"))
		host, port := splitFalcoDestination(dst)
		if host == "169.254.169.254" {
			event.EventType = "metadata_ip"
		} else if privateIP(host) {
			event.EventType = "private_cidr"
		}
		event.Payload = mustJSON(map[string]any{
			"dst":        dst,
			"dst_ip":     host,
			"host":       host,
			"port":       port,
			"rule":       firstNonEmpty(stringAt(raw, "rule"), stringAt(raw, "output")),
			"priority":   stringAt(raw, "priority"),
			"falco_time": stringAt(raw, "time"),
		})
	default:
		return IngestEvent{}, false, nil
	}
	return event, true, nil
}

func splitFalcoDestination(dst string) (string, string) {
	dst = strings.TrimSpace(dst)
	if dst == "" {
		return "", ""
	}
	if host, port, err := net.SplitHostPort(dst); err == nil {
		return strings.Trim(host, "[]"), port
	}
	if idx := strings.LastIndex(dst, ":"); idx > -1 && strings.Count(dst, ":") == 1 {
		return dst[:idx], dst[idx+1:]
	}
	return strings.Trim(dst, "[]"), ""
}

func privateIP(raw string) bool {
	// Loopback (127.0.0.0/8, e.g. the local DNS stub) is not an RFC1918 private
	// network — classifying it as private_cidr would flag benign local traffic as
	// risky egress, so only true private ranges count.
	ip := net.ParseIP(strings.Trim(raw, "[]"))
	return ip != nil && ip.IsPrivate()
}

func secretPath(path string) bool {
	path = strings.ToLower(path)
	for _, pattern := range []string{".env", "id_rsa", "secret", "credentials"} {
		if strings.Contains(path, pattern) {
			return true
		}
	}
	return false
}

func writeOpenFlags(flags string) bool {
	flags = strings.ToLower(flags)
	for _, pattern := range []string{"o_wronly", "o_rdwr", "o_creat", "o_trunc", "write"} {
		if strings.Contains(flags, pattern) {
			return true
		}
	}
	return false
}

func mapLoongCollector(raw map[string]any) (IngestEvent, bool, error) {
	event := baseMappedEvent(raw, "loongcollector_jsonl")
	rawType := strings.ToLower(firstNonEmpty(stringAt(raw, "event_type"), stringAt(raw, "type"), stringAt(raw, "event.name")))
	switch rawType {
	case "execve", "exec", "process_exec":
		event.EventType = "execve"
		argv := stringArrayAt(raw, "argv")
		if len(argv) == 0 {
			argv = splitCommand(stringAt(raw, "command"))
		}
		if len(argv) == 0 {
			argv = []string{"unknown"}
		}
		event.Payload = mustJSON(map[string]any{"argv": argv})
	case "process_exit", "exit":
		event.EventType = "process_exit"
		event.Payload = mustJSON(map[string]any{"exit_code": intAt(raw, "exit_code")})
	case "file_open", "file_write":
		event.EventType = rawType
		event.Payload = mustJSON(map[string]any{"path": firstNonEmpty(stringAt(raw, "path"), stringAt(raw, "file"))})
	case "network_connect", "connect":
		event.EventType = "network_connect"
		event.Payload = mustJSON(map[string]any{"dst": firstNonEmpty(stringAt(raw, "dst"), stringAt(raw, "dst_ip"), stringAt(raw, "host"))})
	default:
		return IngestEvent{}, false, nil
	}
	return event, true, nil
}

func baseMappedEvent(raw map[string]any, source string) IngestEvent {
	return IngestEvent{
		RawEventID:  firstNonEmpty(stringAt(raw, "id"), stringAt(raw, "uuid"), stringAt(raw, "event_id")),
		ContainerID: firstNonEmpty(stringAt(raw, "container_id"), stringAt(raw, "container.id")),
		CgroupID:    firstNonEmpty(stringAt(raw, "cgroup_id"), stringAt(raw, "cgroup.id")),
		PID:         intAt(raw, "pid"),
		TGID:        intAt(raw, "tgid"),
		PPID:        intAt(raw, "ppid"),
		Timestamp:   firstNonEmpty(stringAt(raw, "time"), stringAt(raw, "timestamp")),
		Source:      source,
	}
}

func nestedMap(raw map[string]any, key string) (map[string]any, bool) {
	value, ok := raw[key].(map[string]any)
	return value, ok
}

func stringAt(raw map[string]any, key string) string {
	value, ok := raw[key]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		return strconv.FormatInt(int64(typed), 10)
	default:
		return ""
	}
}

func intAt(raw map[string]any, key string) int64 {
	value, ok := raw[key]
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case float64:
		return int64(typed)
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return n
	default:
		return 0
	}
}

func stringArrayAt(raw map[string]any, key string) []string {
	value, ok := raw[key]
	if !ok {
		return nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := []string{}
	for _, item := range items {
		text, ok := item.(string)
		if ok && strings.TrimSpace(text) != "" {
			out = append(out, text)
		}
	}
	return out
}

func splitCommand(command string) []string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstInt(values ...int64) int64 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func mustJSON(value any) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func hashStrings(values []string) string {
	h := sha256.New()
	for _, value := range values {
		_, _ = h.Write([]byte(value))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
