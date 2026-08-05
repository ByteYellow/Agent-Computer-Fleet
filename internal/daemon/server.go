package daemon

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/byteyellow/agentprovenance/internal/baseline"
	"github.com/byteyellow/agentprovenance/internal/control"
	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/cost"
	"github.com/byteyellow/agentprovenance/internal/evidence"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/observability"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/record"
	securitymodel "github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/signal"
	signalsmodel "github.com/byteyellow/agentprovenance/internal/signals"
	"github.com/byteyellow/agentprovenance/internal/store"
	runtimeplane "github.com/byteyellow/agentprovenance/internal/substrate/runtime"
	"github.com/byteyellow/agentprovenance/internal/substrate/state"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

type Server struct {
	DB                 *sql.DB
	Paths              store.Paths
	Driver             runtimeplane.Driver
	SampleInterval     time.Duration
	SampleLimit        int
	SampleTimeout      time.Duration
	RawRetention       time.Duration
	MaxRawSamples      int
	EvidenceInterval   time.Duration
	EvidenceLimit      int
	SpoolInterval      time.Duration
	SpoolLimit         int
	SpoolMaxQueued     int
	SpoolMaxBytes      int64
	SpoolMaxBatchBytes int64
	SpoolDropPolicy    string
	GCInterval         time.Duration
	GCLimit            int
	// AuthToken, when set, requires every request except GET /v1/health to carry
	// `Authorization: Bearer <AuthToken>`. Empty = open (backward compatible).
	AuthToken string
	writeMu   *sync.Mutex
}

func NewServer(dataDir string) (Server, func(), error) {
	paths, err := store.Init(dataDir)
	if err != nil {
		return Server{}, nil, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return Server{}, nil, err
	}
	driver, err := runtimeplane.NewDriver("docker", paths)
	if err != nil {
		db.Close()
		return Server{}, nil, err
	}
	return Server{DB: db, Paths: paths, Driver: driver, writeMu: &sync.Mutex{}}, func() { db.Close() }, nil
}

func (s Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("POST /v1/leases", s.createLease)
	mux.HandleFunc("POST /v1/sessions", s.createSession)
	mux.HandleFunc("GET /v1/sessions", s.listSessions)
	mux.HandleFunc("/v1/sessions/", s.sessionByID)
	mux.HandleFunc("POST /v1/snapshots", s.createSnapshot)
	mux.HandleFunc("/v1/snapshots/", s.snapshotByID)
	mux.HandleFunc("POST /v1/record", s.recordRun)
	mux.HandleFunc("POST /v1/telemetry/bind", s.bindTelemetry)
	mux.HandleFunc("GET /v1/telemetry/events", s.listTelemetryEvents)
	mux.HandleFunc("GET /v1/telemetry/windows", s.listTelemetryWindows)
	mux.HandleFunc("GET /v1/telemetry/correlations", s.telemetryCorrelations)
	mux.HandleFunc("GET /v1/telemetry/spool", s.listTelemetrySpool)
	mux.HandleFunc("GET /v1/telemetry/producer-health", s.telemetryProducerHealth)
	mux.HandleFunc("POST /v1/telemetry/spool/process", s.processTelemetrySpool)
	mux.HandleFunc("POST /v1/telemetry/retention/prune", s.pruneTelemetryRetention)
	mux.HandleFunc("POST /v1/telemetry/ingest-falco", s.ingestFalco)
	mux.HandleFunc("GET /v1/graph/verify", s.graphVerify)
	mux.HandleFunc("GET /v1/graph/explain", s.graphExplain)
	mux.HandleFunc("GET /v1/graph/lens", s.graphLens)
	mux.HandleFunc("GET /v1/evidence/manifest", s.evidenceManifest)
	mux.HandleFunc("POST /v1/forensics/export", s.forensicsExport)
	mux.HandleFunc("POST /v1/forensics/export-batch", s.forensicsExportBatch)
	mux.HandleFunc("GET /v1/observe/summary", s.observeSummary)
	mux.HandleFunc("GET /v1/signals", s.listSignals)
	mux.HandleFunc("GET /v1/timeline", s.timeline)
	mux.HandleFunc("GET /v1/security/risks", s.securityRisks)
	mux.HandleFunc("GET /v1/security/responses", s.securityResponses)
	mux.HandleFunc("GET /v1/security/deviations", s.securityDeviations)
	mux.HandleFunc("GET /v1/signal/context", s.signalContext)
	mux.HandleFunc("POST /v1/signal/run", s.signalRun)
	mux.HandleFunc("POST /v1/signal/import", s.signalImport)
	return s.withAuth(mux)
}

// withAuth requires a bearer token on every route except GET /v1/health (kept
// open for readiness probes). When AuthToken is empty, the mux is returned
// unwrapped (open, backward compatible). Constant-time comparison avoids leaking
// the token via timing.
func (s Server) withAuth(next http.Handler) http.Handler {
	if s.AuthToken == "" {
		return next
	}
	want := "Bearer " + s.AuthToken
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/health" {
			next.ServeHTTP(w, r)
			return
		}
		got := r.Header.Get("Authorization")
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
			writeJSON(w, map[string]any{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s Server) control() control.Service {
	return control.Service{DB: s.DB, Paths: s.Paths, Driver: s.Driver, WriteMu: s.writeMu}
}

func (s Server) health(w http.ResponseWriter, r *http.Request) {
	var lastSample string
	var queuedEvidence, queuedGC, queuedSpool int64
	var queuedSpoolBytes int64
	_ = s.DB.QueryRow(`SELECT COALESCE(MAX(created_at), '') FROM cpu_samples`).Scan(&lastSample)
	_ = s.DB.QueryRow(`SELECT COALESCE(COUNT(*), 0) FROM evidence_events WHERE status = 'queued'`).Scan(&queuedEvidence)
	_ = s.DB.QueryRow(`SELECT COALESCE(COUNT(*), 0) FROM gc_jobs WHERE status = 'queued'`).Scan(&queuedGC)
	_ = s.DB.QueryRow(`SELECT COALESCE(COUNT(*), 0) FROM telemetry_spool_batches WHERE status = 'queued'`).Scan(&queuedSpool)
	_ = s.DB.QueryRow(`SELECT COALESCE(SUM(size_bytes), 0) FROM telemetry_spool_batches WHERE status IN ('queued', 'processing')`).Scan(&queuedSpoolBytes)
	runtimeName := ""
	if s.Driver != nil {
		runtimeName = s.Driver.Name()
	}
	writeJSON(w, map[string]any{
		"schema_version":        "agentprovenance.daemon_health/v1",
		"status":                "ok",
		"runtime":               runtimeName,
		"sample_interval_ms":    s.SampleInterval.Milliseconds(),
		"sample_limit":          s.SampleLimit,
		"sample_timeout_ms":     s.SampleTimeout.Milliseconds(),
		"raw_retention_ms":      s.RawRetention.Milliseconds(),
		"max_raw_samples":       s.MaxRawSamples,
		"last_cpu_sample_at":    lastSample,
		"background_sampler":    s.SampleInterval > 0,
		"evidence_interval_ms":  s.EvidenceInterval.Milliseconds(),
		"evidence_limit":        s.EvidenceLimit,
		"spool_interval_ms":     s.SpoolInterval.Milliseconds(),
		"spool_limit":           s.SpoolLimit,
		"spool_max_queued":      s.SpoolMaxQueued,
		"spool_max_bytes":       s.SpoolMaxBytes,
		"spool_max_batch_bytes": s.SpoolMaxBatchBytes,
		"spool_drop_policy":     s.SpoolDropPolicy,
		"gc_interval_ms":        s.GCInterval.Milliseconds(),
		"gc_limit":              s.GCLimit,
		"queued_evidence":       queuedEvidence,
		"queued_gc":             queuedGC,
		"queued_spool":          queuedSpool,
		"queued_spool_bytes":    queuedSpoolBytes,
	})
}

func (s Server) StartSampler(ctx context.Context) {
	if s.SampleInterval <= 0 {
		return
	}
	ticker := time.NewTicker(s.SampleInterval)
	defer ticker.Stop()
	s.sampleOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sampleOnce()
		}
	}
}

func (s Server) sampleOnce() {
	result, err := cost.SampleRunningDockerSessionsWithOptions(s.DB, cost.SamplerOptions{Limit: s.SampleLimit, Timeout: s.SampleTimeout, RawRetention: s.RawRetention, MaxRawPerSession: s.MaxRawSamples})
	now := time.Now().UTC().Format(time.RFC3339Nano)
	payload := fmt.Sprintf(`{"sampled":%d,"failed":%d,"skipped":%d,"errors":%q}`, result.Sampled, result.Failed, result.Skipped, strings.Join(result.Errors, "; "))
	if err != nil {
		payload = fmt.Sprintf(`{"sampled":0,"failed":1,"errors":%q}`, err.Error())
	}
	_, _ = s.DB.Exec(`INSERT INTO events (id, source, event_type, payload, created_at)
		VALUES ('evt-' || lower(hex(randomblob(6))), 'daemon_sampler', 'scheduler_sample', ?, ?)`, payload, now)
}

func (s Server) StartEvidenceWorker(ctx context.Context) {
	if s.EvidenceInterval <= 0 {
		return
	}
	ticker := time.NewTicker(s.EvidenceInterval)
	defer ticker.Stop()
	s.processEvidenceOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.processEvidenceOnce()
		}
	}
}

func (s Server) StartSpoolWorker(ctx context.Context) {
	if s.SpoolInterval <= 0 {
		return
	}
	ticker := time.NewTicker(s.SpoolInterval)
	defer ticker.Stop()
	s.processSpoolOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.processSpoolOnce()
		}
	}
}

func (s Server) processSpoolOnce() {
	limit := s.SpoolLimit
	if limit <= 0 {
		limit = 100
	}
	s.lockWrites()
	defer s.unlockWrites()
	result, err := (telemetry.SpoolService{DB: s.DB, Paths: s.Paths}).Process(limit)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	payload := fmt.Sprintf(`{"processed":%d,"failed":%d}`, result.Processed, result.Failed)
	if err != nil {
		payload = fmt.Sprintf(`{"processed":%d,"failed":%d,"error":%q}`, result.Processed, result.Failed+1, err.Error())
	}
	_, _ = s.DB.Exec(`INSERT INTO events (id, source, event_type, payload, created_at)
		VALUES ('evt-' || lower(hex(randomblob(6))), 'daemon_spool', 'spool_worker', ?, ?)`, payload, now)
}

func (s Server) processEvidenceOnce() {
	limit := s.EvidenceLimit
	if limit <= 0 {
		limit = 100
	}
	result, err := (evidence.Service{DB: s.DB, Paths: s.Paths}).ProcessEvidence(limit)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	payload := fmt.Sprintf(`{"processed":%d}`, result.Processed)
	if err != nil {
		payload = fmt.Sprintf(`{"processed":%d,"error":%q}`, result.Processed, err.Error())
	}
	_, _ = s.DB.Exec(`INSERT INTO events (id, source, event_type, payload, created_at)
		VALUES ('evt-' || lower(hex(randomblob(6))), 'daemon_evidence', 'evidence_worker', ?, ?)`, payload, now)
}

func (s Server) StartGCWorker(ctx context.Context) {
	if s.GCInterval <= 0 {
		return
	}
	ticker := time.NewTicker(s.GCInterval)
	defer ticker.Stop()
	s.gcOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.gcOnce()
		}
	}
}

func (s Server) gcOnce() {
	limit := s.GCLimit
	if limit <= 0 {
		limit = 100
	}
	result, err := (evidence.Service{DB: s.DB, Paths: s.Paths}).RunGC(limit)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	payload := fmt.Sprintf(`{"processed":%d,"failed":%d,"reclaimed_bytes":%d,"reclaimed_inodes":%d}`, result.Processed, result.Failed, result.ReclaimedBytes, result.ReclaimedInodes)
	if err != nil {
		payload = fmt.Sprintf(`{"processed":%d,"failed":%d,"error":%q}`, result.Processed, result.Failed+1, err.Error())
	}
	_, _ = s.DB.Exec(`INSERT INTO events (id, source, event_type, payload, created_at)
		VALUES ('evt-' || lower(hex(randomblob(6))), 'daemon_gc', 'gc_worker', ?, ?)`, payload, now)
}

func (s Server) createLease(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Task string `json:"task"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	s.lockWrites()
	defer s.unlockWrites()
	id, err := s.control().CreateLease(req.Task)
	writeResult(w, map[string]any{"lease_id": id}, err)
}

func (s Server) createSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LeaseID string `json:"lease_id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	s.lockWrites()
	defer s.unlockWrites()
	id, err := s.control().CreateSession(req.LeaseID)
	writeResult(w, map[string]any{"session_id": id}, err)
}

func (s Server) listSessions(w http.ResponseWriter, r *http.Request) {
	items, err := s.control().ListSessions()
	writeResult(w, map[string]any{"sessions": items}, err)
}

func (s Server) sessionByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/sessions/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	sessionID := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			item, err := s.control().InspectSession(sessionID)
			writeResult(w, map[string]any{"session": item}, err)
		case http.MethodDelete:
			s.lockWrites()
			defer s.unlockWrites()
			err := s.control().RemoveSession(sessionID)
			writeResult(w, map[string]any{"status": "removed"}, err)
		default:
			http.NotFound(w, r)
		}
		return
	}
	switch parts[1] {
	case "cpu-profile":
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var req struct {
			Profile string `json:"profile"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		s.lockWrites()
		defer s.unlockWrites()
		err := s.control().SetSessionCPUProfile(sessionID, req.Profile)
		writeResult(w, map[string]any{"status": "updated", "profile": req.Profile}, err)
	case "exec":
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		s.exec(w, r, sessionID)
	case "stop":
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		s.lockWrites()
		defer s.unlockWrites()
		err := s.control().StopSession(sessionID)
		writeResult(w, map[string]any{"status": "stopped"}, err)
	default:
		http.NotFound(w, r)
	}
}

func (s Server) exec(w http.ResponseWriter, r *http.Request, sessionID string) {
	var req struct {
		Command []string `json:"command"`
		Stream  bool     `json:"stream"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Stream {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		processID, err := s.control().ExecStream(sessionID, req.Command, flushWriter{ResponseWriter: w}, flushWriter{ResponseWriter: w})
		if err != nil {
			fmt.Fprintf(w, "\nerror=%q\n", err.Error())
			return
		}
		fmt.Fprintf(w, "\n%s\n", processID)
		return
	}
	processID, err := s.control().Exec(sessionID, req.Command, false)
	writeResult(w, map[string]any{"process_id": processID}, err)
}

func (s Server) createSnapshot(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		Type      string `json:"type"`
		Path      string `json:"path"`
		Name      string `json:"name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Type == "" {
		req.Type = "directory"
	}
	if req.Path == "" {
		req.Path = "/workspace"
	}
	if req.Type != "directory" {
		writeResult(w, nil, fmt.Errorf("only directory snapshots are supported"))
		return
	}
	s.lockWrites()
	defer s.unlockWrites()
	id, manifest, snapshotCreateMS, err := state.Service{DB: s.DB, Paths: s.Paths}.CreateDirectorySnapshot(req.SessionID, req.Path, req.Name)
	writeResult(w, map[string]any{"snapshot_id": id, "files": manifest.Files, "bytes": manifest.Bytes, "snapshot_create_ms": snapshotCreateMS, "hash": manifest.Hash}, err)
}

func (s Server) snapshotByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/snapshots/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] != "resume" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var req struct {
		LeaseID string `json:"lease_id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	s.lockWrites()
	defer s.unlockWrites()
	id, err := s.control().ResumeSnapshot(parts[0], req.LeaseID)
	writeResult(w, map[string]any{"session_id": id}, err)
}

func (s Server) bindTelemetry(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RunID         string  `json:"run_id"`
		SessionID     string  `json:"session_id"`
		AttemptID     string  `json:"attempt_id"`
		ToolCallID    string  `json:"tool_call_id"`
		ProcessID     string  `json:"process_id"`
		ContainerID   string  `json:"container_id"`
		CgroupID      string  `json:"cgroup_id"`
		RootPID       int64   `json:"root_pid"`
		PID           int64   `json:"pid"`
		StartedAt     string  `json:"started_at"`
		EndedAt       string  `json:"ended_at"`
		BindingSource string  `json:"binding_source"`
		Confidence    float64 `json:"confidence"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	s.lockWrites()
	defer s.unlockWrites()
	id, err := correlation.RecordBinding(s.DB, correlation.Binding{
		RunID:         req.RunID,
		SessionID:     req.SessionID,
		AttemptID:     req.AttemptID,
		ToolCallID:    req.ToolCallID,
		ProcessID:     req.ProcessID,
		ContainerID:   req.ContainerID,
		CgroupID:      req.CgroupID,
		RootPID:       req.RootPID,
		PID:           req.PID,
		StartedAt:     req.StartedAt,
		EndedAt:       req.EndedAt,
		BindingSource: req.BindingSource,
		Confidence:    req.Confidence,
	})
	writeResult(w, map[string]any{"binding_id": id, "schema_version": "agentprovenance.daemon_telemetry_binding/v1"}, err)
}

func (s Server) ingestFalco(w http.ResponseWriter, r *http.Request) {
	var req struct {
		File     string `json:"file"`
		RunID    string `json:"run_id"`
		NoPolicy bool   `json:"no_policy"`
		Async    bool   `json:"async"`
		Queued   bool   `json:"queued"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Async || req.Queued {
		s.lockWrites()
		defer s.unlockWrites()
		batch, err := (telemetry.SpoolService{DB: s.DB, Paths: s.Paths}).Enqueue(telemetry.SpoolEnqueueRequest{
			Format:         "falco",
			RunID:          req.RunID,
			SourcePath:     req.File,
			PolicyEnabled:  !req.NoPolicy,
			MaxQueued:      s.SpoolMaxQueued,
			MaxQueuedBytes: s.SpoolMaxBytes,
			MaxBatchBytes:  s.SpoolMaxBatchBytes,
			DropPolicy:     s.SpoolDropPolicy,
		})
		writeSpoolEnqueueResult(w, batch, err)
		return
	}
	s.lockWrites()
	defer s.unlockWrites()
	file, err := os.Open(req.File)
	if err != nil {
		writeResult(w, nil, err)
		return
	}
	defer file.Close()
	result, err := telemetry.IngestFalco(s.DB, telemetry.FalcoIngestOptions{Path: req.File, RunID: req.RunID}, file)
	if err == nil && !req.NoPolicy {
		evaluateTelemetryPolicy(s.DB, &result)
	}
	writeResult(w, map[string]any{"batch": result, "policy_decisions": result.PolicyDecisions, "schema_version": "agentprovenance.daemon_falco_ingest/v1"}, err)
}

func (s Server) listTelemetrySpool(w http.ResponseWriter, r *http.Request) {
	items, err := (telemetry.SpoolService{DB: s.DB, Paths: s.Paths}).List(r.URL.Query().Get("run"))
	writeResult(w, map[string]any{"schema_version": "agentprovenance.telemetry_spool/v1", "batches": items}, err)
}

func (s Server) telemetryProducerHealth(w http.ResponseWriter, r *http.Request) {
	report, err := telemetry.BuildProducerHealth(s.DB, telemetry.ProducerHealthOptions{
		RunID:          r.URL.Query().Get("run"),
		MaxQueued:      s.SpoolMaxQueued,
		MaxQueuedBytes: s.SpoolMaxBytes,
		MaxBatchBytes:  s.SpoolMaxBatchBytes,
		DropPolicy:     s.SpoolDropPolicy,
	})
	writeResult(w, report, err)
}

func (s Server) listTelemetryEvents(w http.ResponseWriter, r *http.Request) {
	limit, err := intQuery(r, "limit", 100)
	if err != nil {
		writeResult(w, nil, err)
		return
	}
	result, err := telemetry.ListEventsPage(s.DB, telemetry.ListOptions{
		Filter: telemetry.Filter{
			RunID:      r.URL.Query().Get("run"),
			SessionID:  r.URL.Query().Get("session"),
			Type:       r.URL.Query().Get("type"),
			ToolCallID: r.URL.Query().Get("tool_call"),
		},
		Limit:  limit,
		Cursor: r.URL.Query().Get("cursor"),
	})
	writeResult(w, result, err)
}

func (s Server) listTelemetryWindows(w http.ResponseWriter, r *http.Request) {
	windowSeconds, err := intQuery(r, "window", 0)
	if err != nil {
		writeResult(w, nil, err)
		return
	}
	result, err := telemetry.ListEventWindows(s.DB, telemetry.EventWindowFilter{
		RunID:         r.URL.Query().Get("run"),
		SessionID:     r.URL.Query().Get("session"),
		ToolCallID:    r.URL.Query().Get("tool_call"),
		Type:          r.URL.Query().Get("type"),
		Source:        r.URL.Query().Get("source"),
		WindowSeconds: windowSeconds,
	})
	writeResult(w, result, err)
}

func (s Server) telemetryCorrelations(w http.ResponseWriter, r *http.Request) {
	result, err := telemetry.BuildCorrelationReport(s.DB, telemetry.CorrelationReportOptions{
		RunID:   r.URL.Query().Get("run"),
		EventID: r.URL.Query().Get("event"),
	})
	writeResult(w, result, err)
}

func (s Server) processTelemetrySpool(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Limit int `json:"limit"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	limit := req.Limit
	if limit <= 0 {
		limit = s.SpoolLimit
	}
	if limit <= 0 {
		limit = 100
	}
	s.lockWrites()
	defer s.unlockWrites()
	result, err := (telemetry.SpoolService{DB: s.DB, Paths: s.Paths}).Process(limit)
	writeResult(w, map[string]any{"schema_version": "agentprovenance.telemetry_spool_process/v1", "result": result}, err)
}

func (s Server) pruneTelemetryRetention(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RunID            string `json:"run_id"`
		OlderThanSeconds int64  `json:"older_than_seconds"`
		MaxDelete        int    `json:"max_delete"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	olderThan := time.Duration(req.OlderThanSeconds) * time.Second
	s.lockWrites()
	defer s.unlockWrites()
	result, err := telemetry.PruneRawEvents(s.DB, telemetry.RetentionOptions{RunID: req.RunID, OlderThan: olderThan, MaxDelete: req.MaxDelete})
	writeResult(w, result, err)
}

func (s Server) graphVerify(w http.ResponseWriter, r *http.Request) {
	runID := r.URL.Query().Get("run")
	result, err := provenance.Verify(s.DB, runID)
	writeResult(w, result, err)
}

func (s Server) graphExplain(w http.ResponseWriter, r *http.Request) {
	limit, err := intQuery(r, "limit", 100)
	if err != nil {
		writeResult(w, nil, err)
		return
	}
	depth, err := intQuery(r, "depth", 2)
	if err != nil {
		writeResult(w, nil, err)
		return
	}
	result, err := provenance.BuildExplain(s.DB, provenance.ExplainOptions{
		RunID:    r.URL.Query().Get("run"),
		Artifact: r.URL.Query().Get("artifact"),
		Attempt:  r.URL.Query().Get("attempt"),
		ToolCall: r.URL.Query().Get("tool_call"),
		Process:  r.URL.Query().Get("process"),
		Event:    r.URL.Query().Get("event"),
		Risk:     r.URL.Query().Get("risk"),
		File:     r.URL.Query().Get("file"),
		Depth:    depth,
		Limit:    limit,
		Cursor:   r.URL.Query().Get("cursor"),
	})
	writeResult(w, result, err)
}

func (s Server) graphLens(w http.ResponseWriter, r *http.Request) {
	limit, err := intQuery(r, "limit", 500)
	if err != nil {
		writeResult(w, nil, err)
		return
	}
	result, err := provenance.BuildGraphLens(s.DB, provenance.GraphLensOptions{
		RunID:    r.URL.Query().Get("run"),
		Lens:     r.URL.Query().Get("lens"),
		Focus:    r.URL.Query().Get("focus"),
		Detail:   r.URL.Query().Get("detail"),
		Overlays: r.URL.Query()["overlay"],
		Limit:    limit,
	})
	writeResult(w, result, err)
}

func (s Server) evidenceManifest(w http.ResponseWriter, r *http.Request) {
	runID := r.URL.Query().Get("run")
	materialize := r.URL.Query().Get("materialize") == "1" || r.URL.Query().Get("materialize") == "true"
	objectLimit := 25
	if materialize {
		s.lockWrites()
		defer s.unlockWrites()
	}
	result, err := buildEvidenceManifest(s.DB, s.Paths, runID, objectLimit, materialize)
	writeResult(w, result, err)
}

func (s Server) forensicsExport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RunID string `json:"run_id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	s.lockWrites()
	defer s.unlockWrites()
	bundle, err := (forensics.Service{DB: s.DB, Paths: s.Paths}).ExportBundle(req.RunID)
	writeResult(w, bundle, err)
}

func (s Server) forensicsExportBatch(w http.ResponseWriter, r *http.Request) {
	var req forensics.BatchExportOptions
	if !decodeJSON(w, r, &req) {
		return
	}
	s.lockWrites()
	defer s.unlockWrites()
	bundle, err := (forensics.Service{DB: s.DB, Paths: s.Paths}).ExportBatch(req)
	writeResult(w, bundle, err)
}

// recordRun runs a zero-SDK record over the daemon, so high-frequency callers
// (RL training loops) avoid a fork+exec+DB-open of the CLI per trajectory. The
// request/response use the same snake_case shape as `agentprov record --json`.
func (s Server) recordRun(w http.ResponseWriter, r *http.Request) {
	var req record.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeResult(w, nil, fmt.Errorf("invalid record request: %w", err))
		return
	}
	if len(req.Command) == 0 {
		writeResult(w, nil, errors.New("command is required"))
		return
	}
	result, err := record.Service{DB: s.DB, Paths: s.Paths}.Run(req)
	writeResult(w, result, err)
}

// listSignals exposes the unified signal model over the daemon API. With no
// dimension it returns the versioned SignalSet envelope; with ?dimension= it
// returns the filtered rows. This is the daemon-side mirror of `agentprov
// signals list`.
func (s Server) listSignals(w http.ResponseWriter, r *http.Request) {
	runID := r.URL.Query().Get("run")
	if runID == "" {
		writeResult(w, nil, errors.New("run is required"))
		return
	}
	if dim := r.URL.Query().Get("dimension"); dim != "" {
		if !signalsmodel.Dimension(dim).Valid() {
			writeResult(w, nil, fmt.Errorf("invalid dimension %q (want behavior|cost|quality|security)", dim))
			return
		}
		rows, err := signalsmodel.Query(s.DB, signalsmodel.Filter{RunID: runID, Dimension: signalsmodel.Dimension(dim)})
		writeResult(w, map[string]any{"signals": rows}, err)
		return
	}
	set, err := signalsmodel.Export(s.DB, runID)
	writeResult(w, set, err)
}

func (s Server) observeSummary(w http.ResponseWriter, r *http.Request) {
	topN, err := intQuery(r, "top", 8)
	if err != nil {
		writeResult(w, nil, err)
		return
	}
	result, err := observability.BuildSummary(s.DB, observability.SummaryOptions{RunID: r.URL.Query().Get("run"), TopN: topN})
	writeResult(w, result, err)
}

func (s Server) timeline(w http.ResponseWriter, r *http.Request) {
	limit, err := intQuery(r, "limit", 0)
	if err != nil {
		writeResult(w, nil, err)
		return
	}
	result, err := provenance.BuildTimeline(s.DB, provenance.TimelineOptions{
		RunID:     r.URL.Query().Get("run"),
		ToolCall:  r.URL.Query().Get("tool_call"),
		ProcessID: r.URL.Query().Get("process"),
		Type:      r.URL.Query().Get("type"),
		Limit:     limit,
		Cursor:    r.URL.Query().Get("cursor"),
		View:      r.URL.Query().Get("view"),
	})
	writeResult(w, result, err)
}

func (s Server) securityRisks(w http.ResponseWriter, r *http.Request) {
	result, err := securitymodel.BuildRiskSignalsReport(s.DB, r.URL.Query().Get("run"))
	writeResult(w, result, err)
}

func (s Server) securityResponses(w http.ResponseWriter, r *http.Request) {
	result, err := securitymodel.BuildResponseActionsReport(s.DB, r.URL.Query().Get("run"))
	writeResult(w, result, err)
}

func (s Server) securityDeviations(w http.ResponseWriter, r *http.Request) {
	result, err := baseline.BuildDeviationsReport(s.DB, r.URL.Query().Get("run"))
	writeResult(w, result, err)
}

func (s Server) signalContext(w http.ResponseWriter, r *http.Request) {
	ctx, err := signal.BuildEvalContext(s.DB, r.URL.Query().Get("run"))
	writeResult(w, ctx, err)
}

func (s Server) signalRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RunID string `json:"run_id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	ctx, err := signal.BuildEvalContext(s.DB, req.RunID)
	if err != nil {
		writeResult(w, nil, err)
		return
	}
	report, err := signal.BuildBuiltinReportFromContext(ctx)
	writeResult(w, report, err)
}

func (s Server) signalImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RunID   string              `json:"run_id"`
		Engine  string              `json:"engine"`
		Signals []signal.EvalSignal `json:"signals"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	report, err := signal.ImportSignals(req.RunID, req.Engine, req.Signals)
	if err == nil {
		// Land imported evaluator signals in the unified model as quality signals.
		if _, perr := signal.PersistEvalSignals(s.DB, req.Engine, req.Signals); perr != nil {
			writeResult(w, nil, perr)
			return
		}
	}
	writeResult(w, report, err)
}

func evaluateTelemetryPolicy(db *sql.DB, result *telemetry.JSONLIngestResult) {
	if result == nil {
		return
	}
	for _, eventID := range result.EventIDs {
		record, persisted, err := securitymodel.EvaluateRuntimeEvent(db, eventID)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("event %s: policy failed: %v", eventID, err))
			result.Failed++
			continue
		}
		if persisted {
			result.PolicyDecisions++
			result.PolicyDecisionIDs = append(result.PolicyDecisionIDs, record.ID)
		}
	}
}

func buildEvidenceManifest(db *sql.DB, paths store.Paths, runID string, objectLimit int, materialize bool) (evidence.MaterializedManifest, error) {
	report, err := evidence.BuildManifest(db, evidence.ManifestOptions{RunID: runID, ObjectLimit: objectLimit})
	if err != nil {
		return evidence.MaterializedManifest{}, err
	}
	output := evidence.MaterializedManifest{Manifest: report}
	if !materialize {
		return output, nil
	}
	parentHashes := make([]string, 0, len(report.Objects.TopRefs))
	for _, ref := range report.Objects.TopRefs {
		if ref.Hash != "" {
			parentHashes = append(parentHashes, ref.Hash)
		}
	}
	result, err := (provenance.ObjectStore{DB: db, Paths: paths}).PutExternalObject(provenance.ExternalObjectInput{
		Type:     "evidence_manifest",
		SourceID: runID,
		RunID:    runID,
		Parents:  parentHashes,
		Refs: map[string]any{
			"run_id":                  runID,
			"schema_version":          report.SchemaVersion,
			"summary_result_set_id":   report.Summary.ResultSetID,
			"timeline_result_set_id":  report.Timeline.ResultSetID,
			"objects_result_set_id":   report.Objects.ResultSetID,
			"risks_result_set_id":     report.Security.RisksResultSetID,
			"responses_result_set_id": report.Security.ResponsesResultSetID,
		},
		Payload: map[string]any{"manifest": report},
	})
	if err != nil {
		return evidence.MaterializedManifest{}, err
	}
	output.ObjectHash = result.Hash
	output.ObjectPath = result.Path
	return output, nil
}

func (s Server) lockWrites() {
	if s.writeMu != nil {
		s.writeMu.Lock()
	}
}

func (s Server) unlockWrites() {
	if s.writeMu != nil {
		s.writeMu.Unlock()
	}
}

type flushWriter struct {
	http.ResponseWriter
}

func (w flushWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
	return n, err
}

func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(out); err != nil {
		writeResult(w, nil, err)
		return false
	}
	return true
}

func intQuery(r *http.Request, key string, fallback int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s query parameter", key)
	}
	return value, nil
}

func writeResult(w http.ResponseWriter, data any, err error) {
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, data)
}

func writeSpoolEnqueueResult(w http.ResponseWriter, batch telemetry.SpoolBatch, err error) {
	if err != nil {
		var backpressure telemetry.SpoolBackpressureError
		if errors.As(err, &backpressure) {
			w.WriteHeader(http.StatusTooManyRequests)
			writeJSON(w, map[string]any{
				"schema_version":   "agentprovenance.daemon_falco_spool/v1",
				"error":            backpressure.Reason,
				"queued":           backpressure.Queued,
				"max_queued":       backpressure.MaxQueued,
				"queued_bytes":     backpressure.QueuedBytes,
				"incoming_bytes":   backpressure.IncomingBytes,
				"max_queued_bytes": backpressure.MaxQueuedBytes,
				"max_batch_bytes":  backpressure.MaxBatchBytes,
				"reject_reason":    backpressure.Reason,
			})
			return
		}
		writeResult(w, nil, err)
		return
	}
	writeJSON(w, map[string]any{"spool_batch": batch, "schema_version": "agentprovenance.daemon_falco_spool/v1"})
}

func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}
