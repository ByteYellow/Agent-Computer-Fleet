package daemon

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/byteyellow/agent-computer-fleet/internal/control"
	runtimeplane "github.com/byteyellow/agent-computer-fleet/internal/runtime"
	"github.com/byteyellow/agent-computer-fleet/internal/state"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
)

type Server struct {
	DB     *sql.DB
	Paths  store.Paths
	Driver runtimeplane.Driver
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
	return Server{DB: db, Paths: paths, Driver: driver}, func() { db.Close() }, nil
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
	return mux
}

func (s Server) control() control.Service {
	return control.Service{DB: s.DB, Paths: s.Paths, Driver: s.Driver}
}

func (s Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"status": "ok", "runtime": s.Driver.Name()})
}

func (s Server) createLease(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Task string `json:"task"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
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
			err := s.control().RemoveSession(sessionID)
			writeResult(w, map[string]any{"status": "removed"}, err)
		default:
			http.NotFound(w, r)
		}
		return
	}
	switch parts[1] {
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
	id, err := s.control().ResumeSnapshot(parts[0], req.LeaseID)
	writeResult(w, map[string]any{"session_id": id}, err)
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

func writeResult(w http.ResponseWriter, data any, err error) {
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, data)
}

func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}
