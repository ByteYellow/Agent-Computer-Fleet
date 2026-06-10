package computerapi

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/control"
	"github.com/byteyellow/agent-computer-fleet/internal/ids"
	runtimeplane "github.com/byteyellow/agent-computer-fleet/internal/runtime"
	"github.com/byteyellow/agent-computer-fleet/internal/security"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
)

type Service struct {
	DB    *sql.DB
	Paths store.Paths
}

type SessionMeta struct {
	RunID         string
	ContainerID   string
	WorkspacePath string
}

type SearchMatch struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

func (s Service) ReadFile(sessionID, filePath, toolCallID string) (string, security.DecisionRecord, error) {
	meta, err := s.sessionMeta(sessionID)
	if err != nil {
		return "", security.DecisionRecord{}, err
	}
	hostPath, err := s.workspacePath(meta.WorkspacePath, filePath)
	if err != nil {
		return "", security.DecisionRecord{}, err
	}
	body, err := os.ReadFile(hostPath)
	if err != nil {
		return "", security.DecisionRecord{}, err
	}
	payload := map[string]any{
		"path":       filePath,
		"result_ref": hostPath,
		"bytes":      len(body),
	}
	record, err := s.recordEvent(security.Event{
		Source:     "computer_api",
		EventType:  "file_read",
		RunID:      meta.RunID,
		SessionID:  sessionID,
		ToolCallID: ensureToolCallID(toolCallID),
		Path:       filePath,
	}, payload)
	return string(body), record, err
}

func (s Service) WriteFile(sessionID, filePath, content, toolCallID string) (security.DecisionRecord, error) {
	meta, err := s.sessionMeta(sessionID)
	if err != nil {
		return security.DecisionRecord{}, err
	}
	hostPath, err := s.workspacePath(meta.WorkspacePath, filePath)
	if err != nil {
		return security.DecisionRecord{}, err
	}
	if err := os.MkdirAll(filepath.Dir(hostPath), 0o755); err != nil {
		return security.DecisionRecord{}, err
	}
	if err := os.WriteFile(hostPath, []byte(content), 0o644); err != nil {
		return security.DecisionRecord{}, err
	}
	return s.recordEvent(security.Event{
		Source:     "computer_api",
		EventType:  "file_write",
		RunID:      meta.RunID,
		SessionID:  sessionID,
		ToolCallID: ensureToolCallID(toolCallID),
		Path:       filePath,
	}, map[string]any{
		"path":       filePath,
		"result_ref": hostPath,
		"bytes":      len(content),
	})
}

func (s Service) Search(sessionID, pattern, toolCallID string) ([]SearchMatch, security.DecisionRecord, error) {
	meta, err := s.sessionMeta(sessionID)
	if err != nil {
		return nil, security.DecisionRecord{}, err
	}
	var matches []SearchMatch
	err = filepath.Walk(meta.WorkspacePath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lines := strings.Split(string(body), "\n")
		rel, _ := filepath.Rel(meta.WorkspacePath, path)
		for i, line := range lines {
			if strings.Contains(line, pattern) {
				matches = append(matches, SearchMatch{Path: "/" + filepath.ToSlash(rel), Line: i + 1, Text: line})
			}
		}
		return nil
	})
	if err != nil {
		return nil, security.DecisionRecord{}, err
	}
	record, err := s.recordEvent(security.Event{
		Source:     "computer_api",
		EventType:  "search",
		RunID:      meta.RunID,
		SessionID:  sessionID,
		ToolCallID: ensureToolCallID(toolCallID),
		Args:       []string{pattern},
	}, map[string]any{
		"pattern":     pattern,
		"match_count": len(matches),
		"result_ref":  "search:" + ensureToolCallID(toolCallID),
	})
	return matches, record, err
}

func (s Service) ExportArtifact(sessionID, filePath, name, toolCallID string) (string, security.DecisionRecord, error) {
	meta, err := s.sessionMeta(sessionID)
	if err != nil {
		return "", security.DecisionRecord{}, err
	}
	hostPath, err := s.workspacePath(meta.WorkspacePath, filePath)
	if err != nil {
		return "", security.DecisionRecord{}, err
	}
	body, err := os.ReadFile(hostPath)
	if err != nil {
		return "", security.DecisionRecord{}, err
	}
	if name == "" {
		name = filepath.Base(filePath)
	}
	artifactID := ids.New("artifact")
	artifactPath := filepath.Join(s.Paths.Artifacts, artifactID+"-"+name)
	if err := os.WriteFile(artifactPath, body, 0o644); err != nil {
		return "", security.DecisionRecord{}, err
	}
	record, err := s.recordEvent(security.Event{
		Source:     "computer_api",
		EventType:  "artifact_export",
		RunID:      meta.RunID,
		SessionID:  sessionID,
		ToolCallID: ensureToolCallID(toolCallID),
		Path:       filePath,
	}, map[string]any{
		"path":       filePath,
		"name":       name,
		"result_ref": artifactPath,
		"bytes":      len(body),
	})
	return artifactPath, record, err
}

func (s Service) Call(sessionID, module, function string, args map[string]string, toolCallID string, stream bool) (string, security.DecisionRecord, error) {
	meta, err := s.sessionMeta(sessionID)
	if err != nil {
		return "", security.DecisionRecord{}, err
	}
	if module != "shell" || function != "exec" {
		return "", security.DecisionRecord{}, fmt.Errorf("unsupported call target %s/%s; v1 supports shell/exec", module, function)
	}
	command := strings.TrimSpace(args["command"])
	if command == "" {
		return "", security.DecisionRecord{}, fmt.Errorf("call arg command is required")
	}
	driver, err := runtimeplane.NewDriver("docker", s.Paths)
	if err != nil {
		return "", security.DecisionRecord{}, err
	}
	processID, err := control.Service{DB: s.DB, Paths: s.Paths, Driver: driver}.Exec(sessionID, []string{"sh", "-lc", command}, stream)
	if err != nil {
		return "", security.DecisionRecord{}, err
	}
	record, err := s.recordEvent(security.Event{
		Source:     "computer_api",
		EventType:  "call",
		RunID:      meta.RunID,
		SessionID:  sessionID,
		ToolCallID: ensureToolCallID(toolCallID),
		ProcessID:  processID,
		Args:       []string{module, function, command},
	}, map[string]any{
		"module":     module,
		"function":   function,
		"command":    command,
		"process_id": processID,
		"result_ref": "process:" + processID,
	})
	return processID, record, err
}

func (s Service) sessionMeta(sessionID string) (SessionMeta, error) {
	var meta SessionMeta
	err := s.DB.QueryRow(`SELECT run_id, COALESCE(container_id, ''), workspace_host_path FROM sessions WHERE id = ?`, sessionID).
		Scan(&meta.RunID, &meta.ContainerID, &meta.WorkspacePath)
	return meta, err
}

func (s Service) workspacePath(workspaceRoot, requested string) (string, error) {
	trimmed := strings.TrimPrefix(requested, "/workspace")
	trimmed = strings.TrimPrefix(trimmed, "/")
	hostPath := filepath.Join(workspaceRoot, trimmed)
	cleanRoot := filepath.Clean(workspaceRoot)
	cleanPath := filepath.Clean(hostPath)
	if cleanPath != cleanRoot && !strings.HasPrefix(cleanPath, cleanRoot+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes workspace: %s", requested)
	}
	return cleanPath, nil
}

func (s Service) recordEvent(event security.Event, payload map[string]any) (security.DecisionRecord, error) {
	payload["recorded_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	keys := make([]string, 0, len(payload))
	for key := range payload {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	ordered := make(map[string]any, len(payload))
	for _, key := range keys {
		ordered[key] = payload[key]
	}
	raw, err := json.Marshal(ordered)
	if err != nil {
		return security.DecisionRecord{}, err
	}
	return security.EvaluateAndPersist(s.DB, event, string(raw))
}

func ensureToolCallID(toolCallID string) string {
	if strings.TrimSpace(toolCallID) != "" {
		return toolCallID
	}
	return ids.New("tool")
}
