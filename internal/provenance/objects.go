package provenance

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/redact"
	"github.com/byteyellow/agentprovenance/internal/store"
)

type ObjectStore struct {
	DB    *sql.DB
	Paths store.Paths
}

type MaterializeResult struct {
	RunID       string
	ObjectRoot  string
	ObjectCount int
	RootHashes  []string
}

type ObjectListManifest struct {
	SchemaVersion string      `json:"schema_version"`
	RunID         string      `json:"run_id"`
	Limit         int         `json:"limit"`
	Cursor        string      `json:"cursor,omitempty"`
	NextCursor    string      `json:"next_cursor,omitempty"`
	HasMore       bool        `json:"has_more"`
	ResultSetID   string      `json:"result_set_id"`
	PageHash      string      `json:"page_hash"`
	ObjectCount   int         `json:"object_count"`
	Objects       []ObjectRef `json:"objects"`
}

type ObjectRef struct {
	Hash         string `json:"hash"`
	Type         string `json:"type"`
	SourceID     string `json:"source_id"`
	RunID        string `json:"run_id"`
	RolloutID    string `json:"rollout_id"`
	ParentHashes string `json:"parent_hashes"`
	Path         string `json:"path"`
	SizeBytes    int64  `json:"size_bytes"`
	CreatedAt    string `json:"created_at"`
}

type ObjectListOptions struct {
	RunID  string
	Limit  int
	Cursor string
}

type ExternalObjectInput struct {
	Type      string
	SourceID  string
	RunID     string
	RolloutID string
	Parents   []string
	Refs      map[string]any
	Payload   map[string]any
}

type ExternalObjectResult struct {
	Hash string
	Path string
}

type provenanceObject struct {
	Schema    string         `json:"schema"`
	Type      string         `json:"type"`
	SourceID  string         `json:"source_id"`
	RunID     string         `json:"run_id,omitempty"`
	RolloutID string         `json:"rollout_id,omitempty"`
	Parents   []string       `json:"parents,omitempty"`
	Refs      map[string]any `json:"refs,omitempty"`
	Payload   map[string]any `json:"payload,omitempty"`
}

func (s ObjectStore) PutExternalObject(input ExternalObjectInput) (ExternalObjectResult, error) {
	if s.DB == nil {
		return ExternalObjectResult{}, fmt.Errorf("database is required")
	}
	if strings.TrimSpace(input.Type) == "" {
		return ExternalObjectResult{}, fmt.Errorf("object type is required")
	}
	if strings.TrimSpace(input.SourceID) == "" {
		return ExternalObjectResult{}, fmt.Errorf("source id is required")
	}
	if strings.TrimSpace(input.RunID) == "" {
		return ExternalObjectResult{}, fmt.Errorf("run_id is required")
	}
	if s.Paths.Provenance == "" {
		s.Paths.Provenance = filepath.Join(s.Paths.Root, "provenance")
	}
	ctx := materializeContext{store: s, runID: input.RunID, refHash: map[string]string{}}
	hash, err := ctx.put(provenanceObject{
		Type:      input.Type,
		SourceID:  input.SourceID,
		RunID:     input.RunID,
		RolloutID: input.RolloutID,
		Parents:   input.Parents,
		Refs:      input.Refs,
		Payload:   input.Payload,
	})
	if err != nil {
		return ExternalObjectResult{}, err
	}
	return ExternalObjectResult{Hash: hash, Path: ctx.objectPath(hash)}, nil
}

func (s ObjectStore) MaterializeRun(runID string) (MaterializeResult, error) {
	if runID == "" {
		return MaterializeResult{}, fmt.Errorf("run_id is required")
	}
	if s.DB == nil {
		return MaterializeResult{}, fmt.Errorf("database is required")
	}
	if s.Paths.Provenance == "" {
		s.Paths.Provenance = filepath.Join(s.Paths.Root, "provenance")
	}
	if err := os.MkdirAll(objectRoot(s.Paths), 0o755); err != nil {
		return MaterializeResult{}, err
	}
	ctx := materializeContext{store: s, runID: runID, refHash: map[string]string{}}
	if err := ctx.materializeSnapshots(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeRollouts(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeAttempts(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeToolCalls(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeProcesses(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeArtifacts(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializePromotions(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeEvidence(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeEvents(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeTelemetryBatches(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializePolicyDecisions(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeRiskSignals(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeBaselineDeviations(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeResponseActions(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeCosts(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeReplayManifest(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeTrajectoryManifest(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeDiffBlameManifests(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeAuditManifest(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeRecordManifest(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeRecordBatches(); err != nil {
		return MaterializeResult{}, err
	}
	sort.Strings(ctx.rootHashes)
	return MaterializeResult{
		RunID:       runID,
		ObjectRoot:  objectRoot(s.Paths),
		ObjectCount: ctx.objectCount,
		RootHashes:  ctx.rootHashes,
	}, nil
}

func PrintMaterializeResult(out io.Writer, result MaterializeResult) {
	fmt.Fprintf(out, "run=%s objects=%d object_root=%s\n", result.RunID, result.ObjectCount, result.ObjectRoot)
	for _, hash := range result.RootHashes {
		fmt.Fprintf(out, "root=%s\n", hash)
	}
}

func ListObjects(db *sql.DB, runID string) (ObjectListManifest, error) {
	return ListObjectsPage(db, ObjectListOptions{RunID: runID})
}

func ListObjectsPage(db *sql.DB, opts ObjectListOptions) (ObjectListManifest, error) {
	if opts.RunID == "" {
		return ObjectListManifest{}, fmt.Errorf("run_id is required")
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}
	where := `run_id = ?`
	args := []any{opts.RunID}
	if opts.Cursor != "" {
		cursorType, cursorCreatedAt, cursorHash, err := parseObjectCursor(opts.Cursor)
		if err != nil {
			return ObjectListManifest{}, err
		}
		where += ` AND (object_type > ? OR (object_type = ? AND created_at > ?) OR (object_type = ? AND created_at = ? AND hash > ?))`
		args = append(args, cursorType, cursorType, cursorCreatedAt, cursorType, cursorCreatedAt, cursorHash)
	}
	args = append(args, limit+1)
	rows, err := db.Query(`SELECT hash, object_type, source_id, run_id, rollout_id, parent_hashes, path, size_bytes, created_at
		FROM provenance_objects WHERE `+where+` ORDER BY object_type ASC, created_at ASC, hash ASC LIMIT ?`, args...)
	if err != nil {
		return ObjectListManifest{}, err
	}
	defer rows.Close()
	manifest := ObjectListManifest{SchemaVersion: "agentprovenance.objects/v1", RunID: opts.RunID, Limit: limit, Cursor: opts.Cursor}
	for rows.Next() {
		var ref ObjectRef
		if err := rows.Scan(&ref.Hash, &ref.Type, &ref.SourceID, &ref.RunID, &ref.RolloutID, &ref.ParentHashes, &ref.Path, &ref.SizeBytes, &ref.CreatedAt); err != nil {
			return ObjectListManifest{}, err
		}
		manifest.Objects = append(manifest.Objects, ref)
	}
	if err := rows.Err(); err != nil {
		return ObjectListManifest{}, err
	}
	if len(manifest.Objects) > limit {
		manifest.HasMore = true
		manifest.Objects = manifest.Objects[:limit]
	}
	manifest.ObjectCount = len(manifest.Objects)
	if manifest.HasMore && len(manifest.Objects) > 0 {
		last := manifest.Objects[len(manifest.Objects)-1]
		manifest.NextCursor = formatObjectCursor(last)
	}
	if err := finalizeObjectListIntegrity(&manifest); err != nil {
		return ObjectListManifest{}, err
	}
	return manifest, nil
}

func Objects(db *sql.DB, runID string, out io.Writer) error {
	return ObjectsPage(db, ObjectListOptions{RunID: runID}, out)
}

func ObjectsPage(db *sql.DB, opts ObjectListOptions, out io.Writer) error {
	manifest, err := ListObjectsPage(db, opts)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "run=%s schema=%s objects=%d limit=%d has_more=%t result_set=%s page_hash=%s next_cursor=%s\n",
		manifest.RunID, manifest.SchemaVersion, manifest.ObjectCount, manifest.Limit, manifest.HasMore, manifest.ResultSetID, manifest.PageHash, manifest.NextCursor)
	for _, object := range manifest.Objects {
		fmt.Fprintf(out, "object type=%s source=%s hash=%s parents=%s bytes=%d path=%s\n",
			object.Type, object.SourceID, object.Hash, object.ParentHashes, object.SizeBytes, object.Path)
	}
	return nil
}

func ObjectsJSON(db *sql.DB, runID string, out io.Writer) error {
	return ObjectsPageJSON(db, ObjectListOptions{RunID: runID}, out)
}

func ObjectsPageJSON(db *sql.DB, opts ObjectListOptions, out io.Writer) error {
	manifest, err := ListObjectsPage(db, opts)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(manifest)
}

func formatObjectCursor(ref ObjectRef) string {
	cursor, err := encodeCursor("objects", map[string]any{
		"type":       ref.Type,
		"created_at": ref.CreatedAt,
		"hash":       ref.Hash,
	})
	if err != nil {
		return ""
	}
	return cursor
}

func parseObjectCursor(cursor string) (string, string, string, error) {
	data, err := decodeCursor("objects", cursor)
	if err != nil {
		return "", "", "", err
	}
	objectType, err := cursorString(data, "type")
	if err != nil {
		return "", "", "", fmt.Errorf("invalid object cursor")
	}
	createdAt, err := cursorString(data, "created_at")
	if err != nil {
		return "", "", "", fmt.Errorf("invalid object cursor")
	}
	hash, err := cursorString(data, "hash")
	if err != nil {
		return "", "", "", fmt.Errorf("invalid object cursor")
	}
	return objectType, createdAt, hash, nil
}

func finalizeObjectListIntegrity(manifest *ObjectListManifest) error {
	resultSetID, err := stableDigest(map[string]any{
		"schema_version": manifest.SchemaVersion,
		"kind":           "objects",
		"run_id":         manifest.RunID,
		"order":          "object_type,created_at,hash",
	})
	if err != nil {
		return err
	}
	pageHash, err := stableDigest(map[string]any{
		"schema_version": manifest.SchemaVersion,
		"kind":           "objects_page",
		"run_id":         manifest.RunID,
		"limit":          manifest.Limit,
		"cursor":         manifest.Cursor,
		"next_cursor":    manifest.NextCursor,
		"has_more":       manifest.HasMore,
		"objects":        manifest.Objects,
	})
	if err != nil {
		return err
	}
	manifest.ResultSetID = resultSetID
	manifest.PageHash = pageHash
	return nil
}

type materializeContext struct {
	store       ObjectStore
	runID       string
	refHash     map[string]string
	objectCount int
	rootHashes  []string
}

func objectRoot(paths store.Paths) string {
	return filepath.Join(paths.Provenance, "objects", "sha256")
}

func (c *materializeContext) put(obj provenanceObject) (string, error) {
	obj.Schema = "agentprov.provenance.object.v1"
	if obj.RunID == "" {
		obj.RunID = c.runID
	}
	if obj.Refs == nil {
		obj.Refs = map[string]any{}
	}
	if obj.Payload == nil {
		obj.Payload = map[string]any{}
	}
	sort.Strings(obj.Parents)
	raw, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	// Backstop redaction before the object is hashed: content-addressed objects
	// (LLM message bodies, artifacts) are exported and shared, so mask any secret
	// here too. Redacting before the hash keeps the object self-consistent (the
	// stored hash matches the stored, masked bytes on import verification).
	if red, changed := redact.Redact(string(raw)); changed {
		raw = []byte(red)
	}
	sum := sha256.Sum256(raw)
	hash := "sha256:" + hex.EncodeToString(sum[:])
	path := c.objectPath(hash)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return "", err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = c.store.DB.Exec(`INSERT OR REPLACE INTO provenance_objects
		(hash, object_type, source_id, run_id, rollout_id, parent_hashes, path, size_bytes, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		hash, obj.Type, obj.SourceID, obj.RunID, obj.RolloutID, strings.Join(obj.Parents, ","), path, len(raw), now)
	if err != nil {
		return "", err
	}
	c.refHash[obj.Type+"/"+obj.SourceID] = hash
	c.objectCount++
	return hash, nil
}

func (c *materializeContext) objectPath(hash string) string {
	clean := strings.TrimPrefix(hash, "sha256:")
	prefix := clean
	if len(prefix) > 2 {
		prefix = prefix[:2]
	}
	return filepath.Join(objectRoot(c.store.Paths), prefix, clean+".json")
}

func (c *materializeContext) parent(keys ...string) []string {
	parents := []string{}
	seen := map[string]bool{}
	for _, key := range keys {
		if key == "" {
			continue
		}
		hash := c.refHash[key]
		if hash == "" || seen[hash] {
			continue
		}
		seen[hash] = true
		parents = append(parents, hash)
	}
	sort.Strings(parents)
	return parents
}

func (c *materializeContext) materializeSnapshots() error {
	rows, err := c.store.DB.Query(`SELECT DISTINCT sn.id, COALESCE(sn.name, ''), COALESCE(sn.parent_id, ''), sn.kind, sn.source, sn.path,
			sn.manifest_hash, sn.file_count, sn.bytes, sn.status, COALESCE(sn.tainted, 0), sn.created_at
		FROM snapshots sn
		WHERE sn.id IN (SELECT base_snapshot_id FROM rollouts WHERE run_id = ?)
		   OR sn.id IN (SELECT a.snapshot_id FROM fork_attempts a JOIN rollouts r ON a.rollout_id = r.id WHERE r.run_id = ?)
		   OR sn.session_id IN (SELECT id FROM sessions WHERE run_id = ?)
		ORDER BY sn.created_at ASC`, c.runID, c.runID, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, name, parentID, kind, source, path, manifestHash, status, createdAt string
		var files, bytes int64
		var tainted int
		if err := rows.Scan(&id, &name, &parentID, &kind, &source, &path, &manifestHash, &files, &bytes, &status, &tainted, &createdAt); err != nil {
			return err
		}
		_, err := c.put(provenanceObject{
			Type:     "snapshot",
			SourceID: id,
			Parents:  c.parent("snapshot/" + parentID),
			Refs:     map[string]any{"parent_id": parentID},
			Payload: map[string]any{
				"name": name, "kind": kind, "source": source, "path": path, "manifest_hash": manifestHash,
				"file_count": files, "bytes": bytes, "status": status, "tainted": tainted != 0, "created_at": createdAt,
			},
		})
		if err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializeRollouts() error {
	rows, err := c.store.DB.Query(`SELECT id, base_snapshot_id, status, fanout, winner_attempt_id, promotion_id, cost_estimate, risk_status, created_at, updated_at
		FROM rollouts WHERE run_id = ? ORDER BY created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, baseSnapshotID, status, winnerAttemptID, promotionID, riskStatus, createdAt, updatedAt string
		var fanout int
		var cost float64
		if err := rows.Scan(&id, &baseSnapshotID, &status, &fanout, &winnerAttemptID, &promotionID, &cost, &riskStatus, &createdAt, &updatedAt); err != nil {
			return err
		}
		hash, err := c.put(provenanceObject{
			Type:      "rollout",
			SourceID:  id,
			RolloutID: id,
			Parents:   c.parent("snapshot/" + baseSnapshotID),
			Refs:      map[string]any{"base_snapshot_id": baseSnapshotID, "winner_attempt_id": winnerAttemptID, "promotion_id": promotionID},
			Payload:   map[string]any{"status": status, "fanout": fanout, "cost_estimate": cost, "risk_status": riskStatus, "created_at": createdAt, "updated_at": updatedAt},
		})
		if err != nil {
			return err
		}
		c.rootHashes = append(c.rootHashes, hash)
	}
	return rows.Err()
}

func (c *materializeContext) materializeAttempts() error {
	rows, err := c.store.DB.Query(`SELECT a.id, a.rollout_id, a.tool_call_id, a.snapshot_id, a.strategy, a.command, a.status,
			COALESCE(a.exit_code, 0), a.wall_ms, a.output_summary, a.score, a.cost_estimate, a.saved_cost,
			a.risk_status, a.budget_exceeded, a.is_winner, COALESCE(a.artifact_result, ''), a.created_at
		FROM fork_attempts a JOIN rollouts r ON a.rollout_id = r.id WHERE r.run_id = ? ORDER BY a.created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, rolloutID, toolCallID, snapshotID, strategy, command, status, output, risk, artifact, createdAt string
		var exitCode, wallMS int64
		var score, cost, saved float64
		var budgetExceeded, isWinner int
		if err := rows.Scan(&id, &rolloutID, &toolCallID, &snapshotID, &strategy, &command, &status, &exitCode, &wallMS, &output, &score, &cost, &saved, &risk, &budgetExceeded, &isWinner, &artifact, &createdAt); err != nil {
			return err
		}
		if _, err := c.put(provenanceObject{
			Type:      "attempt",
			SourceID:  id,
			RolloutID: rolloutID,
			Parents:   c.parent("rollout/"+rolloutID, "snapshot/"+snapshotID),
			Refs:      map[string]any{"rollout_id": rolloutID, "tool_call_id": toolCallID, "snapshot_id": snapshotID, "artifact_result": artifact},
			Payload: map[string]any{
				"strategy": strategy, "command": command, "status": status, "exit_code": exitCode, "wall_ms": wallMS,
				"output_summary": output, "score": score, "cost_estimate": cost, "saved_cost": saved,
				"risk_status": risk, "budget_exceeded": budgetExceeded != 0, "winner": isWinner != 0, "created_at": createdAt,
			},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializeToolCalls() error {
	rows, err := c.store.DB.Query(`SELECT id, rollout_id, attempt_id, session_id, command, args_hash, status, COALESCE(exit_code, 0),
			wall_ms, cost_estimate, COALESCE(result_ref, ''), policy_decision, created_at, started_at, ended_at
		FROM tool_calls WHERE run_id = ? ORDER BY created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, rolloutID, attemptID, sessionID, command, argsHash, status, resultRef, policy, createdAt, startedAt, endedAt string
		var exitCode, wallMS int64
		var cost float64
		if err := rows.Scan(&id, &rolloutID, &attemptID, &sessionID, &command, &argsHash, &status, &exitCode, &wallMS, &cost, &resultRef, &policy, &createdAt, &startedAt, &endedAt); err != nil {
			return err
		}
		if _, err := c.put(provenanceObject{
			Type:      "tool_call",
			SourceID:  id,
			RolloutID: rolloutID,
			Parents:   c.parent("attempt/"+attemptID, "rollout/"+rolloutID),
			Refs:      map[string]any{"attempt_id": attemptID, "session_id": sessionID, "result_ref": resultRef},
			Payload: map[string]any{
				"command": command, "args_hash": argsHash, "status": status, "exit_code": exitCode, "wall_ms": wallMS,
				"cost_estimate": cost, "policy_decision": policy, "created_at": createdAt, "started_at": startedAt, "ended_at": endedAt,
			},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializeProcesses() error {
	rows, err := c.store.DB.Query(`SELECT p.id, p.session_id, COALESCE(p.tool_call_id, ''), p.command, p.status, COALESCE(p.exit_code, 0), p.started_at, COALESCE(p.ended_at, '')
		FROM processes p JOIN sessions s ON p.session_id = s.id WHERE s.run_id = ? ORDER BY p.started_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, sessionID, toolCallID, command, status, startedAt, endedAt string
		var exitCode int64
		if err := rows.Scan(&id, &sessionID, &toolCallID, &command, &status, &exitCode, &startedAt, &endedAt); err != nil {
			return err
		}
		if _, err := c.put(provenanceObject{
			Type:     "process",
			SourceID: id,
			Parents:  c.parent("tool_call/" + toolCallID),
			Refs:     map[string]any{"session_id": sessionID, "tool_call_id": toolCallID},
			Payload:  map[string]any{"command": command, "status": status, "exit_code": exitCode, "started_at": startedAt, "ended_at": endedAt},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializeArtifacts() error {
	rows, err := c.store.DB.Query(`SELECT a.id, a.rollout_id, a.tool_call_id, COALESCE(a.artifact_result, '')
		FROM fork_attempts a JOIN rollouts r ON a.rollout_id = r.id
		WHERE r.run_id = ? AND COALESCE(a.artifact_result, '') != '' ORDER BY a.created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var attemptID, rolloutID, toolCallID, artifactRef string
		if err := rows.Scan(&attemptID, &rolloutID, &toolCallID, &artifactRef); err != nil {
			return err
		}
		fileHash, size, exists := fileDigest(artifactRef)
		if _, err := c.put(provenanceObject{
			Type:      "artifact",
			SourceID:  artifactRef,
			RolloutID: rolloutID,
			Parents:   c.parent("attempt/"+attemptID, "tool_call/"+toolCallID),
			Refs:      map[string]any{"attempt_id": attemptID, "tool_call_id": toolCallID, "path": artifactRef},
			Payload:   map[string]any{"file_sha256": fileHash, "size_bytes": size, "exists": exists},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializePromotions() error {
	rows, err := c.store.DB.Query(`SELECT p.id, p.rollout_id, p.attempt_id, p.base_snapshot_id, p.status, p.risk_status, p.reason,
		COALESCE(p.telemetry_watermark, ''), COALESCE(p.drain_started_at, ''), COALESCE(p.drain_completed_at, ''),
		COALESCE(p.drain_queued_before, 0), COALESCE(p.drain_processed, 0), COALESCE(p.drain_pending_after, 0),
		p.created_at, p.updated_at
		FROM promotions p JOIN rollouts r ON p.rollout_id = r.id WHERE r.run_id = ? ORDER BY p.created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, rolloutID, attemptID, baseSnapshotID, status, riskStatus, reason, watermark, drainStartedAt, drainCompletedAt, createdAt, updatedAt string
		var drainQueuedBefore, drainProcessed, drainPendingAfter int
		if err := rows.Scan(&id, &rolloutID, &attemptID, &baseSnapshotID, &status, &riskStatus, &reason, &watermark, &drainStartedAt, &drainCompletedAt, &drainQueuedBefore, &drainProcessed, &drainPendingAfter, &createdAt, &updatedAt); err != nil {
			return err
		}
		hash, err := c.put(provenanceObject{
			Type:      "promotion",
			SourceID:  id,
			RolloutID: rolloutID,
			Parents:   c.parent("rollout/"+rolloutID, "attempt/"+attemptID, "snapshot/"+baseSnapshotID),
			Refs:      map[string]any{"attempt_id": attemptID, "base_snapshot_id": baseSnapshotID},
			Payload: map[string]any{
				"status": status, "risk_status": riskStatus, "reason": reason,
				"telemetry_watermark": watermark, "drain_started_at": drainStartedAt, "drain_completed_at": drainCompletedAt,
				"drain_queued_before": drainQueuedBefore, "drain_processed": drainProcessed, "drain_pending_after": drainPendingAfter,
				"created_at": createdAt, "updated_at": updatedAt,
			},
		})
		if err != nil {
			return err
		}
		c.rootHashes = append(c.rootHashes, hash)
	}
	return rows.Err()
}

func (c *materializeContext) materializeEvidence() error {
	rows, err := c.store.DB.Query(`SELECT id, rollout_id, attempt_id, session_id, tool_call_id, snapshot_id, event_type, priority, payload, status, created_at, processed_at
		FROM evidence_events WHERE run_id = ? ORDER BY created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, rolloutID, attemptID, sessionID, toolCallID, snapshotID, eventType, priority, payload, status, createdAt, processedAt string
		if err := rows.Scan(&id, &rolloutID, &attemptID, &sessionID, &toolCallID, &snapshotID, &eventType, &priority, &payload, &status, &createdAt, &processedAt); err != nil {
			return err
		}
		if _, err := c.put(provenanceObject{
			Type:      "evidence",
			SourceID:  id,
			RolloutID: rolloutID,
			Parents:   c.parent("attempt/"+attemptID, "tool_call/"+toolCallID, "snapshot/"+snapshotID),
			Refs:      map[string]any{"attempt_id": attemptID, "session_id": sessionID, "tool_call_id": toolCallID, "snapshot_id": snapshotID},
			Payload:   map[string]any{"event_type": eventType, "priority": priority, "payload": payload, "status": status, "created_at": createdAt, "processed_at": processedAt},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializeEvents() error {
	rows, err := c.store.DB.Query(`SELECT id, COALESCE(session_id, ''), COALESCE(tool_call_id, ''), COALESCE(process_id, ''), COALESCE(snapshot_id, ''), source, event_type, payload, created_at
		FROM events WHERE run_id = ? ORDER BY created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, sessionID, toolCallID, processID, snapshotID, source, eventType, payload, createdAt string
		if err := rows.Scan(&id, &sessionID, &toolCallID, &processID, &snapshotID, &source, &eventType, &payload, &createdAt); err != nil {
			return err
		}
		if _, err := c.put(provenanceObject{
			Type:     "event",
			SourceID: id,
			Parents:  c.parent("tool_call/"+toolCallID, "process/"+processID, "snapshot/"+snapshotID),
			Refs:     map[string]any{"session_id": sessionID, "tool_call_id": toolCallID, "process_id": processID, "snapshot_id": snapshotID},
			Payload:  map[string]any{"source": source, "event_type": eventType, "payload": payload, "created_at": createdAt},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializeTelemetryBatches() error {
	rows, err := c.store.DB.Query(`SELECT id, format, path, file_sha256, read_count, ingested_count,
			skipped_count, failed_count, event_ids_json, event_ids_sha256, created_at
		FROM telemetry_batches WHERE run_id = ? ORDER BY created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, format, path, fileSHA, eventIDsJSON, eventIDsSHA, createdAt string
		var read, ingested, skipped, failed int
		if err := rows.Scan(&id, &format, &path, &fileSHA, &read, &ingested, &skipped, &failed, &eventIDsJSON, &eventIDsSHA, &createdAt); err != nil {
			return err
		}
		var eventIDs []string
		_ = json.Unmarshal([]byte(eventIDsJSON), &eventIDs)
		parentKeys := make([]string, 0, len(eventIDs))
		for _, eventID := range eventIDs {
			parentKeys = append(parentKeys, "event/"+eventID)
		}
		if _, err := c.put(provenanceObject{
			Type:     "telemetry_batch",
			SourceID: id,
			Parents:  c.parent(parentKeys...),
			Refs:     map[string]any{"run_id": c.runID, "event_ids": eventIDs},
			Payload: map[string]any{
				"format": format, "path": path, "file_sha256": fileSHA,
				"read": read, "ingested": ingested, "skipped": skipped, "failed": failed,
				"event_ids": eventIDs, "event_ids_sha256": eventIDsSHA, "created_at": createdAt,
			},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializePolicyDecisions() error {
	rows, err := c.store.DB.Query(`SELECT id, COALESCE(event_id, ''), COALESCE(session_id, ''), rule_id, decision, reason, created_at
		FROM policy_decisions WHERE run_id = ? ORDER BY created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, eventID, sessionID, ruleID, decision, reason, createdAt string
		if err := rows.Scan(&id, &eventID, &sessionID, &ruleID, &decision, &reason, &createdAt); err != nil {
			return err
		}
		if _, err := c.put(provenanceObject{
			Type:     "policy_decision",
			SourceID: id,
			Parents:  c.parent("event/" + eventID),
			Refs:     map[string]any{"event_id": eventID, "session_id": sessionID},
			Payload:  map[string]any{"rule_id": ruleID, "decision": decision, "reason": reason, "created_at": createdAt},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializeRiskSignals() error {
	rows, err := c.store.DB.Query(`SELECT id, session_id, tool_call_id, process_id, snapshot_id, event_id,
			policy_decision_id, signal_type, severity, reason, recommended_action, payload, created_at
		FROM risk_signals WHERE run_id = ? ORDER BY created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, sessionID, toolCallID, processID, snapshotID, eventID, decisionID, signalType, severity, reason, action, payload, createdAt string
		if err := rows.Scan(&id, &sessionID, &toolCallID, &processID, &snapshotID, &eventID, &decisionID, &signalType, &severity, &reason, &action, &payload, &createdAt); err != nil {
			return err
		}
		if _, err := c.put(provenanceObject{
			Type:     "risk_signal",
			SourceID: id,
			Parents:  c.parent("event/"+eventID, "policy_decision/"+decisionID, "tool_call/"+toolCallID, "process/"+processID, "snapshot/"+snapshotID),
			Refs:     map[string]any{"event_id": eventID, "policy_decision_id": decisionID, "session_id": sessionID, "tool_call_id": toolCallID, "process_id": processID, "snapshot_id": snapshotID},
			Payload:  map[string]any{"signal_type": signalType, "severity": severity, "reason": reason, "recommended_action": action, "payload": payload, "created_at": createdAt},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializeBaselineDeviations() error {
	rows, err := c.store.DB.Query(`SELECT id, template_name, profile_id, deviation_type, status, expected_value,
			observed_value, recommended_action, payload, created_at
		FROM baseline_deviations WHERE run_id = ? ORDER BY created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, templateName, profileID, deviationType, status, action, payload, createdAt string
		var expected, observed float64
		if err := rows.Scan(&id, &templateName, &profileID, &deviationType, &status, &expected, &observed, &action, &payload, &createdAt); err != nil {
			return err
		}
		if _, err := c.put(provenanceObject{
			Type:     "baseline_deviation",
			SourceID: id,
			Refs:     map[string]any{"run_id": c.runID, "template_name": templateName, "profile_id": profileID},
			Payload: map[string]any{
				"deviation_type": deviationType, "status": status, "expected_value": expected,
				"observed_value": observed, "recommended_action": action, "payload": payload, "created_at": createdAt,
			},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializeResponseActions() error {
	rows, err := c.store.DB.Query(`SELECT id, session_id, process_id, snapshot_id, risk_signal_id, policy_decision_id,
			action_type, target_type, target_id, status, result_ref, payload, created_at
		FROM response_actions WHERE run_id = ? ORDER BY created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, sessionID, processID, snapshotID, riskID, decisionID, actionType, targetType, targetID, status, resultRef, payload, createdAt string
		if err := rows.Scan(&id, &sessionID, &processID, &snapshotID, &riskID, &decisionID, &actionType, &targetType, &targetID, &status, &resultRef, &payload, &createdAt); err != nil {
			return err
		}
		if _, err := c.put(provenanceObject{
			Type:     "response_action",
			SourceID: id,
			Parents:  c.parent("risk_signal/"+riskID, "policy_decision/"+decisionID, "process/"+processID, "snapshot/"+snapshotID),
			Refs:     map[string]any{"session_id": sessionID, "process_id": processID, "snapshot_id": snapshotID, "risk_signal_id": riskID, "policy_decision_id": decisionID},
			Payload:  map[string]any{"action_type": actionType, "target_type": targetType, "target_id": targetID, "status": status, "result_ref": resultRef, "payload": payload, "created_at": createdAt},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializeCosts() error {
	rows, err := c.store.DB.Query(`SELECT id, COALESCE(session_id, ''), active_cpu_seconds, idle_seconds, wall_seconds, snapshot_bytes, policy_block_count, quarantine_count, fanout_cost, saved_cost, created_at
		FROM cost_samples WHERE run_id = ? ORDER BY created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, sessionID, createdAt string
		var activeCPU, idle, wall, fanoutCost, savedCost float64
		var snapshotBytes, policyBlocks, quarantine int64
		if err := rows.Scan(&id, &sessionID, &activeCPU, &idle, &wall, &snapshotBytes, &policyBlocks, &quarantine, &fanoutCost, &savedCost, &createdAt); err != nil {
			return err
		}
		if _, err := c.put(provenanceObject{
			Type:     "cost",
			SourceID: id,
			Refs:     map[string]any{"session_id": sessionID},
			Payload: map[string]any{
				"active_cpu_seconds": activeCPU, "idle_seconds": idle, "wall_seconds": wall, "snapshot_bytes": snapshotBytes,
				"policy_block_count": policyBlocks, "quarantine_count": quarantine, "fanout_cost": fanoutCost, "saved_cost": savedCost, "created_at": createdAt,
			},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializeReplayManifest() error {
	manifest, err := BuildReplayRun(c.store.DB, c.runID)
	if err != nil {
		if err == sql.ErrNoRows || isNoRolloutRun(err) {
			return nil
		}
		return err
	}
	payload, err := payloadMap(manifest)
	if err != nil {
		return err
	}
	hash, err := c.put(provenanceObject{
		Type:     "replay_manifest",
		SourceID: c.runID,
		Parents:  append([]string{}, c.rootHashes...),
		Refs:     map[string]any{"run_id": c.runID, "schema_version": manifest.SchemaVersion, "mode": manifest.Mode, "scope": manifest.Scope},
		Payload:  payload,
	})
	if err != nil {
		return err
	}
	c.rootHashes = append(c.rootHashes, hash)
	return nil
}

func (c *materializeContext) materializeTrajectoryManifest() error {
	manifest, err := BuildTrajectoriesRun(c.store.DB, c.runID)
	if err != nil {
		if err == sql.ErrNoRows || isNoRolloutRun(err) {
			return nil
		}
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	payload, err := payloadMap(manifest)
	if err != nil {
		return err
	}
	hash, err := c.put(provenanceObject{
		Type:     "trajectory_manifest",
		SourceID: c.runID,
		Parents:  c.parent("replay_manifest/" + c.runID),
		Refs:     map[string]any{"run_id": c.runID, "schema_version": manifest.SchemaVersion, "decision_owner": manifest.DecisionOwner},
		Payload:  payload,
	})
	if err != nil {
		return err
	}
	c.rootHashes = append(c.rootHashes, hash)
	return nil
}

func (c *materializeContext) materializeDiffBlameManifests() error {
	files, err := filesChangedInRun(c.store.DB, c.runID)
	if err != nil {
		if os.IsNotExist(err) || isNoRolloutRun(err) {
			return nil
		}
		return err
	}
	for _, file := range files {
		diff, err := BuildDiffFile(c.store.DB, c.runID, file)
		if err != nil {
			return err
		}
		diffPayload, err := payloadMap(diff)
		if err != nil {
			return err
		}
		diffHash, err := c.put(provenanceObject{
			Type:     "diff_manifest",
			SourceID: c.runID + ":" + file,
			Parents:  c.parent("trajectory_manifest/"+c.runID, "snapshot/"+diff.BaseSnapshotID),
			Refs:     map[string]any{"run_id": c.runID, "file": file, "schema_version": diff.SchemaVersion, "base_snapshot_id": diff.BaseSnapshotID},
			Payload:  diffPayload,
		})
		if err != nil {
			return err
		}
		blame, err := BuildBlameFile(c.store.DB, c.runID, file)
		if err != nil {
			return err
		}
		blamePayload, err := payloadMap(blame)
		if err != nil {
			return err
		}
		_, err = c.put(provenanceObject{
			Type:     "blame_manifest",
			SourceID: c.runID + ":" + file,
			Parents:  []string{diffHash},
			Refs:     map[string]any{"run_id": c.runID, "file": file, "schema_version": blame.SchemaVersion, "base_snapshot_id": blame.BaseSnapshotID},
			Payload:  blamePayload,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func isNoRolloutRun(err error) bool {
	return err != nil && strings.Contains(err.Error(), "has no rollouts")
}

func (c *materializeContext) materializeAuditManifest() error {
	payload := map[string]any{
		"schema_version": "agentprovenance.audit/v1",
		"run_id":         c.runID,
		"object_count":   c.objectCount,
	}
	for _, item := range []struct {
		key   string
		query string
	}{
		{"rollout_count", `SELECT COUNT(*) FROM rollouts WHERE run_id = ?`},
		{"attempt_count", `SELECT COUNT(*) FROM fork_attempts WHERE rollout_id IN (SELECT id FROM rollouts WHERE run_id = ?)`},
		{"tool_call_count", `SELECT COUNT(*) FROM tool_calls WHERE run_id = ?`},
		{"process_count", `SELECT COUNT(*) FROM processes WHERE session_id IN (SELECT id FROM sessions WHERE run_id = ?)`},
		{"event_count", `SELECT COUNT(*) FROM events WHERE run_id = ?`},
		{"evidence_count", `SELECT COUNT(*) FROM evidence_events WHERE run_id = ?`},
		{"policy_decision_count", `SELECT COUNT(*) FROM policy_decisions WHERE run_id = ?`},
	} {
		var count int
		if err := c.store.DB.QueryRow(item.query, c.runID).Scan(&count); err != nil {
			return err
		}
		payload[item.key] = count
	}
	hash, err := c.put(provenanceObject{
		Type:     "audit_manifest",
		SourceID: c.runID,
		Parents:  append([]string{}, c.rootHashes...),
		Refs:     map[string]any{"run_id": c.runID, "schema_version": payload["schema_version"]},
		Payload:  payload,
	})
	if err != nil {
		return err
	}
	c.rootHashes = append(c.rootHashes, hash)
	return nil
}

func (c *materializeContext) materializeRecordManifest() error {
	manifest, err := BuildRecordManifest(c.store.DB, c.runID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	}
	hash, err := c.put(provenanceObject{
		Type:     "record_manifest",
		SourceID: c.runID,
		Parents:  c.parent("rollout/"+manifest.RolloutID, "attempt/"+manifest.AttemptID, "tool_call/"+manifest.ToolCallID, "process/"+manifest.ProcessID, "snapshot/"+manifest.BaseSnapshotID),
		Refs:     map[string]any{"run_id": c.runID, "schema_version": manifest.SchemaVersion, "attempt_id": manifest.AttemptID, "tool_call_id": manifest.ToolCallID, "process_id": manifest.ProcessID},
		Payload:  map[string]any{"manifest": manifest},
	})
	if err != nil {
		return err
	}
	c.rootHashes = append(c.rootHashes, hash)
	return nil
}

func (c *materializeContext) materializeRecordBatches() error {
	rows, err := c.store.DB.Query(`SELECT DISTINCT b.id, b.input_sha256, b.started_at, b.ended_at, b.job_count,
			b.passed, b.failed, b.skipped, b.status_counts_json, b.run_ids_json, b.shards_json,
			b.result_set_id, b.page_hash, b.created_at
		FROM record_batches b JOIN record_batch_items i ON i.batch_id = b.id
		WHERE i.run_id = ?
		ORDER BY b.created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var batch RecordBatchManifest
		var statusCountsJSON, runIDsJSON, shardsJSON string
		if err := rows.Scan(&batch.BatchID, &batch.InputSHA256, &batch.StartedAt, &batch.EndedAt, &batch.JobCount,
			&batch.Passed, &batch.Failed, &batch.Skipped, &statusCountsJSON, &runIDsJSON, &shardsJSON,
			&batch.ResultSetID, &batch.PageHash, &batch.CreatedAt); err != nil {
			return err
		}
		batch.SchemaVersion = "agentprovenance.record_batch/v1"
		_ = json.Unmarshal([]byte(statusCountsJSON), &batch.StatusCounts)
		_ = json.Unmarshal([]byte(runIDsJSON), &batch.RunIDs)
		_ = json.Unmarshal([]byte(shardsJSON), &batch.Shards)
		batch.Items, err = recordBatchItems(c.store.DB, batch.BatchID, "")
		if err != nil {
			return err
		}
		batchPayload, err := payloadMap(batch)
		if err != nil {
			return err
		}
		batchHash, err := c.put(provenanceObject{
			Type:     "record_batch",
			SourceID: batch.BatchID,
			Parents:  c.parent("record_manifest/" + c.runID),
			Refs: map[string]any{
				"batch_id":       batch.BatchID,
				"run_id":         c.runID,
				"run_ids":        batch.RunIDs,
				"schema_version": batch.SchemaVersion,
				"result_set_id":  batch.ResultSetID,
				"page_hash":      batch.PageHash,
			},
			Payload: batchPayload,
		})
		if err != nil {
			return err
		}
		summary := RecordBatchSummaryManifest{
			SchemaVersion: "agentprovenance.record_batch_summary/v1",
			BatchID:       batch.BatchID,
			RunID:         c.runID,
			Items:         filterRecordBatchItems(batch.Items, c.runID),
			ResultSetID:   batch.ResultSetID,
			PageHash:      batch.PageHash,
		}
		summary.ItemCount = len(summary.Items)
		summary.StatusCounts = map[string]int{}
		summary.Shards = map[string]int{}
		for _, item := range summary.Items {
			summary.StatusCounts[item.Status]++
			if item.Status == "passed" {
				summary.Passed++
			}
			if item.Status == "failed" {
				summary.Failed++
			}
			if item.Status == "skipped" {
				summary.Skipped++
			}
			if item.ShardID != "" {
				summary.Shards[item.ShardID]++
			}
		}
		summaryPayload, err := payloadMap(summary)
		if err != nil {
			return err
		}
		summaryHash, err := c.put(provenanceObject{
			Type:     "record_batch_summary",
			SourceID: batch.BatchID + ":" + c.runID,
			Parents:  append(c.parent("record_manifest/"+c.runID), batchHash),
			Refs: map[string]any{
				"batch_id":       batch.BatchID,
				"run_id":         c.runID,
				"schema_version": summary.SchemaVersion,
				"result_set_id":  summary.ResultSetID,
				"page_hash":      summary.PageHash,
			},
			Payload: summaryPayload,
		})
		if err != nil {
			return err
		}
		c.rootHashes = append(c.rootHashes, summaryHash)
	}
	return rows.Err()
}

type RecordBatchManifest struct {
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
	Items         []RecordBatchItem `json:"items"`
	ResultSetID   string            `json:"result_set_id"`
	PageHash      string            `json:"page_hash"`
	CreatedAt     string            `json:"created_at"`
}

type RecordBatchSummaryManifest struct {
	SchemaVersion string            `json:"schema_version"`
	BatchID       string            `json:"batch_id"`
	RunID         string            `json:"run_id"`
	ItemCount     int               `json:"item_count"`
	Passed        int               `json:"passed"`
	Failed        int               `json:"failed"`
	Skipped       int               `json:"skipped"`
	StatusCounts  map[string]int    `json:"status_counts"`
	Shards        map[string]int    `json:"shards,omitempty"`
	Items         []RecordBatchItem `json:"items"`
	ResultSetID   string            `json:"result_set_id"`
	PageHash      string            `json:"page_hash"`
}

type RecordBatchItem struct {
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

func recordBatchItems(db *sql.DB, batchID, runID string) ([]RecordBatchItem, error) {
	where := "batch_id = ?"
	args := []any{batchID}
	if runID != "" {
		where += " AND run_id = ?"
		args = append(args, runID)
	}
	rows, err := db.Query(`SELECT idx, job_id, shard_id, run_id, attempt_id, tool_call_id, process_id, workdir, command, status,
			exit_code, wall_ms, changed_file_count, changed_files_json, error, evidence_manifest_command, eval_context_command, explain_command
		FROM record_batch_items WHERE `+where+` ORDER BY idx ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []RecordBatchItem
	for rows.Next() {
		var item RecordBatchItem
		var changedFilesJSON string
		if err := rows.Scan(&item.Index, &item.JobID, &item.ShardID, &item.RunID, &item.AttemptID, &item.ToolCallID,
			&item.ProcessID, &item.Workdir, &item.Command, &item.Status, &item.ExitCode, &item.WallMS,
			&item.ChangedFileCount, &changedFilesJSON, &item.Error, &item.EvidenceManifestCommand,
			&item.EvalContextCommand, &item.ExplainCommand); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(changedFilesJSON), &item.ChangedFiles)
		items = append(items, item)
	}
	return items, rows.Err()
}

func filterRecordBatchItems(items []RecordBatchItem, runID string) []RecordBatchItem {
	out := make([]RecordBatchItem, 0)
	for _, item := range items {
		if item.RunID == runID {
			out = append(out, item)
		}
	}
	return out
}

func filesChangedInRun(db *sql.DB, runID string) ([]string, error) {
	manifest, err := BuildTrajectoriesRun(db, runID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	seen := map[string]bool{}
	files := []string{}
	for _, trajectory := range manifest.Trajectories {
		for _, change := range trajectory.FileChanges {
			if !change.BaseExists && !change.NextExists {
				continue
			}
			if seen[change.Path] {
				continue
			}
			seen[change.Path] = true
			files = append(files, change.Path)
		}
	}
	sort.Strings(files)
	return files, nil
}

func payloadMap(value any) (map[string]any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

type RecordManifest struct {
	SchemaVersion     string                  `json:"schema_version"`
	RunID             string                  `json:"run_id"`
	RolloutID         string                  `json:"rollout_id"`
	BaseSnapshotID    string                  `json:"base_snapshot_id"`
	AttemptID         string                  `json:"attempt_id"`
	SessionID         string                  `json:"session_id"`
	ToolCallID        string                  `json:"tool_call_id"`
	ProcessID         string                  `json:"process_id"`
	Workdir           string                  `json:"workdir"`
	Command           string                  `json:"command"`
	Status            string                  `json:"status"`
	ExitCode          int64                   `json:"exit_code"`
	WallMS            int64                   `json:"wall_ms"`
	ChangedFiles      []string                `json:"changed_files"`
	ChangedFileCount  int                     `json:"changed_file_count"`
	RootPID           int64                   `json:"root_pid"`
	ObservedProcesses []RecordObservedProcess `json:"observed_processes,omitempty"`
	OrphanPolicy      string                  `json:"orphan_policy"`
	PostRootGraceMS   int64                   `json:"post_root_grace_ms"`
	CWD               string                  `json:"cwd"`
	ProcessTreeCount  int                     `json:"process_tree_count"`
	TimeWindow        map[string]any          `json:"time_window"`
	ContextMode       string                  `json:"context_mode"`
	ScopeInference    map[string]any          `json:"scope_inference"`
}

type RecordObservedProcess struct {
	PID          int64  `json:"pid"`
	PPID         int64  `json:"ppid"`
	Command      string `json:"command"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
	OutlivedRoot bool   `json:"outlived_root"`
}

func BuildRecordManifest(db *sql.DB, runID string) (RecordManifest, error) {
	var m RecordManifest
	m.SchemaVersion = "agentprovenance.record/v1"
	m.RunID = runID
	err := db.QueryRow(`SELECT a.id, a.rollout_id, a.tool_call_id, a.snapshot_id, a.workspace_path, a.command, a.status, COALESCE(a.exit_code, 0), a.wall_ms
		FROM fork_attempts a JOIN rollouts r ON a.rollout_id = r.id
		WHERE r.run_id = ? AND a.strategy = 'zero-sdk-record'
		ORDER BY a.created_at ASC LIMIT 1`, runID).Scan(&m.AttemptID, &m.RolloutID, &m.ToolCallID, &m.BaseSnapshotID, &m.Workdir, &m.Command, &m.Status, &m.ExitCode, &m.WallMS)
	if err != nil {
		return RecordManifest{}, err
	}
	_ = db.QueryRow(`SELECT id FROM sessions WHERE run_id = ? ORDER BY created_at ASC LIMIT 1`, runID).Scan(&m.SessionID)
	var startedAt, endedAt string
	_ = db.QueryRow(`SELECT id, started_at, COALESCE(ended_at, '') FROM processes WHERE tool_call_id = ? ORDER BY started_at ASC LIMIT 1`, m.ToolCallID).Scan(&m.ProcessID, &startedAt, &endedAt)
	_ = db.QueryRow(`SELECT COALESCE(root_pid, 0), started_at, COALESCE(ended_at, '') FROM execution_context_bindings WHERE process_id = ? ORDER BY created_at ASC LIMIT 1`, m.ProcessID).Scan(&m.RootPID, &startedAt, &endedAt)
	m.CWD = m.Workdir
	m.ContextMode = "zero_sdk"
	m.TimeWindow = map[string]any{"started_at": startedAt, "ended_at": endedAt}
	observed, err := recordObservedProcesses(db, runID)
	if err != nil {
		return RecordManifest{}, err
	}
	m.ObservedProcesses = observed
	m.OrphanPolicy = "observe_only"
	m.PostRootGraceMS = 250
	m.ProcessTreeCount = 0
	if m.RootPID != 0 {
		m.ProcessTreeCount = 1 + len(m.ObservedProcesses)
	}
	rows, err := db.Query(`SELECT payload FROM events WHERE run_id = ? AND source = 'record_file_diff' AND event_type = 'file_write' ORDER BY created_at ASC`, runID)
	if err != nil {
		return RecordManifest{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return RecordManifest{}, err
		}
		if path := verifyPayloadPath(payload); path != "" {
			m.ChangedFiles = append(m.ChangedFiles, path)
		}
	}
	if err := rows.Err(); err != nil {
		return RecordManifest{}, err
	}
	sort.Strings(m.ChangedFiles)
	m.ChangedFileCount = len(m.ChangedFiles)
	m.ScopeInference = map[string]any{
		"method":             "zero_sdk_root_process+cwd+time_window+file_diff",
		"root_pid":           m.RootPID,
		"process_tree_count": m.ProcessTreeCount,
		"cwd":                m.CWD,
		"changed_file_count": m.ChangedFileCount,
		"observed_processes": len(m.ObservedProcesses),
		"boundary":           "root_pid_descendants+cwd+time_window+file_diff",
		"orphan_policy":      m.OrphanPolicy,
		"post_root_grace_ms": m.PostRootGraceMS,
	}
	return m, nil
}

func recordObservedProcesses(db *sql.DB, runID string) ([]RecordObservedProcess, error) {
	rows, err := db.Query(`SELECT payload FROM events
		WHERE run_id = ? AND source = 'record_process_sample' AND event_type = 'process_observed'
		ORDER BY created_at ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RecordObservedProcess
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var proc RecordObservedProcess
		if err := json.Unmarshal(unwrapRecordProcessPayload(payload), &proc); err != nil {
			continue
		}
		if proc.PID != 0 {
			out = append(out, proc)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out, nil
}

func fileDigest(path string) (string, int64, bool) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, false
	}
	defer file.Close()
	h := sha256.New()
	n, err := io.Copy(h, file)
	if err != nil {
		return "", 0, false
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), n, true
}
