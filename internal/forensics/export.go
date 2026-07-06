package forensics

import (
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/evidence"
	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/redact"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

type Service struct {
	DB    *sql.DB
	Paths store.Paths
	// SignKey, when set, makes ExportBundle emit a capture-time DSSE/in-toto
	// attestation over the bundle's sha256 for tamper-evidence.
	// When nil, bundles are produced unsigned and behavior is unchanged.
	SignKey   ed25519.PrivateKey
	SignKeyID string
}

type BundleInfo struct {
	SchemaVersion   string `json:"schema_version"`
	ID              string `json:"id"`
	RunID           string `json:"run_id"`
	Path            string `json:"path"`
	SHA256          string `json:"sha256"`
	SizeBytes       int64  `json:"size_bytes"`
	Status          string `json:"status"`
	CreatedAt       string `json:"created_at"`
	Signed          bool   `json:"signed"`
	AttestationPath string `json:"attestation_path,omitempty"`
}

func (s Service) Export(runID string) (string, error) {
	info, err := s.ExportBundle(runID)
	if err != nil {
		return "", err
	}
	return info.Path, nil
}

func (s Service) ExportBundle(runID string) (BundleInfo, error) {
	if runID == "" {
		return BundleInfo{}, fmt.Errorf("run_id is required")
	}
	batches, err := telemetry.ListBatches(s.DB, runID)
	if err != nil {
		return BundleInfo{}, err
	}
	evidenceManifest, err := evidence.BuildManifest(s.DB, evidence.ManifestOptions{RunID: runID})
	if err != nil {
		return BundleInfo{}, err
	}
	// Replay-relevant tables are dumped with SELECT * (full columns), not curated
	// subsets: a forensics bundle is also the replay artifact, and import re-inserts
	// these rows verbatim, so dropping a column here silently breaks the replayed
	// graph (e.g. processes.tool_call_id wires tool_call->process in the lens).
	// Each entry pairs a table with the WHERE that scopes it to this run.
	type tableSpec struct{ key, table, where, order string }
	specs := []tableSpec{
		{"leases", "leases", "run_id = ?", "created_at ASC, id ASC"},
		{"sessions", "sessions", "run_id = ?", "created_at ASC, id ASC"},
		// Correlation bindings must travel or the replayed run has correlated events
		// with no binding, which verify flags as missing_execution_context_binding.
		{"execution_context_bindings", "execution_context_bindings", "run_id = ?", "created_at ASC, id ASC"},
		{"rollouts", "rollouts", "run_id = ?", "created_at ASC, id ASC"},
		{"tool_calls", "tool_calls", "run_id = ?", "created_at ASC, id ASC"},
		// Multi-agent orchestration actors (names/types/parent) so a replayed
		// orchestration lens shows alice/bob/recon, not bare agent ids.
		{"agents", "agents", "run_id = ?", "id ASC"},
		{"processes", "processes", "session_id IN (SELECT id FROM sessions WHERE run_id = ?)", "started_at ASC, id ASC"},
		{"fork_attempts", "fork_attempts", "rollout_id IN (SELECT id FROM rollouts WHERE run_id = ?)", "created_at ASC, id ASC"},
		// Snapshots a run references aren't all session-scoped: a rollout's base
		// snapshot (and an attempt's snapshot) can predate the run's sessions, so
		// include those too or the replayed graph shows them as "unknown" nodes.
		{"snapshots", "snapshots", "session_id IN (SELECT id FROM sessions WHERE run_id = ?)" +
			" OR id IN (SELECT base_snapshot_id FROM rollouts WHERE run_id = ?)" +
			" OR id IN (SELECT snapshot_id FROM fork_attempts WHERE rollout_id IN (SELECT id FROM rollouts WHERE run_id = ?))", "created_at ASC, id ASC"},
		{"events", "events", "run_id = ?", "created_at ASC, id ASC"},
		{"policy_decisions", "policy_decisions", "run_id = ?", "created_at ASC, id ASC"},
		{"risk_signals", "risk_signals", "run_id = ?", "created_at ASC, id ASC"},
		// Unified signal model (security/cost/quality/behavior) — without it the
		// replay has no Signals & Risk and verify flags missing_policy_unified_signal.
		{"signals", "signals", "run_id = ?", "created_at ASC, id ASC"},
		{"response_actions", "response_actions", "run_id = ?", "created_at ASC, id ASC"},
		{"external_effects", "external_effects", "run_id = ?", "created_at ASC, id ASC"},
		{"evidence_events", "evidence_events", "run_id = ?", "created_at ASC, id ASC"},
		{"graph_edges", "graph_edges", "run_id = ?", "created_at ASC, id ASC"},
		{"cost_samples", "cost_samples", "run_id = ?", "created_at ASC, id ASC"},
		{"provenance_objects", "provenance_objects", "run_id = ?", "object_type ASC, created_at ASC, hash ASC"},
	}
	bundle := map[string]any{
		"schema_version":    "agentprovenance.forensics_bundle/v1",
		"run_id":            runID,
		"exported_at":       time.Now().UTC().Format(time.RFC3339Nano),
		"evidence_manifest": evidenceManifest,
		"telemetry_batches": telemetryBatchSummaries(batches),
	}
	for _, spec := range specs {
		// The run id is bound once per "?" placeholder in the WHERE clause.
		args := make([]any, strings.Count(spec.where, "?"))
		for i := range args {
			args[i] = runID
		}
		rows, err := selectRows(s.DB, "SELECT * FROM "+spec.table+" WHERE "+spec.where+" ORDER BY "+spec.order, args...)
		if err != nil {
			return BundleInfo{}, fmt.Errorf("dump %s: %w", spec.table, err)
		}
		bundle[spec.key] = rows
	}
	// Backstop redaction: mask secrets in every event payload before the bundle
	// is hashed and signed. Capture-time redaction (telemetry ingest, object
	// materialize) is the primary defense; this guarantees no bundle ever ships
	// a plaintext credential regardless of which writer might have missed it —
	// the export is the one sink that leaves the host and gets committed/shared.
	// Object blob content is redacted at materialize time instead (it is
	// content-addressed, so masking here would break its hash on import).
	redactBundleEventPayloads(bundle["events"])

	// Embed artifact content inline so the bundle is self-contained AND the DSSE
	// signature covers it (tampering a captured artifact then breaks the signature).
	// Content over maxInlineContentBytes is NOT embedded — it is recorded in
	// "omitted_content" (hash/size/reason) so the gap is explicit, never silent,
	// and the bundle stays small for large real captures. The provenance row + hash
	// always travel, so the graph and integrity checks are unaffected.
	var omitted []map[string]any
	objectBlobs, omittedObj, err := embedObjectBlobs(bundle["provenance_objects"])
	if err != nil {
		return BundleInfo{}, err
	}
	snapshotFiles, omittedSnap, err := embedSnapshotFiles(bundle["snapshots"])
	if err != nil {
		return BundleInfo{}, err
	}
	omitted = append(omitted, omittedObj...)
	omitted = append(omitted, omittedSnap...)
	bundle["object_blobs"] = objectBlobs
	bundle["snapshot_files"] = snapshotFiles
	bundle["omitted_content"] = omitted
	raw, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return BundleInfo{}, err
	}
	bundleID := ids.New("forensics")
	path := filepath.Join(s.Paths.Artifacts, bundleID+".json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return BundleInfo{}, err
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`INSERT INTO forensics_bundles (id, run_id, path, sha256, size_bytes, status, created_at)
		VALUES (?, ?, ?, ?, ?, 'ready', ?)`, bundleID, runID, path, hash, len(raw), now)
	if err != nil {
		return BundleInfo{}, err
	}
	info := BundleInfo{SchemaVersion: "agentprovenance.forensics_export/v1", ID: bundleID, RunID: runID, Path: path, SHA256: hash, SizeBytes: int64(len(raw)), Status: "ready", CreatedAt: now}

	// Capture-time attestation: sign an in-toto statement over the bundle digest
	// so a defender can detect post-compromise rewrites of the stored bundle.
	if s.SignKey != nil {
		stmt := attest.NewStatement("forensics/"+runID, hash, map[string]any{
			"run_id":         runID,
			"bundle_id":      bundleID,
			"kind":           "forensics_bundle",
			"schema_version": info.SchemaVersion,
			"created_at":     now,
		})
		env, err := attest.Sign(stmt, s.SignKey, s.SignKeyID)
		if err != nil {
			return BundleInfo{}, fmt.Errorf("sign bundle: %w", err)
		}
		envRaw, err := json.MarshalIndent(env, "", "  ")
		if err != nil {
			return BundleInfo{}, err
		}
		attPath := filepath.Join(s.Paths.Artifacts, bundleID+".dsse.json")
		if err := os.WriteFile(attPath, envRaw, 0o644); err != nil {
			return BundleInfo{}, err
		}
		info.Signed = true
		info.AttestationPath = attPath
	}
	return info, nil
}

// VerifyBundleAttestation re-reads the bundle and its DSSE attestation and
// confirms the signature covers the current bundle bytes. It returns an error if
// the attestation is missing, the signature is invalid for pub, or the bundle on
// disk no longer matches the signed digest (i.e. it was tampered after signing).
func VerifyBundleAttestation(bundlePath, attestationPath string, pub ed25519.PublicKey) error {
	bundleRaw, err := readBundleBytes(bundlePath)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	return VerifyBundleAttestationBytes(bundleRaw, attestationPath, pub)
}

func VerifyBundleAttestationBytes(bundleRaw []byte, attestationPath string, pub ed25519.PublicKey) error {
	envRaw, err := os.ReadFile(attestationPath)
	if err != nil {
		return fmt.Errorf("read attestation: %w", err)
	}
	var env attest.Envelope
	if err := json.Unmarshal(envRaw, &env); err != nil {
		return fmt.Errorf("decode attestation: %w", err)
	}
	stmt, err := attest.Verify(env, pub)
	if err != nil {
		return err
	}
	want := attest.DigestSHA256(bundleRaw)
	if len(stmt.Subject) == 0 || stmt.Subject[0].Digest["sha256"] != want {
		return fmt.Errorf("bundle digest mismatch: signed=%q actual=%q (bundle tampered after signing)", stmtDigest(stmt), want)
	}
	return nil
}

func stmtDigest(s attest.Statement) string {
	if len(s.Subject) == 0 {
		return ""
	}
	return s.Subject[0].Digest["sha256"]
}

// maxInlineContentBytes caps how large a single artifact/snapshot file may be to
// travel inline in the bundle. Captured demo artifacts are well under this; the
// cap only matters for very large real captures, where oversized content is
// recorded in omitted_content rather than bloating a single in-memory JSON file.
const maxInlineContentBytes = 4 << 20 // 4 MiB

// embedObjectBlobs reads each content-addressed provenance object blob and returns
// the inline-embeddable ones plus an explicit list of any omitted for size.
func embedObjectBlobs(rows any) (blobs []map[string]any, omitted []map[string]any, err error) {
	list, _ := rows.([]map[string]any)
	blobs = []map[string]any{}
	for _, r := range list {
		hash, _ := r["hash"].(string)
		path, _ := r["path"].(string)
		if hash == "" || path == "" {
			continue
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, nil, fmt.Errorf("read object blob %s: %w", hash, readErr)
		}
		if len(content) > maxInlineContentBytes {
			omitted = append(omitted, map[string]any{
				"kind": "object", "ref": hash, "size_bytes": len(content),
				"reason": fmt.Sprintf("exceeds inline cap (%d bytes)", maxInlineContentBytes),
			})
			continue
		}
		blobs = append(blobs, map[string]any{
			"hash":        hash,
			"content_b64": base64.StdEncoding.EncodeToString(content),
		})
	}
	return blobs, omitted, nil
}

// embedSnapshotFiles walks each snapshot directory and returns its files inline,
// recording any oversized file as omitted rather than silently dropping it.
func embedSnapshotFiles(rows any) (files []map[string]any, omitted []map[string]any, err error) {
	list, _ := rows.([]map[string]any)
	files = []map[string]any{}
	for _, r := range list {
		id, _ := r["id"].(string)
		dir, _ := r["path"].(string)
		if id == "" || dir == "" {
			continue
		}
		info, statErr := os.Stat(dir)
		if statErr != nil {
			// Snapshot artifact not present on this machine; the snapshot row still
			// travels, so the gap is documented, not silent.
			omitted = append(omitted, map[string]any{"kind": "snapshot", "ref": id, "reason": "snapshot path not present at export"})
			continue
		}
		walkRoot := dir
		if !info.IsDir() {
			walkRoot = filepath.Dir(dir)
		}
		walkErr := filepath.WalkDir(dir, func(p string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.IsDir() {
				return nil
			}
			fi, e := d.Info()
			if e != nil {
				return e
			}
			rel, e := filepath.Rel(walkRoot, p)
			if e != nil {
				return e
			}
			if fi.Size() > maxInlineContentBytes {
				omitted = append(omitted, map[string]any{
					"kind": "snapshot_file", "ref": id, "name": rel, "size_bytes": fi.Size(),
					"reason": fmt.Sprintf("exceeds inline cap (%d bytes)", maxInlineContentBytes),
				})
				return nil
			}
			content, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			files = append(files, map[string]any{
				"snapshot_id": id,
				"name":        rel,
				"content_b64": base64.StdEncoding.EncodeToString(content),
			})
			return nil
		})
		if walkErr != nil {
			return nil, nil, fmt.Errorf("walk snapshot %s: %w", id, walkErr)
		}
	}
	return files, omitted, nil
}

func telemetryBatchSummaries(batches []telemetry.BatchRecord) []map[string]any {
	out := make([]map[string]any, 0, len(batches))
	for _, batch := range batches {
		out = append(out, map[string]any{
			"id":                batch.ID,
			"run_id":            batch.RunID,
			"format":            batch.Format,
			"path":              batch.Path,
			"file_sha256":       batch.FileSHA256,
			"read":              batch.Read,
			"ingested":          batch.Ingested,
			"skipped":           batch.Skipped,
			"failed":            batch.Failed,
			"event_ids_sha256":  batch.EventIDsSHA256,
			"created_at":        batch.CreatedAt,
			"source_query_hint": "telemetry batches --run " + batch.RunID,
		})
	}
	return out
}

func selectRows(db *sql.DB, query string, args ...any) ([]map[string]any, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	result := []map[string]any{}
	for rows.Next() {
		values := make([]any, len(columns))
		valuePtrs := make([]any, len(columns))
		for i := range columns {
			valuePtrs[i] = &values[i]
		}
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}
		item := map[string]any{}
		for i, column := range columns {
			switch v := values[i].(type) {
			case []byte:
				item[column] = string(v)
			default:
				item[column] = v
			}
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

// redactBundleEventPayloads masks secrets in the `payload` column of every
// dumped event row, in place, before the bundle is hashed and signed.
func redactBundleEventPayloads(rows any) {
	list, ok := rows.([]map[string]any)
	if !ok {
		return
	}
	for _, row := range list {
		if p, ok := row["payload"].(string); ok && p != "" {
			row["payload"] = redact.RedactString(p)
		}
	}
}
