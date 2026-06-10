package state

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/ids"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
)

type Service struct {
	DB    *sql.DB
	Paths store.Paths
}

type Manifest struct {
	Hash  string
	Files int64
	Bytes int64
}

type FileEntry struct {
	Path      string
	Hash      string
	SizeBytes int64
	Mode      string
}

type ForkResult struct {
	AttemptID     string
	WorkspacePath string
	ForkMS        int64
	Plan          string
}

type SnapshotPlan struct {
	SnapshotID string
	Plan       string
	Reason     string
	Score      float64
}

type SnapshotInfo struct {
	ID               string
	Name             string
	SessionID        string
	ParentID         string
	Kind             string
	Source           string
	Path             string
	ManifestHash     string
	FileCount        int64
	Bytes            int64
	SnapshotCreateMS int64
	Status           string
	CreatedAt        string
}

type StackResult struct {
	TemplateSnapshotID string
	ReadySnapshotID    string
	Attempt            ForkResult
}

func (s Service) CreateDirectorySnapshot(sessionID, workspacePath, name string) (string, Manifest, int64, error) {
	if workspacePath != "/workspace" {
		return "", Manifest{}, 0, fmt.Errorf("only /workspace directory snapshots are supported in MVP")
	}
	var src, runID string
	if err := s.DB.QueryRow(`SELECT workspace_host_path, run_id FROM sessions WHERE id = ?`, sessionID).Scan(&src, &runID); err != nil {
		return "", Manifest{}, 0, err
	}
	snapshotID := ids.New("snap")
	dst := filepath.Join(s.Paths.Snapshots, snapshotID)
	start := time.Now()
	if err := CopyDir(src, dst); err != nil {
		return "", Manifest{}, 0, err
	}
	snapshotCreateMS := time.Since(start).Milliseconds()
	manifest, err := BuildManifest(dst)
	if err != nil {
		return "", Manifest{}, 0, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	parentID, delta := s.latestSnapshotForSession(sessionID, dst)
	score := plannerScore(manifest.Bytes, false)
	_, err = s.DB.Exec(`INSERT INTO snapshots (id, name, session_id, parent_id, kind, source, path, manifest_hash, file_count, bytes, snapshot_create_ms, delta_parent_id, delta_files_added, delta_files_modified, delta_files_deleted, planner_score, status, created_at)
		VALUES (?, ?, ?, ?, 'ready', 'session', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ready', ?)`, snapshotID, name, sessionID, parentID, dst, manifest.Hash, manifest.Files, manifest.Bytes, snapshotCreateMS, parentID, delta.Added, delta.Modified, delta.Deleted, score, now)
	if err != nil {
		return "", Manifest{}, 0, err
	}
	_ = s.recordManifest(snapshotID, dst)
	if parentID != "" {
		_, _ = s.DB.Exec(`INSERT INTO snapshot_edges (id, parent_id, child_id, edge_type, plan, plan_reason, planner_score, created_at)
			VALUES (?, ?, ?, 'snapshot_delta', 'file_manifest_delta', ?, ?, ?)`, ids.New("edge"), parentID, snapshotID, fmt.Sprintf("added=%d modified=%d deleted=%d", delta.Added, delta.Modified, delta.Deleted), score, now)
	}
	_, _ = s.DB.Exec(`INSERT INTO cost_samples (id, run_id, session_id, snapshot_bytes, wall_seconds, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, ids.New("cost"), runID, sessionID, manifest.Bytes, float64(snapshotCreateMS)/1000, now)
	return snapshotID, manifest, snapshotCreateMS, nil
}

func (s Service) CreateStack(taskPath string) (StackResult, error) {
	templateID := ids.New("tmpl")
	templateDir := filepath.Join(s.Paths.Snapshots, templateID)
	if err := os.MkdirAll(templateDir, 0o755); err != nil {
		return StackResult{}, err
	}
	taskBytes, err := os.ReadFile(taskPath)
	if err != nil {
		return StackResult{}, err
	}
	if err := os.WriteFile(filepath.Join(templateDir, "task.yaml"), taskBytes, 0o644); err != nil {
		return StackResult{}, err
	}
	templateManifest, err := BuildManifest(templateDir)
	if err != nil {
		return StackResult{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`INSERT INTO snapshots (id, name, kind, source, path, manifest_hash, file_count, bytes, status, created_at)
		VALUES (?, 'template', 'template', ?, ?, ?, ?, ?, 'ready', ?)`, templateID, taskPath, templateDir, templateManifest.Hash, templateManifest.Files, templateManifest.Bytes, now)
	if err != nil {
		return StackResult{}, err
	}

	readyID := ids.New("snap")
	readyDir := filepath.Join(s.Paths.Snapshots, readyID)
	if err := CopyDir(templateDir, readyDir); err != nil {
		return StackResult{}, err
	}
	if err := os.WriteFile(filepath.Join(readyDir, "STACK_READY"), []byte("ready\n"), 0o644); err != nil {
		return StackResult{}, err
	}
	readyManifest, err := BuildManifest(readyDir)
	if err != nil {
		return StackResult{}, err
	}
	now = time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`INSERT INTO snapshots (id, name, parent_id, kind, source, path, manifest_hash, file_count, bytes, status, created_at)
		VALUES (?, 'ready', ?, 'ready', ?, ?, ?, ?, ?, 'ready', ?)`, readyID, templateID, "stack:"+taskPath, readyDir, readyManifest.Hash, readyManifest.Files, readyManifest.Bytes, now)
	if err != nil {
		return StackResult{}, err
	}
	attempts, err := s.Fork(readyID, 1)
	if err != nil {
		return StackResult{}, err
	}
	return StackResult{TemplateSnapshotID: templateID, ReadySnapshotID: readyID, Attempt: attempts[0]}, nil
}

func (s Service) CreateStackFromTemplate(templateNameOrID string) (StackResult, error) {
	var templateID, templateName, templatePath, manifestHash string
	var templateBytes int64
	err := s.DB.QueryRow(`SELECT id, name, task_path, manifest_hash, bytes FROM templates
		WHERE id = ? OR name = ? ORDER BY created_at DESC LIMIT 1`, templateNameOrID, templateNameOrID).
		Scan(&templateID, &templateName, &templatePath, &manifestHash, &templateBytes)
	if err != nil {
		return StackResult{}, err
	}
	templateDir := filepath.Join(s.Paths.Templates, templateID)
	manifest, err := BuildManifest(templateDir)
	if err != nil {
		return StackResult{}, err
	}
	if manifestHash == "" {
		manifestHash = manifest.Hash
	}
	if templateBytes == 0 {
		templateBytes = manifest.Bytes
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`INSERT OR IGNORE INTO snapshots (id, name, kind, source, path, manifest_hash, file_count, bytes, status, created_at)
		VALUES (?, ?, 'template', 'template_bundle', ?, ?, ?, ?, 'ready', ?)`,
		templateID, templateName, templateDir, manifestHash, manifest.Files, templateBytes, now)
	if err != nil {
		return StackResult{}, err
	}

	readyID := ids.New("snap")
	readyDir := filepath.Join(s.Paths.Snapshots, readyID)
	if err := CopyDir(templateDir, readyDir); err != nil {
		return StackResult{}, err
	}
	if err := os.WriteFile(filepath.Join(readyDir, "STACK_READY"), []byte("ready\n"), 0o644); err != nil {
		return StackResult{}, err
	}
	readyManifest, err := BuildManifest(readyDir)
	if err != nil {
		return StackResult{}, err
	}
	now = time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`INSERT INTO snapshots (id, name, parent_id, kind, source, path, manifest_hash, file_count, bytes, status, created_at)
		VALUES (?, 'ready', ?, 'ready', ?, ?, ?, ?, ?, 'ready', ?)`, readyID, templateID, "template:"+templatePath, readyDir, readyManifest.Hash, readyManifest.Files, readyManifest.Bytes, now)
	if err != nil {
		return StackResult{}, err
	}
	attempts, err := s.Fork(readyID, 1)
	if err != nil {
		return StackResult{}, err
	}
	return StackResult{TemplateSnapshotID: templateID, ReadySnapshotID: readyID, Attempt: attempts[0]}, nil
}

func (s Service) Fork(snapshotNameOrID string, count int) ([]ForkResult, error) {
	if count < 1 {
		return nil, fmt.Errorf("count must be >= 1")
	}
	var snapshotID, src string
	plan, err := s.Plan(snapshotNameOrID, false)
	if err != nil {
		return nil, err
	}
	snapshotID = plan.SnapshotID
	if err := s.DB.QueryRow(`SELECT path FROM snapshots WHERE id = ?`, snapshotID).Scan(&src); err != nil {
		return nil, err
	}
	results := make([]ForkResult, 0, count)
	for i := 0; i < count; i++ {
		attemptID := ids.New("attempt")
		dst := filepath.Join(s.Paths.Workspaces, attemptID)
		start := time.Now()
		if err := CopyDir(src, dst); err != nil {
			return results, err
		}
		forkMS := time.Since(start).Milliseconds()
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := s.DB.Exec(`INSERT INTO fork_attempts (id, snapshot_id, workspace_path, fork_ms, created_at)
			VALUES (?, ?, ?, ?, ?)`, attemptID, snapshotID, dst, forkMS, now); err != nil {
			return results, err
		}
		_, _ = s.DB.Exec(`INSERT INTO snapshot_edges (id, parent_id, child_id, edge_type, plan, plan_reason, planner_score, created_at)
			VALUES (?, ?, ?, 'fork', ?, ?, ?, ?)`, ids.New("edge"), snapshotID, attemptID, plan.Plan, plan.Reason, plan.Score, now)
		results = append(results, ForkResult{AttemptID: attemptID, WorkspacePath: dst, ForkMS: forkMS, Plan: plan.Plan})
	}
	return results, nil
}

type deltaCounts struct{ Added, Modified, Deleted int64 }

func (s Service) Plan(snapshotNameOrID string, rejectTainted bool) (SnapshotPlan, error) {
	rows, err := s.DB.Query(`SELECT id, bytes, COALESCE(tainted, 0), status, created_at FROM snapshots
		WHERE id = ? OR name = ? OR parent_id = ?
		ORDER BY created_at DESC`, snapshotNameOrID, snapshotNameOrID, snapshotNameOrID)
	if err != nil {
		return SnapshotPlan{}, err
	}
	defer rows.Close()
	var best SnapshotPlan
	found := false
	for rows.Next() {
		var id, status, createdAt string
		var bytes int64
		var tainted int
		if err := rows.Scan(&id, &bytes, &tainted, &status, &createdAt); err != nil {
			return SnapshotPlan{}, err
		}
		if rejectTainted && (tainted != 0 || status == "tainted") {
			continue
		}
		score := plannerScore(bytes, tainted != 0 || status == "tainted")
		if !found || score > best.Score {
			best = SnapshotPlan{SnapshotID: id, Plan: "copy", Reason: fmt.Sprintf("latest-local score=%.3f created_at=%s", score, createdAt), Score: score}
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		return SnapshotPlan{}, err
	}
	if !found {
		return SnapshotPlan{}, fmt.Errorf("no usable snapshot found for %s", snapshotNameOrID)
	}
	return best, nil
}

func (s Service) ListSnapshots() ([]SnapshotInfo, error) {
	rows, err := s.DB.Query(`SELECT id, COALESCE(name, ''), COALESCE(session_id, ''), COALESCE(parent_id, ''),
		kind, source, path, manifest_hash, file_count, bytes, snapshot_create_ms, status, created_at
		FROM snapshots ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var snapshots []SnapshotInfo
	for rows.Next() {
		var snapshot SnapshotInfo
		if err := rows.Scan(&snapshot.ID, &snapshot.Name, &snapshot.SessionID, &snapshot.ParentID, &snapshot.Kind, &snapshot.Source, &snapshot.Path, &snapshot.ManifestHash, &snapshot.FileCount, &snapshot.Bytes, &snapshot.SnapshotCreateMS, &snapshot.Status, &snapshot.CreatedAt); err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, rows.Err()
}

func (s Service) InspectSnapshot(snapshotNameOrID string) (SnapshotInfo, []SnapshotInfo, error) {
	var snapshot SnapshotInfo
	err := s.DB.QueryRow(`SELECT id, COALESCE(name, ''), COALESCE(session_id, ''), COALESCE(parent_id, ''),
		kind, source, path, manifest_hash, file_count, bytes, snapshot_create_ms, status, created_at
		FROM snapshots WHERE id = ? OR name = ? ORDER BY created_at DESC LIMIT 1`, snapshotNameOrID, snapshotNameOrID).Scan(&snapshot.ID, &snapshot.Name, &snapshot.SessionID, &snapshot.ParentID, &snapshot.Kind, &snapshot.Source, &snapshot.Path, &snapshot.ManifestHash, &snapshot.FileCount, &snapshot.Bytes, &snapshot.SnapshotCreateMS, &snapshot.Status, &snapshot.CreatedAt)
	if err != nil {
		return SnapshotInfo{}, nil, err
	}
	lineage := []SnapshotInfo{snapshot}
	parentID := snapshot.ParentID
	for strings.TrimSpace(parentID) != "" {
		var parent SnapshotInfo
		err := s.DB.QueryRow(`SELECT id, COALESCE(name, ''), COALESCE(session_id, ''), COALESCE(parent_id, ''),
			kind, source, path, manifest_hash, file_count, bytes, snapshot_create_ms, status, created_at
			FROM snapshots WHERE id = ?`, parentID).Scan(&parent.ID, &parent.Name, &parent.SessionID, &parent.ParentID, &parent.Kind, &parent.Source, &parent.Path, &parent.ManifestHash, &parent.FileCount, &parent.Bytes, &parent.SnapshotCreateMS, &parent.Status, &parent.CreatedAt)
		if err != nil {
			break
		}
		lineage = append(lineage, parent)
		parentID = parent.ParentID
	}
	return snapshot, lineage, nil
}

func (s Service) latestSnapshotForSession(sessionID, newRoot string) (string, deltaCounts) {
	var parentID string
	var parentPath string
	err := s.DB.QueryRow(`SELECT id, path FROM snapshots WHERE session_id = ? AND status IN ('ready', 'tainted') ORDER BY created_at DESC LIMIT 1`, sessionID).Scan(&parentID, &parentPath)
	if err != nil {
		return "", deltaCounts{}
	}
	delta, err := diffManifests(parentPath, newRoot)
	if err != nil {
		return parentID, deltaCounts{}
	}
	return parentID, delta
}

func (s Service) recordManifest(snapshotID, root string) error {
	entries, err := BuildFileManifest(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if _, err := s.DB.Exec(`INSERT OR REPLACE INTO snapshot_files (snapshot_id, path, sha256, size_bytes, mode) VALUES (?, ?, ?, ?, ?)`,
			snapshotID, entry.Path, entry.Hash, entry.SizeBytes, entry.Mode); err != nil {
			return err
		}
	}
	return nil
}

func diffManifests(oldRoot, newRoot string) (deltaCounts, error) {
	oldEntries, err := BuildFileManifest(oldRoot)
	if err != nil {
		return deltaCounts{}, err
	}
	newEntries, err := BuildFileManifest(newRoot)
	if err != nil {
		return deltaCounts{}, err
	}
	oldMap := map[string]FileEntry{}
	newMap := map[string]FileEntry{}
	for _, entry := range oldEntries {
		oldMap[entry.Path] = entry
	}
	for _, entry := range newEntries {
		newMap[entry.Path] = entry
	}
	var delta deltaCounts
	for path, newEntry := range newMap {
		oldEntry, ok := oldMap[path]
		if !ok {
			delta.Added++
			continue
		}
		if oldEntry.Hash != newEntry.Hash || oldEntry.SizeBytes != newEntry.SizeBytes {
			delta.Modified++
		}
	}
	for path := range oldMap {
		if _, ok := newMap[path]; !ok {
			delta.Deleted++
		}
	}
	return delta, nil
}

func plannerScore(bytes int64, tainted bool) float64 {
	score := 1000.0 - float64(bytes)/(1024*1024)
	if tainted {
		score -= 500
	}
	return score
}

func CopyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		return copyFile(path, target, info.Mode())
	})
}

func copyFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func BuildManifest(root string) (Manifest, error) {
	entries, err := BuildFileManifest(root)
	if err != nil {
		return Manifest{}, err
	}
	h := sha256.New()
	var files, bytes int64
	for _, entry := range entries {
		_, _ = h.Write([]byte(entry.Path))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(entry.Hash))
		files++
		bytes += entry.SizeBytes
	}
	return Manifest{Hash: hex.EncodeToString(h.Sum(nil)), Files: files, Bytes: bytes}, nil
}

func BuildFileManifest(root string) ([]FileEntry, error) {
	var entries []FileEntry
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		fh := sha256.New()
		n, copyErr := io.Copy(fh, f)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		entries = append(entries, FileEntry{Path: rel, Hash: hex.EncodeToString(fh.Sum(nil)), SizeBytes: n, Mode: info.Mode().String()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}
