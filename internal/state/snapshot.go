package state

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

type ForkResult struct {
	AttemptID     string
	WorkspacePath string
	ForkMS        int64
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
	_, err = s.DB.Exec(`INSERT INTO snapshots (id, name, session_id, path, manifest_hash, file_count, bytes, snapshot_create_ms, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ready', ?)`, snapshotID, name, sessionID, dst, manifest.Hash, manifest.Files, manifest.Bytes, snapshotCreateMS, now)
	if err != nil {
		return "", Manifest{}, 0, err
	}
	_, _ = s.DB.Exec(`INSERT INTO cost_samples (id, run_id, session_id, snapshot_bytes, wall_seconds, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, ids.New("cost"), runID, sessionID, manifest.Bytes, float64(snapshotCreateMS)/1000, now)
	return snapshotID, manifest, snapshotCreateMS, nil
}

func (s Service) Fork(snapshotNameOrID string, count int) ([]ForkResult, error) {
	if count < 1 {
		return nil, fmt.Errorf("count must be >= 1")
	}
	var snapshotID, src string
	err := s.DB.QueryRow(`SELECT id, path FROM snapshots WHERE id = ? OR name = ? ORDER BY created_at DESC LIMIT 1`, snapshotNameOrID, snapshotNameOrID).Scan(&snapshotID, &src)
	if err != nil {
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
		results = append(results, ForkResult{AttemptID: attemptID, WorkspacePath: dst, ForkMS: forkMS})
	}
	return results, nil
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
	h := sha256.New()
	var files, bytes int64
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
		_, _ = h.Write([]byte(rel))
		_, _ = h.Write([]byte{0})
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		n, copyErr := io.Copy(h, f)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		files++
		bytes += n
		return nil
	})
	if err != nil {
		return Manifest{}, err
	}
	return Manifest{Hash: hex.EncodeToString(h.Sum(nil)), Files: files, Bytes: bytes}, nil
}
