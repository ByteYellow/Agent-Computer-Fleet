package envtemplate

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/control"
	"github.com/byteyellow/agent-computer-fleet/internal/ids"
	"github.com/byteyellow/agent-computer-fleet/internal/state"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
)

type Service struct {
	DB    *sql.DB
	Paths store.Paths
}

type Info struct {
	ID           string
	Name         string
	TaskPath     string
	Image        string
	RiskTier     string
	NetworkMode  string
	ManifestHash string
	Bytes        int64
	Status       string
	CreatedAt    string
}

func (s Service) Build(taskPath, name string) (Info, error) {
	task, raw, err := control.LoadTask(taskPath)
	if err != nil {
		return Info{}, err
	}
	if task.Image == "" {
		return Info{}, fmt.Errorf("task image is required")
	}
	if name == "" {
		name = filepath.Base(taskPath)
	}
	absTaskPath, err := filepath.Abs(taskPath)
	if err != nil {
		return Info{}, err
	}
	templateID := ids.New("tmpl")
	templateDir := filepath.Join(s.Paths.Templates, templateID)
	if err := os.MkdirAll(templateDir, 0o755); err != nil {
		return Info{}, err
	}
	if err := os.WriteFile(filepath.Join(templateDir, "task.yaml"), raw, 0o644); err != nil {
		return Info{}, err
	}
	manifest, err := state.BuildManifest(templateDir)
	if err != nil {
		return Info{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`INSERT INTO templates (id, name, task_path, image, risk_tier, network_mode, manifest_hash, bytes, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ready', ?)`, templateID, name, absTaskPath, task.Image, task.RiskTier, task.NetworkMode, manifest.Hash, manifest.Bytes, now)
	if err != nil {
		return Info{}, err
	}
	return Info{
		ID:           templateID,
		Name:         name,
		TaskPath:     absTaskPath,
		Image:        task.Image,
		RiskTier:     task.RiskTier,
		NetworkMode:  task.NetworkMode,
		ManifestHash: manifest.Hash,
		Bytes:        manifest.Bytes,
		Status:       "ready",
		CreatedAt:    now,
	}, nil
}

func (s Service) List() ([]Info, error) {
	rows, err := s.DB.Query(`SELECT id, name, task_path, image, risk_tier, network_mode, manifest_hash, bytes, status, created_at
		FROM templates ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var templates []Info
	for rows.Next() {
		var info Info
		if err := rows.Scan(&info.ID, &info.Name, &info.TaskPath, &info.Image, &info.RiskTier, &info.NetworkMode, &info.ManifestHash, &info.Bytes, &info.Status, &info.CreatedAt); err != nil {
			return nil, err
		}
		templates = append(templates, info)
	}
	return templates, rows.Err()
}

func (s Service) Inspect(nameOrID string) (Info, control.Task, error) {
	var info Info
	err := s.DB.QueryRow(`SELECT id, name, task_path, image, risk_tier, network_mode, manifest_hash, bytes, status, created_at
		FROM templates WHERE id = ? OR name = ? ORDER BY created_at DESC LIMIT 1`, nameOrID, nameOrID).
		Scan(&info.ID, &info.Name, &info.TaskPath, &info.Image, &info.RiskTier, &info.NetworkMode, &info.ManifestHash, &info.Bytes, &info.Status, &info.CreatedAt)
	if err != nil {
		return Info{}, control.Task{}, err
	}
	task, _, err := control.LoadTask(info.TaskPath)
	if err != nil {
		return Info{}, control.Task{}, err
	}
	return info, task, nil
}
