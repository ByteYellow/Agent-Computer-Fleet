package warm

import (
	"database/sql"
	"fmt"
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

type Item struct {
	ID             string
	TemplateName   string
	SessionID      string
	WorkspacePath  string
	Frequency      int64
	ColdStartP95MS int64
	SizeScore      float64
	Priority       float64
	Status         string
	CreatedAt      string
	UpdatedAt      string
}

func (s Service) Create(templateName string, size int) ([]Item, error) {
	if templateName == "" {
		return nil, fmt.Errorf("template is required")
	}
	if size < 1 {
		size = 1
	}
	items := make([]Item, 0, size)
	for i := 0; i < size; i++ {
		id := ids.New("pool")
		workspace := filepath.Join(s.Paths.Workspaces, id)
		if err := os.MkdirAll(workspace, 0o755); err != nil {
			return items, err
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		item := Item{
			ID:             id,
			TemplateName:   templateName,
			WorkspacePath:  workspace,
			Frequency:      1,
			ColdStartP95MS: 0,
			SizeScore:      1,
			Priority:       greedyDualPriority(1, 0, 1),
			Status:         "warm",
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		_, err := s.DB.Exec(`INSERT INTO warm_pool_items (id, template_name, workspace_path, frequency, cold_start_p95_ms, size_score, priority, status, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, item.ID, item.TemplateName, item.WorkspacePath, item.Frequency, item.ColdStartP95MS, item.SizeScore, item.Priority, item.Status, item.CreatedAt, item.UpdatedAt)
		if err != nil {
			return items, err
		}
		items = append(items, item)
	}
	return items, nil
}

func (s Service) Status() ([]Item, error) {
	rows, err := s.DB.Query(`SELECT id, template_name, COALESCE(session_id, ''), COALESCE(workspace_path, ''), frequency, cold_start_p95_ms, size_score, priority, status, created_at, updated_at
		FROM warm_pool_items ORDER BY priority DESC, updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Item{}
	for rows.Next() {
		var item Item
		if err := rows.Scan(&item.ID, &item.TemplateName, &item.SessionID, &item.WorkspacePath, &item.Frequency, &item.ColdStartP95MS, &item.SizeScore, &item.Priority, &item.Status, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func greedyDualPriority(frequency, coldStartP95MS int64, sizeScore float64) float64 {
	if sizeScore <= 0 {
		sizeScore = 1
	}
	return (float64(frequency) + float64(coldStartP95MS)/1000.0) / sizeScore
}
