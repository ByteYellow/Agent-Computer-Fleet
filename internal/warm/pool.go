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
	ID               string
	TemplateName     string
	SessionID        string
	WorkspacePath    string
	Frequency        int64
	ColdStartP95MS   int64
	SizeScore        float64
	Priority         float64
	HitCount         int64
	LastHitAt        string
	ColdStartSavedMS int64
	MemoryMB         int64
	DiskBytes        int64
	EvictionReason   string
	Status           string
	CreatedAt        string
	UpdatedAt        string
}

func (s Service) Create(templateName string, size int) ([]Item, error) {
	return s.CreateFromSeed(templateName, size, "")
}

func (s Service) CreateFromSeed(templateName string, size int, seedWorkspace string) ([]Item, error) {
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
		if seedWorkspace != "" {
			if err := copyDir(seedWorkspace, workspace); err != nil {
				return items, err
			}
		}
		diskBytes := dirBytes(workspace)
		now := time.Now().UTC().Format(time.RFC3339Nano)
		item := Item{
			ID:             id,
			TemplateName:   templateName,
			WorkspacePath:  workspace,
			Frequency:      1,
			ColdStartP95MS: 0,
			SizeScore:      1,
			DiskBytes:      diskBytes,
			Priority:       greedyDualPriority(1, 0, 1, 0, diskBytes, false),
			Status:         "ready",
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		_, err := s.DB.Exec(`INSERT INTO warm_pool_items (id, template_name, workspace_path, frequency, cold_start_p95_ms, size_score, priority, disk_bytes, status, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, item.ID, item.TemplateName, item.WorkspacePath, item.Frequency, item.ColdStartP95MS, item.SizeScore, item.Priority, item.DiskBytes, item.Status, item.CreatedAt, item.UpdatedAt)
		if err != nil {
			return items, err
		}
		items = append(items, item)
	}
	return items, nil
}

func (s Service) Status() ([]Item, error) {
	rows, err := s.DB.Query(`SELECT id, template_name, COALESCE(session_id, ''), COALESCE(workspace_path, ''), frequency, cold_start_p95_ms, size_score, priority, hit_count, COALESCE(last_hit_at, ''), cold_start_saved_ms, memory_mb, disk_bytes, COALESCE(eviction_reason, ''), status, created_at, updated_at
		FROM warm_pool_items ORDER BY priority DESC, updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Item{}
	for rows.Next() {
		var item Item
		if err := rows.Scan(&item.ID, &item.TemplateName, &item.SessionID, &item.WorkspacePath, &item.Frequency, &item.ColdStartP95MS, &item.SizeScore, &item.Priority, &item.HitCount, &item.LastHitAt, &item.ColdStartSavedMS, &item.MemoryMB, &item.DiskBytes, &item.EvictionReason, &item.Status, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s Service) Hit(templateName, sessionID string, coldStartSavedMS, memoryMB int64) (Item, bool, error) {
	var item Item
	err := s.DB.QueryRow(`SELECT id, template_name, COALESCE(session_id, ''), COALESCE(workspace_path, ''), frequency, cold_start_p95_ms, size_score, priority, hit_count, COALESCE(last_hit_at, ''), cold_start_saved_ms, memory_mb, disk_bytes, COALESCE(eviction_reason, ''), status, created_at, updated_at
		FROM warm_pool_items WHERE template_name = ? AND status IN ('ready', 'warm') ORDER BY priority DESC, updated_at DESC LIMIT 1`, templateName).
		Scan(&item.ID, &item.TemplateName, &item.SessionID, &item.WorkspacePath, &item.Frequency, &item.ColdStartP95MS, &item.SizeScore, &item.Priority, &item.HitCount, &item.LastHitAt, &item.ColdStartSavedMS, &item.MemoryMB, &item.DiskBytes, &item.EvictionReason, &item.Status, &item.CreatedAt, &item.UpdatedAt)
	if err == sql.ErrNoRows {
		return Item{}, false, nil
	}
	if err != nil {
		return Item{}, false, err
	}
	item.HitCount++
	item.Frequency++
	item.ColdStartSavedMS += coldStartSavedMS
	item.MemoryMB = memoryMB
	item.LastHitAt = time.Now().UTC().Format(time.RFC3339Nano)
	item.Status = "assigned"
	item.SessionID = sessionID
	item.DiskBytes = dirBytes(item.WorkspacePath)
	item.Priority = greedyDualPriority(item.Frequency, item.ColdStartP95MS, item.SizeScore, item.ColdStartSavedMS, item.DiskBytes, false)
	_, err = s.DB.Exec(`UPDATE warm_pool_items SET session_id = ?, frequency = ?, hit_count = ?, last_hit_at = ?, cold_start_saved_ms = ?, memory_mb = ?, disk_bytes = ?, priority = ?, status = 'assigned', updated_at = ? WHERE id = ?`,
		sessionID, item.Frequency, item.HitCount, item.LastHitAt, item.ColdStartSavedMS, item.MemoryMB, item.DiskBytes, item.Priority, item.LastHitAt, item.ID)
	return item, true, err
}

func (s Service) EvictIfOverLimit(templateName string, maxItems int) (Item, bool, error) {
	if maxItems <= 0 {
		return Item{}, false, nil
	}
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM warm_pool_items WHERE template_name = ? AND status IN ('ready', 'warm')`, templateName).Scan(&count); err != nil {
		return Item{}, false, err
	}
	if count <= maxItems {
		return Item{}, false, nil
	}
	var item Item
	err := s.DB.QueryRow(`SELECT id, template_name, COALESCE(workspace_path, ''), priority FROM warm_pool_items WHERE template_name = ? AND status IN ('ready', 'warm') ORDER BY priority ASC, updated_at ASC LIMIT 1`, templateName).
		Scan(&item.ID, &item.TemplateName, &item.WorkspacePath, &item.Priority)
	if err != nil {
		return Item{}, false, err
	}
	item.EvictionReason = "gdsf_lowest_priority"
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`UPDATE warm_pool_items SET status = 'evicted', eviction_reason = ?, updated_at = ? WHERE id = ?`, item.EvictionReason, now, item.ID)
	return item, true, err
}

func greedyDualPriority(frequency, coldStartP95MS int64, sizeScore float64, coldStartSavedMS, diskBytes int64, tainted bool) float64 {
	if sizeScore <= 0 {
		sizeScore = 1
	}
	sizeCost := sizeScore + float64(diskBytes)/(1024*1024*64)
	priority := (float64(frequency) + float64(coldStartP95MS+coldStartSavedMS)/1000.0) / sizeCost
	if tainted {
		priority -= 100
	}
	return priority
}

func dirBytes(path string) int64 {
	var total int64
	_ = filepath.WalkDir(path, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	})
}
