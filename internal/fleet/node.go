package fleet

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/ids"
)

type Node struct {
	ID            string
	Address       string
	Runtime       string
	Labels        string
	CPUCapacity   float64
	MemoryMB      int64
	ActiveCPUDebt float64
	WarmHitCount  int64
	Status        string
	CreatedAt     string
	UpdatedAt     string
}

func Register(db *sql.DB, address, runtime, labels string, cpu float64, memoryMB int64) (Node, error) {
	if address == "" {
		return Node{}, fmt.Errorf("address is required")
	}
	if runtime == "" {
		runtime = "docker"
	}
	if cpu == 0 {
		cpu = 1
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	node := Node{
		ID:          ids.New("node"),
		Address:     address,
		Runtime:     runtime,
		Labels:      labels,
		CPUCapacity: cpu,
		MemoryMB:    memoryMB,
		Status:      "healthy",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	_, err := db.Exec(`INSERT INTO nodes (id, address, runtime, labels, cpu_capacity, memory_mb, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, node.ID, node.Address, node.Runtime, node.Labels, node.CPUCapacity, node.MemoryMB, node.Status, node.CreatedAt, node.UpdatedAt)
	return node, err
}

func Heartbeat(db *sql.DB, nodeID string, activeCPUDebt float64, warmHits int64) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := db.Exec(`UPDATE nodes SET active_cpu_debt = ?, warm_hit_count = warm_hit_count + ?, status = 'healthy', updated_at = ? WHERE id = ?`, activeCPUDebt, warmHits, now, nodeID)
	return err
}

func List(db *sql.DB) ([]Node, error) {
	rows, err := db.Query(`SELECT id, address, runtime, labels, cpu_capacity, memory_mb, active_cpu_debt, warm_hit_count, status, created_at, updated_at
		FROM nodes ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nodes := []Node{}
	for rows.Next() {
		var node Node
		if err := rows.Scan(&node.ID, &node.Address, &node.Runtime, &node.Labels, &node.CPUCapacity, &node.MemoryMB, &node.ActiveCPUDebt, &node.WarmHitCount, &node.Status, &node.CreatedAt, &node.UpdatedAt); err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	return nodes, rows.Err()
}

func Inspect(db *sql.DB, nodeID string) (Node, error) {
	var node Node
	err := db.QueryRow(`SELECT id, address, runtime, labels, cpu_capacity, memory_mb, active_cpu_debt, warm_hit_count, status, created_at, updated_at
		FROM nodes WHERE id = ?`, nodeID).
		Scan(&node.ID, &node.Address, &node.Runtime, &node.Labels, &node.CPUCapacity, &node.MemoryMB, &node.ActiveCPUDebt, &node.WarmHitCount, &node.Status, &node.CreatedAt, &node.UpdatedAt)
	return node, err
}
