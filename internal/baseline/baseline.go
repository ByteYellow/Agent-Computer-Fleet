package baseline

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/ids"
)

type Profile struct {
	ID                string
	TemplateName      string
	ExecCount         int64
	NetworkEventCount int64
	PolicyBlockCount  int64
	ActiveCPUSeconds  float64
	Status            string
	CreatedAt         string
}

func Learn(db *sql.DB, templateName, runID string) (Profile, error) {
	if templateName == "" || runID == "" {
		return Profile{}, fmt.Errorf("template and run are required")
	}
	var execCount, networkCount, blockCount int64
	var activeCPU float64
	_ = db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id = ? AND event_type IN ('exec_start', 'call')`, runID).Scan(&execCount)
	_ = db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id = ? AND event_type = 'network_connect'`, runID).Scan(&networkCount)
	_ = db.QueryRow(`SELECT COUNT(*) FROM policy_decisions WHERE run_id = ? AND decision != 'allow'`, runID).Scan(&blockCount)
	_ = db.QueryRow(`SELECT COALESCE(SUM(active_cpu_seconds), 0) FROM cost_samples WHERE run_id = ?`, runID).Scan(&activeCPU)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	profile := Profile{
		ID:                ids.New("base"),
		TemplateName:      templateName,
		ExecCount:         execCount,
		NetworkEventCount: networkCount,
		PolicyBlockCount:  blockCount,
		ActiveCPUSeconds:  activeCPU,
		Status:            "ready",
		CreatedAt:         now,
	}
	_, err := db.Exec(`INSERT INTO baseline_profiles (id, template_name, exec_count, network_event_count, policy_block_count, active_cpu_seconds, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, profile.ID, profile.TemplateName, profile.ExecCount, profile.NetworkEventCount, profile.PolicyBlockCount, profile.ActiveCPUSeconds, profile.Status, profile.CreatedAt)
	return profile, err
}

func Check(db *sql.DB, templateName, runID string) (string, []string, error) {
	profile, err := latestProfile(db, templateName)
	if err != nil {
		return "", nil, err
	}
	current, err := currentProfile(db, templateName, runID)
	if err != nil {
		return "", nil, err
	}
	var deviations []string
	if current.NetworkEventCount > profile.NetworkEventCount+2 {
		deviations = append(deviations, "network_event_count")
	}
	if current.PolicyBlockCount > profile.PolicyBlockCount {
		deviations = append(deviations, "policy_block_count")
	}
	if profile.ActiveCPUSeconds > 0 && current.ActiveCPUSeconds > profile.ActiveCPUSeconds*2 {
		deviations = append(deviations, "active_cpu_seconds")
	}
	if len(deviations) == 0 {
		return "normal", deviations, nil
	}
	return "anomalous", deviations, nil
}

func latestProfile(db *sql.DB, templateName string) (Profile, error) {
	var p Profile
	err := db.QueryRow(`SELECT id, template_name, exec_count, network_event_count, policy_block_count, active_cpu_seconds, status, created_at
		FROM baseline_profiles WHERE template_name = ? ORDER BY created_at DESC LIMIT 1`, templateName).
		Scan(&p.ID, &p.TemplateName, &p.ExecCount, &p.NetworkEventCount, &p.PolicyBlockCount, &p.ActiveCPUSeconds, &p.Status, &p.CreatedAt)
	return p, err
}

func currentProfile(db *sql.DB, templateName, runID string) (Profile, error) {
	p := Profile{TemplateName: templateName}
	_ = db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id = ? AND event_type IN ('exec_start', 'call')`, runID).Scan(&p.ExecCount)
	_ = db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id = ? AND event_type = 'network_connect'`, runID).Scan(&p.NetworkEventCount)
	_ = db.QueryRow(`SELECT COUNT(*) FROM policy_decisions WHERE run_id = ? AND decision != 'allow'`, runID).Scan(&p.PolicyBlockCount)
	_ = db.QueryRow(`SELECT COALESCE(SUM(active_cpu_seconds), 0) FROM cost_samples WHERE run_id = ?`, runID).Scan(&p.ActiveCPUSeconds)
	return p, nil
}
