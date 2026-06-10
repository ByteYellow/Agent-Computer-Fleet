package security

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/ids"
	"gopkg.in/yaml.v3"
)

type Event struct {
	Source     string   `json:"source"`
	EventType  string   `json:"event_type"`
	RunID      string   `json:"run_id"`
	SessionID  string   `json:"session_id"`
	ToolCallID string   `json:"tool_call_id"`
	ProcessID  string   `json:"process_id"`
	SnapshotID string   `json:"snapshot_id"`
	DstIP      string   `json:"dst_ip"`
	Path       string   `json:"path"`
	Args       []string `json:"args"`
}

type Decision struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	RuleID   string `json:"rule_id,omitempty"`
}

type DecisionRecord struct {
	ID        string
	EventID   string
	RunID     string
	SessionID string
	RuleID    string
	Decision  string
	Reason    string
	CreatedAt string
}

type Engine struct {
	SecretPathPatterns []string
	Rules              []Rule
}

func DefaultEngine() Engine {
	return Engine{SecretPathPatterns: []string{".env", "id_rsa", "secret", "credentials"}, Rules: DefaultRules()}
}

type Rule struct {
	ID       string    `yaml:"id"`
	Match    RuleMatch `yaml:"match"`
	Decision string    `yaml:"decision"`
	Reason   string    `yaml:"reason"`
}

type RuleMatch struct {
	Source       string   `yaml:"source"`
	EventType    string   `yaml:"event_type"`
	DstIP        string   `yaml:"dst_ip"`
	PrivateCIDR  bool     `yaml:"private_cidr"`
	PathContains []string `yaml:"path_contains"`
	ArgsContains []string `yaml:"args_contains"`
}

type RuleFile struct {
	Rules []Rule `yaml:"rules"`
}

func DefaultRules() []Rule {
	return []Rule{
		{
			ID:       "metadata_ip_dst",
			Match:    RuleMatch{DstIP: "169.254.169.254"},
			Decision: "quarantine",
			Reason:   "metadata IP access",
		},
		{
			ID:       "metadata_ip_args",
			Match:    RuleMatch{ArgsContains: []string{"169.254.169.254"}},
			Decision: "quarantine",
			Reason:   "metadata IP access",
		},
		{
			ID:       "private_cidr_access",
			Match:    RuleMatch{PrivateCIDR: true},
			Decision: "deny",
			Reason:   "private CIDR access",
		},
		{
			ID:       "secret_path_access",
			Match:    RuleMatch{PathContains: []string{".env", "id_rsa", "secret", "credentials"}},
			Decision: "kill",
			Reason:   "secret path access",
		},
	}
}

func LoadEngine(path string) (Engine, error) {
	if path == "" {
		return DefaultEngine(), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Engine{}, err
	}
	var file RuleFile
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return Engine{}, err
	}
	engine := Engine{Rules: file.Rules}
	if len(engine.Rules) == 0 {
		return Engine{}, fmt.Errorf("policy rule file has no rules")
	}
	return engine, nil
}

func (e Engine) Evaluate(event Event) Decision {
	if len(e.Rules) > 0 {
		for _, rule := range e.Rules {
			if rule.Matches(event) {
				reason := rule.Reason
				if reason == "" {
					reason = rule.ID
				}
				return Decision{Decision: rule.Decision, Reason: reason, RuleID: rule.ID}
			}
		}
	}
	return Decision{Decision: "allow", Reason: "no policy matched"}
}

func (r Rule) Matches(event Event) bool {
	if r.Match.Source != "" && r.Match.Source != event.Source {
		return false
	}
	if r.Match.EventType != "" && r.Match.EventType != event.EventType {
		return false
	}
	if r.Match.DstIP != "" && event.DstIP != r.Match.DstIP && !strings.Contains(strings.Join(event.Args, " "), r.Match.DstIP) {
		return false
	}
	if r.Match.PrivateCIDR && !isPrivateIP(event.DstIP) {
		return false
	}
	for _, pattern := range r.Match.PathContains {
		if pattern != "" && strings.Contains(event.Path, pattern) {
			return true
		}
	}
	if len(r.Match.PathContains) > 0 {
		return false
	}
	joinedArgs := strings.Join(event.Args, " ")
	for _, pattern := range r.Match.ArgsContains {
		if pattern != "" && strings.Contains(joinedArgs, pattern) {
			return true
		}
	}
	if len(r.Match.ArgsContains) > 0 {
		return false
	}
	return r.Match.Source != "" || r.Match.EventType != "" || r.Match.DstIP != "" || r.Match.PrivateCIDR
}

func EvaluateJSONL(path string, out io.Writer) error {
	return EvaluateJSONLWithEngine(nil, path, out, DefaultEngine())
}

func EvaluateJSONLWithState(db *sql.DB, path string, out io.Writer) error {
	return EvaluateJSONLWithEngine(db, path, out, DefaultEngine())
}

func EvaluateJSONLWithEngine(db *sql.DB, path string, out io.Writer, engine Engine) error {
	return evaluateJSONL(path, out, db, engine)
}

func EvaluateAndPersist(db *sql.DB, event Event, rawPayload string) (DecisionRecord, error) {
	decision := DefaultEngine().Evaluate(event)
	return persistDecision(db, event, rawPayload, decision)
}

func PersistDecision(db *sql.DB, event Event, rawPayload string, decision Decision) (DecisionRecord, error) {
	return persistDecision(db, event, rawPayload, decision)
}

func ListDecisions(db *sql.DB, runID string) ([]DecisionRecord, error) {
	query := `SELECT id, COALESCE(event_id, ''), COALESCE(run_id, ''), COALESCE(session_id, ''), COALESCE(rule_id, ''), decision, reason, created_at
		FROM policy_decisions`
	args := []any{}
	if runID != "" {
		query += ` WHERE run_id = ?`
		args = append(args, runID)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []DecisionRecord
	for rows.Next() {
		var record DecisionRecord
		if err := rows.Scan(&record.ID, &record.EventID, &record.RunID, &record.SessionID, &record.RuleID, &record.Decision, &record.Reason, &record.CreatedAt); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func evaluateJSONL(path string, out io.Writer, db *sql.DB, engine Engine) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return err
		}
		decision := engine.Evaluate(event)
		if db != nil {
			if _, err := persistDecision(db, event, line, decision); err != nil {
				return err
			}
		}
		row := map[string]any{"event": event, "rule_id": decision.RuleID, "decision": decision.Decision, "reason": decision.Reason}
		b, _ := json.Marshal(row)
		fmt.Fprintln(out, string(b))
	}
	return scanner.Err()
}

func persistDecision(db *sql.DB, event Event, rawPayload string, decision Decision) (DecisionRecord, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	eventID := ids.New("evt")
	_, err := db.Exec(`INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, snapshot_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, eventID, event.RunID, event.SessionID, event.ToolCallID, event.ProcessID, event.SnapshotID, event.Source, event.EventType, rawPayload, now)
	if err != nil {
		return DecisionRecord{}, err
	}
	record := DecisionRecord{
		ID:        ids.New("dec"),
		EventID:   eventID,
		RunID:     event.RunID,
		SessionID: event.SessionID,
		RuleID:    decision.RuleID,
		Decision:  decision.Decision,
		Reason:    decision.Reason,
		CreatedAt: now,
	}
	_, err = db.Exec(`INSERT INTO policy_decisions (id, event_id, run_id, session_id, rule_id, decision, reason, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, record.ID, eventID, event.RunID, event.SessionID, decision.RuleID, decision.Decision, decision.Reason, now)
	if err != nil {
		return DecisionRecord{}, err
	}
	blockCount := int64(0)
	quarantineCount := int64(0)
	if decision.Decision != "allow" {
		blockCount = 1
	}
	switch decision.Decision {
	case "quarantine":
		quarantineCount = 1
		if event.SessionID != "" {
			_, _ = db.Exec(`UPDATE sessions SET status = 'quarantined', updated_at = ? WHERE id = ?`, now, event.SessionID)
			_, _ = db.Exec(`UPDATE snapshots SET status = 'tainted' WHERE session_id = ?`, event.SessionID)
		}
	case "kill":
		if event.SessionID != "" {
			_, _ = db.Exec(`UPDATE sessions SET status = 'stopped', updated_at = ? WHERE id = ?`, now, event.SessionID)
			_, _ = db.Exec(`UPDATE snapshots SET status = 'tainted' WHERE session_id = ?`, event.SessionID)
		}
		if event.ProcessID != "" {
			_, _ = db.Exec(`UPDATE processes SET status = 'killed', ended_at = ? WHERE id = ?`, now, event.ProcessID)
		}
	}
	if event.RunID != "" {
		_, _ = db.Exec(`INSERT INTO cost_samples (id, run_id, session_id, policy_block_count, quarantine_count, created_at)
			VALUES (?, ?, ?, ?, ?, ?)`, ids.New("cost"), event.RunID, event.SessionID, blockCount, quarantineCount, now)
	}
	return record, nil
}

func isPrivateIP(raw string) bool {
	ip := net.ParseIP(raw)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback()
}
