package egress

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/byteyellow/agent-computer-fleet/internal/security"
)

func Check(db *sql.DB, runID, sessionID, dstIP, host string) (security.DecisionRecord, error) {
	payload := map[string]any{"dst_ip": dstIP, "host": host}
	raw, _ := json.Marshal(payload)
	return security.EvaluateAndPersist(db, security.Event{
		Source:    "egress_proxy",
		EventType: "network_connect",
		RunID:     runID,
		SessionID: sessionID,
		DstIP:     dstIP,
		Args:      []string{host},
	}, string(raw))
}

func InjectCredential(db *sql.DB, runID, sessionID, name, host string) error {
	if name == "" || host == "" {
		return fmt.Errorf("credential name and host are required")
	}
	payload, _ := json.Marshal(map[string]any{
		"credential_name": name,
		"host":            host,
		"injection":       "proxy_header",
		"raw_secret":      "redacted",
	})
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := db.Exec(`INSERT INTO events (id, run_id, session_id, source, event_type, payload, created_at)
		VALUES ('evt-' || lower(hex(randomblob(6))), ?, ?, 'credential_proxy', 'credential_inject', ?, ?)`, runID, sessionID, string(payload), now)
	return err
}
