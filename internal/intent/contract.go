package intent

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Contract kinds.
const (
	ContractToolCall      = "tool_call"
	ContractPeerMessage   = "peer_message"
	ContractRefusal       = "refusal"
	ContractModelResponse = "model_response"
)

// assertedConfidence caps how much a hook-derived (model-asserted) contract may
// vouch for itself. The runtime effect it is diffed against is kernel-witnessed
// (confidence ~1.0); the intent side is only what the model CLAIMED, so a
// mismatch's confidence is bounded by this. Mirrors the ai_asserted 0.5 cap the
// correlation layer already uses.
const assertedConfidence = 0.5

// IntentContract is what one agent action declares it should and must-not do.
type IntentContract struct {
	ID         string  `json:"id"`
	Kind       string  `json:"kind"`
	ScopeAgent string  `json:"scope_agent"`
	ToolCallID string  `json:"tool_call_id,omitempty"`
	Operation  string  `json:"operation"`
	Target     string  `json:"target"`
	Profile    Profile `json:"-"`
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
	// Negative marks a refusal: the agent declared it would NOT do the proposed
	// action, so the baseline sensitive effects become a hard forbid for it.
	Negative bool `json:"negative,omitempty"`
}

// ExtractContracts builds every IntentContract for a run from the captured
// intent surfaces: each agent tool call (via its profile), each peer message
// (governing the recipient), and each refusal (a negative contract).
func ExtractContracts(db *sql.DB, runID string, profiles map[string]Profile) ([]IntentContract, error) {
	var out []IntentContract

	rows, err := db.Query(`SELECT id, agent_id, command, status FROM tool_calls
		WHERE run_id = ? AND agent_id != '' AND command != ''`, runID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, agentID, command, status string
		if err := rows.Scan(&id, &agentID, &command, &status); err != nil {
			rows.Close()
			return nil, err
		}
		if status == "refused" || strings.HasPrefix(id, "refusal-") {
			// A refusal is a negative contract: the agent said it would not act,
			// so any baseline-sensitive effect later attributed to it is a bypass.
			out = append(out, IntentContract{
				ID:         "contract/" + id,
				Kind:       ContractRefusal,
				ScopeAgent: agentID,
				ToolCallID: id,
				Operation:  "refusal",
				Target:     strings.TrimPrefix(command, "[llm refusal] "),
				Profile:    Profile{Operation: "refusal"},
				Source:     "refusal " + id,
				Confidence: assertedConfidence,
				Negative:   true,
			})
			continue
		}
		op := inferOperation(command)
		out = append(out, IntentContract{
			ID:         "contract/" + id,
			Kind:       ContractToolCall,
			ScopeAgent: agentID,
			ToolCallID: id,
			Operation:  op,
			Target:     command,
			Profile:    profileFor(profiles, op),
			Source:     "tool_call " + id,
			Confidence: assertedConfidence,
		})
	}
	rows.Close()

	msgs, err := extractMessageContracts(db, runID, profiles)
	if err != nil {
		return nil, err
	}
	out = append(out, msgs...)
	modelContracts, err := extractModelResponseContracts(db, runID)
	if err != nil {
		return nil, err
	}
	out = append(out, modelContracts...)
	return out, nil
}

func extractModelResponseContracts(db *sql.DB, runID string) ([]IntentContract, error) {
	var rootAgent string
	_ = db.QueryRow(`SELECT id FROM agents WHERE run_id = ? AND parent_agent_id = '' ORDER BY created_at LIMIT 1`, runID).Scan(&rootAgent)
	var rootToolCall string
	_ = db.QueryRow(`SELECT id FROM tool_calls WHERE run_id = ? ORDER BY started_at LIMIT 1`, runID).Scan(&rootToolCall)
	rows, err := db.Query(`SELECT source_id, path FROM provenance_objects
		WHERE run_id = ? AND object_type = 'llm_message' AND source_id LIKE 'endpoint/resp-%'`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IntentContract
	for rows.Next() {
		var sourceID, path string
		if err := rows.Scan(&sourceID, &path); err != nil {
			return nil, err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var obj struct {
			Payload struct {
				Semantics struct {
					DeclaredToolCall bool   `json:"declared_tool_call"`
					IntentRole       string `json:"intent_role"`
				} `json:"semantics"`
			} `json:"payload"`
		}
		if json.Unmarshal(raw, &obj) != nil || obj.Payload.Semantics.DeclaredToolCall || obj.Payload.Semantics.IntentRole != "primary" {
			continue
		}
		seq := strings.TrimPrefix(sourceID, "endpoint/resp-")
		out = append(out, IntentContract{
			ID: "contract/endpoint-response-" + seq, Kind: ContractModelResponse,
			ScopeAgent: rootAgent, ToolCallID: rootToolCall, Operation: "text_response",
			Target:  "model returned text without declaring a tool call",
			Profile: Profile{Operation: "text_response"}, Source: sourceID, Confidence: assertedConfidence,
		})
	}
	return out, rows.Err()
}

// extractMessageContracts turns each peer SendMessage into a contract that
// governs the RECIPIENT: the instruction alice sends bob ("install X") declares
// what bob's ensuing runtime should be about, so bob reading a foreign secret
// while acting on it is a peer_message_intent_mismatch. The agent_message edges
// route sender -> body-object -> recipient; we pair them via the shared object.
func extractMessageContracts(db *sql.DB, runID string, profiles map[string]Profile) ([]IntentContract, error) {
	rows, err := db.Query(`SELECT from_id, to_id FROM graph_edges
		WHERE run_id = ? AND edge_type = 'agent_message'`, runID)
	if err != nil {
		return nil, err
	}
	senderOf := map[string]string{}    // object hash -> sender agent node
	recipientOf := map[string]string{} // object hash -> recipient agent node
	for rows.Next() {
		var from, to string
		if err := rows.Scan(&from, &to); err != nil {
			rows.Close()
			return nil, err
		}
		switch {
		case strings.HasPrefix(to, "sha256:"):
			senderOf[to] = from
		case strings.HasPrefix(from, "sha256:"):
			recipientOf[from] = to
		}
	}
	rows.Close()

	var out []IntentContract
	i := 0
	for hash, recipient := range recipientOf {
		body := readMessageBody(db, hash)
		if body == "" {
			continue
		}
		op := inferOperation(body)
		recipientAgent := strings.TrimPrefix(recipient, "agent/")
		i++
		out = append(out, IntentContract{
			ID:         fmt.Sprintf("contract/msg-%d", i),
			Kind:       ContractPeerMessage,
			ScopeAgent: recipientAgent,
			Operation:  op,
			Target:     body,
			Profile:    profileFor(profiles, op),
			Source:     "peer_message " + strings.TrimPrefix(senderOf[hash], "agent/") + "->" + recipientAgent,
			Confidence: assertedConfidence,
		})
	}
	return out, nil
}

// readMessageBody fetches an objectified agent-message body (content-addressed on
// disk) and returns its text.
func readMessageBody(db *sql.DB, hash string) string {
	var path string
	if err := db.QueryRow(`SELECT path FROM provenance_objects WHERE hash = ?`, hash).Scan(&path); err != nil {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var obj struct {
		Payload struct {
			Body    string `json:"body"`
			Content string `json:"content"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}
	if obj.Payload.Body != "" {
		return obj.Payload.Body
	}
	return obj.Payload.Content
}
