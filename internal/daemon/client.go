package daemon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/byteyellow/agent-computer-fleet/internal/control"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func NewClient(baseURL string) Client {
	return Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: http.DefaultClient}
}

func (c Client) CreateLease(task string) (string, error) {
	var resp struct {
		LeaseID string `json:"lease_id"`
	}
	err := c.postJSON("/v1/leases", map[string]any{"task": task}, &resp)
	return resp.LeaseID, err
}

func (c Client) CreateSession(leaseID string) (string, error) {
	var resp struct {
		SessionID string `json:"session_id"`
	}
	err := c.postJSON("/v1/sessions", map[string]any{"lease_id": leaseID}, &resp)
	return resp.SessionID, err
}

func (c Client) ListSessions() ([]control.SessionInfo, error) {
	var resp struct {
		Sessions []control.SessionInfo `json:"sessions"`
	}
	err := c.getJSON("/v1/sessions", &resp)
	return resp.Sessions, err
}

func (c Client) InspectSession(sessionID string) (control.SessionInfo, error) {
	var resp struct {
		Session control.SessionInfo `json:"session"`
	}
	err := c.getJSON("/v1/sessions/"+sessionID, &resp)
	return resp.Session, err
}

func (c Client) StopSession(sessionID string) error {
	return c.postJSON("/v1/sessions/"+sessionID+"/stop", map[string]any{}, nil)
}

func (c Client) RemoveSession(sessionID string) error {
	req, err := http.NewRequest(http.MethodDelete, c.BaseURL+"/v1/sessions/"+sessionID, nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

func (c Client) Exec(sessionID string, command []string, stream bool, out io.Writer) (string, error) {
	if stream {
		raw, _ := json.Marshal(map[string]any{"command": command, "stream": true})
		req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/v1/sessions/"+sessionID+"/exec", bytes.NewReader(raw))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			body, _ := io.ReadAll(resp.Body)
			return "", fmt.Errorf("%s", strings.TrimSpace(string(body)))
		}
		_, err = io.Copy(out, resp.Body)
		return "", err
	}
	var resp struct {
		ProcessID string `json:"process_id"`
	}
	err := c.postJSON("/v1/sessions/"+sessionID+"/exec", map[string]any{"command": command, "stream": false}, &resp)
	return resp.ProcessID, err
}

func (c Client) CreateSnapshot(sessionID, typ, path, name string) (SnapshotCreateResponse, error) {
	var resp SnapshotCreateResponse
	err := c.postJSON("/v1/snapshots", map[string]any{"session_id": sessionID, "type": typ, "path": path, "name": name}, &resp)
	return resp, err
}

func (c Client) ResumeSnapshot(snapshotNameOrID, leaseID string) (string, error) {
	var resp struct {
		SessionID string `json:"session_id"`
	}
	err := c.postJSON("/v1/snapshots/"+snapshotNameOrID+"/resume", map[string]any{"lease_id": leaseID}, &resp)
	return resp.SessionID, err
}

type SnapshotCreateResponse struct {
	SnapshotID       string `json:"snapshot_id"`
	Files            int64  `json:"files"`
	Bytes            int64  `json:"bytes"`
	SnapshotCreateMS int64  `json:"snapshot_create_ms"`
	Hash             string `json:"hash"`
}

func (c Client) getJSON(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

func (c Client) postJSON(path string, payload any, out any) error {
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

func (c Client) do(req *http.Request, out any) error {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error == "" {
			errResp.Error = resp.Status
		}
		return fmt.Errorf("%s", errResp.Error)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
