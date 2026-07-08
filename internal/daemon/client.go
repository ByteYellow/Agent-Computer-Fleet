package daemon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/baseline"
	"github.com/byteyellow/agentprovenance/internal/control"
	"github.com/byteyellow/agentprovenance/internal/evidence"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/observability"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	securitymodel "github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/signal"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
	Token   string
}

func NewClient(baseURL string) Client {
	return Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: http.DefaultClient, Token: os.Getenv("AGENTPROV_DAEMON_TOKEN")}
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

func (c Client) SetSessionCPUProfile(sessionID, profile string) error {
	return c.postJSON("/v1/sessions/"+sessionID+"/cpu-profile", map[string]any{"profile": profile}, nil)
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
		c.authorize(req)
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

func (c Client) ObserveSummary(runID string, topN int) (observability.Summary, error) {
	values := url.Values{}
	values.Set("run", runID)
	if topN > 0 {
		values.Set("top", fmt.Sprintf("%d", topN))
	}
	var summary observability.Summary
	err := c.getJSON("/v1/observe/summary?"+values.Encode(), &summary)
	return summary, err
}

func (c Client) Timeline(opts provenance.TimelineOptions) (provenance.TimelineManifest, error) {
	values := url.Values{}
	values.Set("run", opts.RunID)
	if opts.ToolCall != "" {
		values.Set("tool_call", opts.ToolCall)
	}
	if opts.ProcessID != "" {
		values.Set("process", opts.ProcessID)
	}
	if opts.Type != "" {
		values.Set("type", opts.Type)
	}
	if opts.View != "" {
		values.Set("view", opts.View)
	}
	if opts.Limit > 0 {
		values.Set("limit", fmt.Sprintf("%d", opts.Limit))
	}
	if opts.Cursor != "" {
		values.Set("cursor", opts.Cursor)
	}
	var manifest provenance.TimelineManifest
	err := c.getJSON("/v1/timeline?"+values.Encode(), &manifest)
	return manifest, err
}

func (c Client) TelemetryCorrelations(runID, eventID string) (telemetry.CorrelationReport, error) {
	values := url.Values{}
	if runID != "" {
		values.Set("run", runID)
	}
	if eventID != "" {
		values.Set("event", eventID)
	}
	var report telemetry.CorrelationReport
	err := c.getJSON("/v1/telemetry/correlations?"+values.Encode(), &report)
	return report, err
}

func (c Client) SecurityRisks(runID string) (securitymodel.RiskSignalsReport, error) {
	var report securitymodel.RiskSignalsReport
	err := c.getJSON("/v1/security/risks?run="+url.QueryEscape(runID), &report)
	return report, err
}

func (c Client) SecurityResponses(runID string) (securitymodel.ResponseActionsReport, error) {
	var report securitymodel.ResponseActionsReport
	err := c.getJSON("/v1/security/responses?run="+url.QueryEscape(runID), &report)
	return report, err
}

func (c Client) SecurityDeviations(runID string) (baseline.DeviationsReport, error) {
	var report baseline.DeviationsReport
	err := c.getJSON("/v1/security/deviations?run="+url.QueryEscape(runID), &report)
	return report, err
}

func (c Client) VerifyGraph(runID string) (provenance.VerifyResult, error) {
	var result provenance.VerifyResult
	err := c.getJSON("/v1/graph/verify?run="+url.QueryEscape(runID), &result)
	return result, err
}

func (c Client) ExplainGraph(opts provenance.ExplainOptions) (provenance.ExplainManifest, error) {
	values := url.Values{}
	if opts.RunID != "" {
		values.Set("run", opts.RunID)
	}
	if opts.Artifact != "" {
		values.Set("artifact", opts.Artifact)
	}
	if opts.Attempt != "" {
		values.Set("attempt", opts.Attempt)
	}
	if opts.ToolCall != "" {
		values.Set("tool_call", opts.ToolCall)
	}
	if opts.Process != "" {
		values.Set("process", opts.Process)
	}
	if opts.Event != "" {
		values.Set("event", opts.Event)
	}
	if opts.Risk != "" {
		values.Set("risk", opts.Risk)
	}
	if opts.File != "" {
		values.Set("file", opts.File)
	}
	if opts.Depth > 0 {
		values.Set("depth", fmt.Sprintf("%d", opts.Depth))
	}
	if opts.Limit > 0 {
		values.Set("limit", fmt.Sprintf("%d", opts.Limit))
	}
	if opts.Cursor != "" {
		values.Set("cursor", opts.Cursor)
	}
	var manifest provenance.ExplainManifest
	err := c.getJSON("/v1/graph/explain?"+values.Encode(), &manifest)
	return manifest, err
}

func (c Client) GraphLens(opts provenance.GraphLensOptions) (provenance.GraphLensManifest, error) {
	values := url.Values{}
	if opts.RunID != "" {
		values.Set("run", opts.RunID)
	}
	if opts.Lens != "" {
		values.Set("lens", opts.Lens)
	}
	if opts.Focus != "" {
		values.Set("focus", opts.Focus)
	}
	if opts.Detail != "" {
		values.Set("detail", opts.Detail)
	}
	if opts.Limit > 0 {
		values.Set("limit", fmt.Sprintf("%d", opts.Limit))
	}
	for _, overlay := range opts.Overlays {
		values.Add("overlay", overlay)
	}
	var manifest provenance.GraphLensManifest
	err := c.getJSON("/v1/graph/lens?"+values.Encode(), &manifest)
	return manifest, err
}

func (c Client) EvidenceManifest(runID string, materialize bool) (evidence.MaterializedManifest, error) {
	values := url.Values{}
	values.Set("run", runID)
	if materialize {
		values.Set("materialize", "1")
	}
	var result evidence.MaterializedManifest
	err := c.getJSON("/v1/evidence/manifest?"+values.Encode(), &result)
	return result, err
}

func (c Client) ExportForensics(runID string) (forensics.BundleInfo, error) {
	var bundle forensics.BundleInfo
	err := c.postJSON("/v1/forensics/export", map[string]any{"run_id": runID}, &bundle)
	return bundle, err
}

func (c Client) ExportBatchForensics(opts forensics.BatchExportOptions) (forensics.BatchBundleInfo, error) {
	var bundle forensics.BatchBundleInfo
	err := c.postJSON("/v1/forensics/export-batch", opts, &bundle)
	return bundle, err
}

func (c Client) SignalContext(runID string) (signal.EvalContext, error) {
	var ctx signal.EvalContext
	err := c.getJSON("/v1/signal/context?run="+url.QueryEscape(runID), &ctx)
	return ctx, err
}

func (c Client) RunBuiltinSignals(runID string) (signal.EvalReport, error) {
	var report signal.EvalReport
	err := c.postJSON("/v1/signal/run", map[string]any{"run_id": runID}, &report)
	return report, err
}

func (c Client) ImportSignals(runID, engine string, signals []signal.EvalSignal) (signal.EvalReport, error) {
	var report signal.EvalReport
	err := c.postJSON("/v1/signal/import", map[string]any{"run_id": runID, "engine": engine, "signals": signals}, &report)
	return report, err
}

type SnapshotCreateResponse struct {
	SnapshotID       string `json:"snapshot_id"`
	Files            int64  `json:"files"`
	Bytes            int64  `json:"bytes"`
	SnapshotCreateMS int64  `json:"snapshot_create_ms"`
	Hash             string `json:"hash"`
}

// authorize attaches the bearer token to a request when one is configured.
func (c Client) authorize(req *http.Request) {
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
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
	c.authorize(req)
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
