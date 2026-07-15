package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

// The literal key shape that actually leaked into the committed demo bundles
// (a DeepSeek key: sk- + 32 hex). Kept as a test fixture so a regression that
// stops masking it fails loudly.
const leakedKey = "sk-003fe97861dc48ebba10d6d391e4cebe"

func TestRedactCatchesLeakInEverySerialization(t *testing.T) {
	cases := map[string]string{
		"joined command": `curl .../v1/messages -H content-type: application/json -H x-api-key: ` + leakedKey + ` --data-binary @/tmp/x`,
		"argv array":     `{"argv":["-H","x-api-key:","` + leakedKey + `","--data-binary"]}`,
		"bearer header":  `authorization: Bearer sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345`,
		"json body":      `{"model":"claude","api_key":"` + leakedKey + `"}`,
	}
	for name, in := range cases {
		out, changed := Redact(in)
		if !changed {
			t.Errorf("%s: nothing redacted", name)
		}
		if strings.Contains(out, leakedKey) {
			t.Errorf("%s: leaked key survived: %q", name, out)
		}
		if strings.Contains(out, "sk-ant-api03") {
			t.Errorf("%s: bearer token survived: %q", name, out)
		}
	}
}

func TestRedactKeepsBearerScheme(t *testing.T) {
	out, _ := Redact(`authorization: Bearer sk-secretsecretsecret123456`)
	if !strings.Contains(out, "Bearer") {
		t.Errorf("scheme should be preserved, got %q", out)
	}
	if strings.Contains(out, "secretsecret") {
		t.Errorf("token should be masked, got %q", out)
	}
}

func TestRedactDoesNotTouchNonSecrets(t *testing.T) {
	// Policy detection targets must survive untouched, or redaction would blind
	// the very signals the graph exists to produce.
	keep := []string{
		"connect 169.254.169.254",
		"openat /home/agent/.aws/credentials",
		`{"model":"claude-opus-4-8","tools_offered":["bash","read_file"]}`,
		"python3 ../pysnake-helper/setup.py install --user",
	}
	for _, s := range keep {
		out, changed := Redact(s)
		if changed || out != s {
			t.Errorf("false positive on %q -> %q", s, out)
		}
	}
}

func TestRedactPreservesJSONStructure(t *testing.T) {
	in := `{"raw":{"command":"curl -H x-api-key: ` + leakedKey + `","comm":"curl","argv":["curl"]}}`
	out, _ := Redact(in)
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("redacted payload is no longer valid JSON: %v\n%s", err, out)
	}
	if strings.Contains(out, leakedKey) {
		t.Errorf("key survived: %q", out)
	}
}

// A secret embedded in an ESCAPED JSON string (e.g. an LLM request body stored as
// a string field of a provenance object) is immediately followed by a \" escape.
// Redaction must mask the secret without consuming the backslash — otherwise the
// following quote becomes structural and the whole object is corrupted.
func TestRedactPreservesEscapedJSONString(t *testing.T) {
	in := `{"content":"env: access_key=FAKE-secret-do-not-use\",\"role\":\"user\"","semantics":{"host":"api.x.ai"}}`
	out, _ := Redact(in)
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("redacted escaped-JSON payload is no longer valid JSON: %v\n%s", err, out)
	}
	if strings.Contains(out, "FAKE-secret-do-not-use") {
		t.Errorf("secret survived redaction: %q", out)
	}
}

func TestRedactHeadersMasksByName(t *testing.T) {
	h := map[string]string{
		"X-Api-Key":     leakedKey,
		"Authorization": "Bearer abc123def456",
		"Content-Type":  "application/json",
		"Host":          "api.anthropic.com",
	}
	if !RedactHeaders(h) {
		t.Fatal("expected headers to be masked")
	}
	if h["X-Api-Key"] == leakedKey || strings.Contains(h["Authorization"], "abc123") {
		t.Errorf("credential header not masked: %+v", h)
	}
	if h["Content-Type"] != "application/json" || h["Host"] != "api.anthropic.com" {
		t.Errorf("non-credential headers must be untouched: %+v", h)
	}
}

func TestRedactIdempotent(t *testing.T) {
	once, _ := Redact(`x-api-key: ` + leakedKey)
	twice, changed := Redact(once)
	if changed || twice != once {
		t.Errorf("second pass changed already-redacted text: %q -> %q", once, twice)
	}
}
