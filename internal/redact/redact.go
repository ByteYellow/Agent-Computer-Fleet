// Package redact masks secrets out of captured evidence before it is stored,
// materialized into content-addressed objects, or exported into a signed
// forensics bundle.
//
// The threat it addresses is concrete: the sensor captures raw agent activity
// verbatim — an execve's full argv (including a `curl -H "x-api-key: sk-..."`),
// and, once full-TLS-body capture lands, the plaintext of the agent's own LLM
// requests. Any of those can carry a live API key. Evidence flows to many sinks
// (the store, the dashboard, `--json` output, and a SIGNED, shareable bundle),
// so masking has to happen at capture/write time, not only when one sink
// renders — a single un-redacted export is a public leak.
//
// Matching strategy: anchored provider-token patterns are PRIMARY. They key on
// the token's own high-entropy prefix (`sk-`, `ghp_`, `AKIA`, ...) so they fire
// regardless of serialization — the same key is caught whether it sits in a
// joined command string (`... x-api-key: sk-123 ...`) or an argv array where the
// header name and value are split across separate JSON tokens
// (`["x-api-key:","sk-123"]`). A key/value pattern is SECONDARY, for secrets
// that lack a recognizable prefix but appear next to a telltale field name.
package redact

import "regexp"

const mask = "***REDACTED***"

// tokenRes are anchored on a provider token's own prefix, so they match no
// matter how the surrounding text is serialized. Order does not matter: each is
// self-contained and they do not overlap destructively.
var tokenRes = []*regexp.Regexp{
	// OpenAI / Anthropic / DeepSeek and compatibles: sk-, sk-ant-, sk-proj-…
	regexp.MustCompile(`sk-[A-Za-z0-9_-]{16,}`),
	// GitHub personal/OAuth/app/refresh/server tokens.
	regexp.MustCompile(`gh[porsu]_[A-Za-z0-9]{20,}`),
	// GitLab personal access tokens.
	regexp.MustCompile(`glpat-[A-Za-z0-9_-]{16,}`),
	// Slack tokens.
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),
	// AWS access key id.
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	// Google API key.
	regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
	// Hugging Face user access token.
	regexp.MustCompile(`hf_[A-Za-z0-9]{30,}`),
	// PEM private key block.
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
}

// kvSecretRe catches a secret sitting next to a telltale field name, for values
// that have no recognizable prefix of their own. The value group deliberately
// skips an optional `Bearer ` scheme prefix so the SCHEME is kept and the TOKEN
// is masked (a naive value match eats "Bearer" and leaks the token after it).
var kvSecretRe = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|authorization)(["']?\s*[:=]\s*["']?)(?:(bearer|basic)\s+)?([^\s"',}]{6,})`)

// sensitiveHeaders are TLS/HTTP headers whose entire value is a credential.
// tlsintent masks these structurally (by name) rather than by regex, which is
// precise and never touches the message body.
var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"x-api-key":           true,
	"api-key":             true,
	"cookie":              true,
	"set-cookie":          true,
	"x-goog-api-key":      true,
}

// Redact masks secrets in s and reports whether anything was replaced. It is
// safe to run over a JSON payload string: the token patterns match only the
// secret substrings, not JSON structural characters, so the surrounding
// document stays well-formed.
func Redact(s string) (string, bool) {
	changed := false
	for _, re := range tokenRes {
		if re.MatchString(s) {
			s = re.ReplaceAllString(s, mask)
			changed = true
		}
	}
	if kvSecretRe.MatchString(s) {
		out := kvSecretRe.ReplaceAllStringFunc(s, func(m string) string {
			g := kvSecretRe.FindStringSubmatch(m)
			// g[4] already == mask when a token pattern replaced it above;
			// avoid double-masking and avoid masking our own placeholder.
			if g[4] == mask {
				return m
			}
			scheme := ""
			if g[3] != "" {
				scheme = g[3] + " "
			}
			return g[1] + g[2] + scheme + mask
		})
		if out != s {
			s = out
			changed = true
		}
	}
	return s, changed
}

// RedactString is Redact without the changed flag, for call sites that just want
// the safe string.
func RedactString(s string) string {
	out, _ := Redact(s)
	return out
}

// RedactHeaders masks the values of credential-bearing headers in place and
// reports whether anything was masked. Used by tlsintent on a reassembled HTTP
// message's header map, where masking by name is precise.
func RedactHeaders(headers map[string]string) bool {
	changed := false
	for k := range headers {
		if sensitiveHeaders[canonLower(k)] {
			if headers[k] != mask {
				headers[k] = mask
				changed = true
			}
		}
	}
	return changed
}

func canonLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
