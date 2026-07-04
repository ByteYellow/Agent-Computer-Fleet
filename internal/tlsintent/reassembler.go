// Package tlsintent reassembles the fragmented TLS plaintext that the eBPF
// SSL_write/SSL_read probes capture into COMPLETE HTTP/1.1 request/response
// messages, and pulls minimal LLM semantics (model, endpoint) out of the body.
//
// It is the userspace half of "capture the agent's actual LLM traffic without
// instrumenting the agent": the kernel probe can only read a bounded buffer per
// call, so it emits ordered Chunks keyed by the TLS connection; this package
// accumulates them and parses the message once whole. Clean-room implementation
// (technique only; our own code, Go stdlib HTTP framing).
//
// Scope: HTTP/1.1 with Content-Length, chunked, and SSE (streaming) bodies.
// HTTP/2 is DETECTED (the h2 client preface) and passed through as raw, never
// mis-parsed. Platform-neutral (no eBPF/Linux deps) so it unit-tests anywhere.
package tlsintent

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// Direction of a captured segment relative to the agent.
const (
	Request  = "request"  // SSL_write: bytes the agent sent (the LLM request)
	Response = "response" // SSL_read: bytes the agent received (the LLM response)
)

// Protocol values on a reassembled Message.
const (
	ProtoHTTP11 = "http/1.1"
	ProtoH2     = "h2" // detected, not parsed; Body is the raw plaintext
)

// Chunk is one ordered segment of TLS plaintext from the eBPF probe. A large
// request/response arrives as several Chunks with increasing arrival order on the
// same (PID, Conn) TLS connection. This is the eBPF<->userspace contract.
type Chunk struct {
	PID       uint32
	Conn      uint64 // the SSL* pointer: identifies one TLS connection
	Direction string // Request or Response
	Data      []byte
	Truncated bool // the kernel dropped bytes past its capture cap for this call
}

// Message is a fully reassembled HTTP/1.1 message plus minimal LLM semantics.
type Message struct {
	PID       uint32
	Conn      uint64
	Direction string // Request or Response
	Protocol  string // ProtoHTTP11 or ProtoH2

	// HTTP surface.
	Method  string // request only
	Path    string // request only
	Host    string // request only
	Status  int    // response only
	Headers map[string]string
	Body    []byte // decoded body: dechunked and, for SSE, the joined data: payloads

	Truncated bool // some bytes were dropped, so Body may be incomplete

	// Minimal LLM semantics (best-effort; empty when not an LLM call).
	Model    string
	Endpoint string // request: host+path
}

// Reassembler accumulates Chunks per connection+direction and returns any
// messages that became complete. It handles HTTP keep-alive (several messages on
// one connection) by keeping the pipelined remainder after each complete message.
type Reassembler struct {
	streams  map[streamKey]*stream
	MaxBytes int // per-stream buffer cap; 0 -> defaultMaxBytes
}

type streamKey struct {
	pid       uint32
	conn      uint64
	direction string
}

type stream struct {
	buf       bytes.Buffer
	truncated bool
	isH2      bool
}

const defaultMaxBytes = 1 << 20 // 1 MiB per stream

// NewReassembler returns an empty Reassembler.
func NewReassembler() *Reassembler {
	return &Reassembler{streams: map[streamKey]*stream{}, MaxBytes: defaultMaxBytes}
}

// Add feeds one Chunk and returns every message that completed as a result
// (usually zero or one).
func (r *Reassembler) Add(c Chunk) []Message {
	if r.streams == nil {
		r.streams = map[streamKey]*stream{}
	}
	if len(c.Data) == 0 && !c.Truncated {
		return nil
	}
	k := streamKey{c.PID, c.Conn, c.Direction}
	s := r.streams[k]
	if s == nil {
		s = &stream{}
		r.streams[k] = s
	}
	if c.Truncated {
		s.truncated = true
	}
	max := r.MaxBytes
	if max <= 0 {
		max = defaultMaxBytes
	}
	if s.buf.Len() < max {
		s.buf.Write(c.Data)
	} else {
		s.truncated = true
	}
	if !s.isH2 && c.Direction == Request && looksLikeH2(s.buf.Bytes()) {
		s.isH2 = true
	}

	var out []Message
	for {
		msg, consumed, ok := parseOne(c.PID, c.Conn, c.Direction, s.buf.Bytes(), s.isH2)
		if !ok || consumed <= 0 {
			break
		}
		msg.Truncated = s.truncated
		out = append(out, msg)
		rest := append([]byte(nil), s.buf.Bytes()[consumed:]...)
		s.buf.Reset()
		s.buf.Write(rest)
		s.truncated = false
	}
	return out
}

// Flush emits whatever is buffered for a connection as a best-effort (possibly
// truncated) message and forgets its streams. Call it when a connection closes
// (e.g. on process_exit) so a close-framed response with no Content-Length isn't
// lost.
func (r *Reassembler) Flush(pid uint32, conn uint64) []Message {
	var out []Message
	for _, dir := range []string{Request, Response} {
		k := streamKey{pid, conn, dir}
		s := r.streams[k]
		if s == nil || s.buf.Len() == 0 {
			continue
		}
		if msg, ok := parseBestEffort(pid, conn, dir, s.buf.Bytes(), s.isH2); ok {
			msg.Truncated = true
			out = append(out, msg)
		}
		delete(r.streams, k)
	}
	return out
}

func looksLikeH2(b []byte) bool {
	return bytes.HasPrefix(b, []byte("PRI * HTTP/2.0\r\n"))
}

// parseOne tries to parse exactly one complete HTTP/1.1 message from the front of
// buf. Returns the message, bytes consumed, and whether it succeeded.
func parseOne(pid uint32, conn uint64, direction string, buf []byte, isH2 bool) (Message, int, bool) {
	if isH2 {
		return Message{}, 0, false // handled via Flush as raw
	}
	hdrEnd := bytes.Index(buf, []byte("\r\n\r\n"))
	if hdrEnd < 0 {
		return Message{}, 0, false
	}
	rest := buf[hdrEnd+4:]
	msg, headers, ok := parseStartAndHeaders(pid, conn, direction, buf[:hdrEnd+4])
	if !ok {
		return Message{}, 0, false
	}

	if cl, hasCL := contentLength(headers); hasCL {
		if len(rest) < cl {
			return Message{}, 0, false
		}
		msg.Body = decodeBody(append([]byte(nil), rest[:cl]...), headers)
		finalizeSemantics(&msg)
		return msg, hdrEnd + 4 + cl, true
	}
	if strings.EqualFold(headers["transfer-encoding"], "chunked") {
		raw, n, done := dechunk(rest)
		if !done {
			return Message{}, 0, false
		}
		msg.Body = decodeBody(raw, headers)
		finalizeSemantics(&msg)
		return msg, hdrEnd + 4 + n, true
	}
	if isSSE(headers) {
		raw, n, done := readSSE(rest)
		if !done {
			return Message{}, 0, false
		}
		msg.Body = raw
		finalizeSemantics(&msg)
		return msg, hdrEnd + 4 + n, true
	}
	if direction == Request {
		finalizeSemantics(&msg) // request with no body (GET / no Content-Length)
		return msg, hdrEnd + 4, true
	}
	return Message{}, 0, false // response framed by connection close -> Flush
}

func parseBestEffort(pid uint32, conn uint64, direction string, buf []byte, isH2 bool) (Message, bool) {
	if isH2 {
		return Message{PID: pid, Conn: conn, Direction: direction, Protocol: ProtoH2, Body: append([]byte(nil), buf...)}, true
	}
	hdrEnd := bytes.Index(buf, []byte("\r\n\r\n"))
	if hdrEnd < 0 {
		return Message{}, false
	}
	msg, headers, ok := parseStartAndHeaders(pid, conn, direction, buf[:hdrEnd+4])
	if !ok {
		return Message{}, false
	}
	rest := buf[hdrEnd+4:]
	if isSSE(headers) {
		if body := sseJoin(rest); len(body) > 0 {
			msg.Body = body
		} else {
			msg.Body = append([]byte(nil), rest...)
		}
	} else {
		msg.Body = decodeBody(append([]byte(nil), rest...), headers)
	}
	finalizeSemantics(&msg)
	return msg, true
}

func parseStartAndHeaders(pid uint32, conn uint64, direction string, headerBytes []byte) (Message, map[string]string, bool) {
	rd := bufio.NewReader(bytes.NewReader(headerBytes))
	startLine, err := rd.ReadString('\n')
	if err != nil {
		return Message{}, nil, false
	}
	startLine = strings.TrimRight(startLine, "\r\n")
	msg := Message{PID: pid, Conn: conn, Direction: direction, Protocol: ProtoHTTP11, Headers: map[string]string{}}
	headers := map[string]string{}
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:i]))
		val := strings.TrimSpace(line[i+1:])
		headers[name] = val
		msg.Headers[name] = val
	}
	fields := strings.Fields(startLine)
	switch {
	case strings.HasPrefix(startLine, "HTTP/"):
		msg.Direction = Response
		if len(fields) >= 2 {
			msg.Status, _ = strconv.Atoi(fields[1])
		}
	case len(fields) >= 2:
		msg.Direction = Request
		msg.Method = fields[0]
		msg.Path = fields[1]
		msg.Host = headers["host"]
	default:
		return Message{}, nil, false
	}
	return msg, headers, true
}

// decodeBody post-processes a fully-read body: if it is SSE, join the data:
// payloads into the reconstructed stream content.
func decodeBody(raw []byte, headers map[string]string) []byte {
	if isSSE(headers) {
		if joined := sseJoin(raw); len(joined) > 0 {
			return joined
		}
	}
	return raw
}

func contentLength(headers map[string]string) (int, bool) {
	v, ok := headers["content-length"]
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func isSSE(headers map[string]string) bool {
	return strings.Contains(strings.ToLower(headers["content-type"]), "text/event-stream")
}

// dechunk decodes a Transfer-Encoding: chunked body by hand (so we know exactly
// how many RAW bytes were consumed, for keep-alive). Returns decoded bytes, raw
// bytes consumed, and whether the terminating 0-size chunk arrived.
func dechunk(raw []byte) (body []byte, consumed int, done bool) {
	var out bytes.Buffer
	pos := 0
	for {
		nl := bytes.Index(raw[pos:], []byte("\r\n"))
		if nl < 0 {
			return nil, 0, false // size line not fully arrived
		}
		sizeLine := raw[pos : pos+nl]
		if semi := bytes.IndexByte(sizeLine, ';'); semi >= 0 { // chunk extensions
			sizeLine = sizeLine[:semi]
		}
		size, err := strconv.ParseInt(strings.TrimSpace(string(sizeLine)), 16, 64)
		if err != nil || size < 0 {
			return nil, 0, false
		}
		pos += nl + 2
		if size == 0 { // last chunk; skip trailers up to the final CRLF
			end := bytes.Index(raw[pos:], []byte("\r\n"))
			if end < 0 {
				return nil, 0, false
			}
			return out.Bytes(), pos + end + 2, true
		}
		if pos+int(size)+2 > len(raw) {
			return nil, 0, false // chunk data + trailing CRLF not fully arrived
		}
		out.Write(raw[pos : pos+int(size)])
		pos += int(size) + 2 // data + CRLF
	}
}

// readSSE consumes a non-chunked SSE body up to the stream terminator, returning
// the joined data payloads, raw bytes consumed, and whether the stream ended.
func readSSE(raw []byte) (body []byte, consumed int, done bool) {
	end := sseTerminator(raw)
	if end < 0 {
		return nil, 0, false
	}
	return sseJoin(raw[:end]), end, true
}

// sseTerminator returns the byte offset just past the end of an SSE stream, or -1
// if not yet terminated. LLM streams end with "data: [DONE]" (OpenAI) or an
// "event: message_stop" (Anthropic), each followed by a blank line.
func sseTerminator(raw []byte) int {
	for _, marker := range [][]byte{[]byte("data: [DONE]"), []byte("event: message_stop")} {
		if i := bytes.Index(raw, marker); i >= 0 {
			if j := bytes.Index(raw[i:], []byte("\n\n")); j >= 0 {
				return i + j + 2
			}
		}
	}
	return -1
}

// sseJoin concatenates the payloads of all `data:` lines (dropping the [DONE]
// sentinel), one per line — the reconstructed stream content.
func sseJoin(raw []byte) []byte {
	var out bytes.Buffer
	for _, line := range bytes.Split(raw, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if bytes.HasPrefix(line, []byte("data:")) {
			payload := bytes.TrimSpace(line[len("data:"):])
			if string(payload) == "[DONE]" {
				continue
			}
			out.Write(payload)
			out.WriteByte('\n')
		}
	}
	return out.Bytes()
}

// finalizeSemantics pulls minimal LLM fields (endpoint, model) from a message.
func finalizeSemantics(msg *Message) {
	if msg.Direction == Request {
		msg.Endpoint = msg.Host + msg.Path
	}
	var body struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(msg.Body, &body) == nil && body.Model != "" {
		msg.Model = body.Model
	}
}
