package tlsintent

import (
	"fmt"
	"strings"
	"testing"
)

// feed splits full into byte slices of size split and feeds them as ordered
// Chunks on one connection/direction, returning all completed messages.
func feed(r *Reassembler, pid uint32, conn uint64, dir string, full string, split int) []Message {
	var msgs []Message
	b := []byte(full)
	for i := 0; i < len(b); i += split {
		end := i + split
		if end > len(b) {
			end = len(b)
		}
		msgs = append(msgs, r.Add(Chunk{PID: pid, Conn: conn, Direction: dir, Data: b[i:end]})...)
	}
	return msgs
}

func contentLengthMsg(startLine, ctype, body string) string {
	return startLine + "\r\n" +
		"Host: api.anthropic.com\r\n" +
		"Content-Type: " + ctype + "\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)) + body
}

func chunkedBody(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		fmt.Fprintf(&b, "%x\r\n%s\r\n", len(p), p)
	}
	b.WriteString("0\r\n\r\n")
	return b.String()
}

func TestContentLengthRequestReassembledAcrossChunks(t *testing.T) {
	r := NewReassembler()
	body := `{"model":"claude-opus-4-8","messages":[{"role":"user","content":"read ~/.aws/credentials"}]}`
	full := contentLengthMsg("POST /v1/messages HTTP/1.1", "application/json", body)

	// Split into tiny 7-byte chunks to force reassembly across the header/body.
	msgs := feed(r, 100, 0xABC, Request, full, 7)
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	m := msgs[0]
	if m.Direction != Request || m.Method != "POST" || m.Path != "/v1/messages" {
		t.Errorf("bad request line: %+v", m)
	}
	if m.Host != "api.anthropic.com" || m.Endpoint != "api.anthropic.com/v1/messages" {
		t.Errorf("endpoint = %q", m.Endpoint)
	}
	if m.Model != "claude-opus-4-8" {
		t.Errorf("model = %q, want claude-opus-4-8", m.Model)
	}
	if string(m.Body) != body {
		t.Errorf("body mismatch:\n got %q\nwant %q", m.Body, body)
	}
	if m.Truncated {
		t.Error("unexpectedly truncated")
	}
}

func TestContentLengthResponse(t *testing.T) {
	r := NewReassembler()
	body := `{"model":"claude-opus-4-8","stop_reason":"tool_use","content":[{"type":"tool_use","name":"bash"}]}`
	full := contentLengthMsg("HTTP/1.1 200 OK", "application/json", body)
	msgs := feed(r, 1, 1, Response, full, 13)
	if len(msgs) != 1 {
		t.Fatalf("got %d, want 1", len(msgs))
	}
	if msgs[0].Direction != Response || msgs[0].Status != 200 {
		t.Errorf("status = %d", msgs[0].Status)
	}
	if msgs[0].Model != "claude-opus-4-8" {
		t.Errorf("model = %q", msgs[0].Model)
	}
}

func TestCloseFramedResponseFlushedOnNextRequestSameConn(t *testing.T) {
	// A close-framed response (no Content-Length, no chunked) has no in-band
	// terminator, so parseOne can't complete it. On a reused SSL* connection the
	// next request is the completion signal — the response must not be lost.
	r := NewReassembler()
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n" +
		`{"model":"deepseek-v4-flash","choices":[{"message":{"content":"hi"}}]}`
	if msgs := r.Add(Chunk{PID: 1, Conn: 9, Direction: Response, Data: []byte(resp)}); len(msgs) != 0 {
		t.Fatalf("close-framed response should buffer, not emit yet: got %d", len(msgs))
	}
	// A new request on the same conn (SSL* reused) flushes the pending response.
	req := "POST /v2 HTTP/1.1\r\nHost: api.deepseek.com\r\nContent-Length: 0\r\n\r\n"
	msgs := r.Add(Chunk{PID: 1, Conn: 9, Direction: Request, Data: []byte(req)})
	var gotResp bool
	for _, m := range msgs {
		if m.Direction == Response && m.Status == 200 && m.Model == "deepseek-v4-flash" {
			gotResp = true
		}
	}
	if !gotResp {
		t.Fatalf("pending close-framed response not flushed on next request: %+v", msgs)
	}
}

func TestChunkedResponse(t *testing.T) {
	r := NewReassembler()
	body := chunkedBody(`{"model":"claude-opus-4-8",`, `"content":"hello"}`)
	full := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n" + body
	msgs := feed(r, 1, 2, Response, full, 5)
	if len(msgs) != 1 {
		t.Fatalf("got %d, want 1", len(msgs))
	}
	want := `{"model":"claude-opus-4-8","content":"hello"}`
	if string(msgs[0].Body) != want {
		t.Errorf("dechunked body = %q, want %q", msgs[0].Body, want)
	}
	if msgs[0].Model != "claude-opus-4-8" {
		t.Errorf("model = %q", msgs[0].Model)
	}
}

func TestChunkedSSEStreamingResponse(t *testing.T) {
	r := NewReassembler()
	// A streaming completion: SSE events delivered inside chunked encoding, ending
	// with Anthropic's message_stop.
	sse := "event: message_start\r\ndata: {\"type\":\"message_start\"}\n\n" +
		"event: content_block_delta\ndata: {\"delta\":{\"text\":\"exfil\"}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	full := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\n\r\n" + chunkedBody(sse)
	msgs := feed(r, 1, 3, Response, full, 9)
	if len(msgs) != 1 {
		t.Fatalf("got %d, want 1", len(msgs))
	}
	joined := string(msgs[0].Body)
	// The reconstructed body is the joined data: payloads.
	if !strings.Contains(joined, `"delta":{"text":"exfil"}`) || !strings.Contains(joined, "message_stop") {
		t.Errorf("SSE join missing content:\n%s", joined)
	}
	if strings.Contains(joined, "event:") {
		t.Errorf("SSE join should drop event: lines, got:\n%s", joined)
	}
}

func TestH2IncompleteFrameYieldsNothing(t *testing.T) {
	r := NewReassembler()
	// preface + a frame header claiming 18 payload bytes with only a few present:
	// h2 is parsed (not mis-read as HTTP/1.1), and an incomplete frame emits
	// nothing rather than a raw dump. Full h2 parsing is covered in http2_test.go.
	full := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x12\x04\x00binaryframes"
	msgs := feed(r, 1, 4, Request, full, 6)
	if len(msgs) != 0 {
		t.Fatalf("incomplete h2 frame should emit nothing, got %d", len(msgs))
	}
	if flushed := r.Flush(1, 4); len(flushed) != 0 {
		t.Fatalf("no complete h2 headers -> flush should emit nothing, got %+v", flushed)
	}
}

func TestKeepAliveTwoMessagesOneConnection(t *testing.T) {
	r := NewReassembler()
	a := contentLengthMsg("HTTP/1.1 200 OK", "application/json", `{"model":"m1"}`)
	b := contentLengthMsg("HTTP/1.1 200 OK", "application/json", `{"model":"m2"}`)
	msgs := feed(r, 1, 5, Response, a+b, 4)
	if len(msgs) != 2 {
		t.Fatalf("got %d, want 2 (keep-alive)", len(msgs))
	}
	if msgs[0].Model != "m1" || msgs[1].Model != "m2" {
		t.Errorf("models = %q, %q", msgs[0].Model, msgs[1].Model)
	}
}

func TestIncompleteBodyYieldsNothing(t *testing.T) {
	r := NewReassembler()
	// Content-Length 100 but only a short body arrives.
	full := "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" + "{\"partial\":true}"
	msgs := feed(r, 1, 6, Response, full, 8)
	if len(msgs) != 0 {
		t.Fatalf("incomplete body must not complete, got %d", len(msgs))
	}
}

func TestTruncatedChunkMarksMessage(t *testing.T) {
	r := NewReassembler()
	body := `{"model":"m"}`
	full := contentLengthMsg("HTTP/1.1 200 OK", "application/json", body)
	b := []byte(full)
	// Feed the header + first half normally, mark a truncation, then the rest.
	half := len(b) / 2
	r.Add(Chunk{PID: 1, Conn: 7, Direction: Response, Data: b[:half], Truncated: true})
	msgs := r.Add(Chunk{PID: 1, Conn: 7, Direction: Response, Data: b[half:]})
	if len(msgs) != 1 {
		t.Fatalf("got %d, want 1", len(msgs))
	}
	if !msgs[0].Truncated {
		t.Error("message should be marked Truncated")
	}
}
