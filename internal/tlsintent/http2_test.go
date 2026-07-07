package tlsintent

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func h2Frame(ftype, flags byte, streamID uint32, payload []byte) []byte {
	f := make([]byte, 9+len(payload))
	f[0] = byte(len(payload) >> 16)
	f[1] = byte(len(payload) >> 8)
	f[2] = byte(len(payload))
	f[3] = ftype
	f[4] = flags
	binary.BigEndian.PutUint32(f[5:9], streamID)
	copy(f[9:], payload)
	return f
}

func hpackEncode(fields ...[2]string) []byte {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, f := range fields {
		_ = enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	return buf.Bytes()
}

func TestH2RequestHeadersAndBody(t *testing.T) {
	r := NewReassembler()
	hdr := hpackEncode(
		[2]string{":method", "POST"},
		[2]string{":path", "/v1/messages"},
		[2]string{":authority", "api.anthropic.com"},
		[2]string{"content-type", "application/json"},
	)
	body := []byte(`{"model":"claude-opus-4","max_tokens":10}`)
	stream := []byte(h2ClientPreface)
	// A SETTINGS frame (type 0x4, stream 0) precedes app frames and must be skipped.
	stream = append(stream, h2Frame(0x4, 0, 0, nil)...)
	stream = append(stream, h2Frame(h2FrameHeaders, h2FlagEndHeaders, 1, hdr)...)
	stream = append(stream, h2Frame(h2FrameData, h2FlagEndStream, 1, body)...)

	msgs := r.Add(Chunk{PID: 7, Conn: 99, Direction: Request, Data: stream})
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	m := msgs[0]
	if m.Protocol != ProtoH2 {
		t.Errorf("protocol = %q, want %q", m.Protocol, ProtoH2)
	}
	if m.Method != "POST" || m.Path != "/v1/messages" || m.Host != "api.anthropic.com" {
		t.Errorf("request line = %s %s %s", m.Method, m.Path, m.Host)
	}
	if m.Model != "claude-opus-4" {
		t.Errorf("model = %q, want claude-opus-4", m.Model)
	}
	if m.Endpoint != "api.anthropic.com/v1/messages" {
		t.Errorf("endpoint = %q", m.Endpoint)
	}
	if string(m.Body) != string(body) {
		t.Errorf("body = %q", m.Body)
	}
}

func TestH2ResponseOnSameConnection(t *testing.T) {
	r := NewReassembler()
	// A request first marks the connection h2 so the response side is framed too.
	reqHdr := hpackEncode([2]string{":method", "GET"}, [2]string{":path", "/"}, [2]string{":authority", "x"})
	req := append([]byte(h2ClientPreface), h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, reqHdr)...)
	r.Add(Chunk{PID: 1, Conn: 1, Direction: Request, Data: req})

	respHdr := hpackEncode([2]string{":status", "200"}, [2]string{"content-type", "application/json"})
	respBody := []byte(`{"model":"gpt-x","ok":true}`)
	resp := append(h2Frame(h2FrameHeaders, h2FlagEndHeaders, 1, respHdr), h2Frame(h2FrameData, h2FlagEndStream, 1, respBody)...)
	msgs := r.Add(Chunk{PID: 1, Conn: 1, Direction: Response, Data: resp})
	if len(msgs) != 1 {
		t.Fatalf("expected 1 response message, got %d", len(msgs))
	}
	m := msgs[0]
	if m.Direction != Response || m.Status != 200 {
		t.Errorf("direction=%s status=%d, want response/200", m.Direction, m.Status)
	}
	if m.Model != "gpt-x" {
		t.Errorf("model = %q", m.Model)
	}
}

func TestH2RequestSplitAcrossChunks(t *testing.T) {
	r := NewReassembler()
	hdr := hpackEncode([2]string{":method", "POST"}, [2]string{":path", "/p"}, [2]string{":authority", "h"})
	body := []byte(`{"model":"m1"}`)
	full := append([]byte(h2ClientPreface), h2Frame(h2FrameHeaders, h2FlagEndHeaders, 1, hdr)...)
	full = append(full, h2Frame(h2FrameData, h2FlagEndStream, 1, body)...)

	// Split at an awkward point (mid-frame) to exercise buffering.
	split := len(h2ClientPreface) + 5
	var got []Message
	got = append(got, r.Add(Chunk{PID: 2, Conn: 2, Direction: Request, Data: full[:split]})...)
	got = append(got, r.Add(Chunk{PID: 2, Conn: 2, Direction: Request, Data: full[split:]})...)
	if len(got) != 1 {
		t.Fatalf("expected 1 message across chunks, got %d", len(got))
	}
	if got[0].Method != "POST" || got[0].Model != "m1" {
		t.Errorf("reassembled wrong: %+v", got[0])
	}
}

func TestH2PaddedDataStripped(t *testing.T) {
	r := NewReassembler()
	hdr := hpackEncode([2]string{":method", "POST"}, [2]string{":path", "/"}, [2]string{":authority", "h"})
	body := []byte(`{"model":"pad"}`)
	// PADDED DATA: [padLen=3][body][3 pad bytes].
	padded := append([]byte{3}, body...)
	padded = append(padded, 0, 0, 0)
	stream := append([]byte(h2ClientPreface), h2Frame(h2FrameHeaders, h2FlagEndHeaders, 1, hdr)...)
	stream = append(stream, h2Frame(h2FrameData, h2FlagEndStream|h2FlagPadded, 1, padded)...)
	msgs := r.Add(Chunk{PID: 3, Conn: 3, Direction: Request, Data: stream})
	if len(msgs) != 1 || string(msgs[0].Body) != string(body) {
		t.Fatalf("padded body not stripped correctly: %+v", msgs)
	}
}
