package tlsintent

import (
	"bytes"
	"encoding/binary"

	"golang.org/x/net/http2/hpack"
)

// HTTP/2 support for the TLS-intent reassembler. The eBPF SSL_write/SSL_read
// probes capture the same plaintext bytes for an h2 connection as for h1.1; the
// bytes are just framed. This parser turns that framed byte stream into the same
// Message model the HTTP/1.1 path emits, so model-intent capture works for the
// h2 traffic that dominates real LLM APIs (Anthropic, OpenAI) and curl's default.
//
// Scope: HEADERS (+ CONTINUATION) with HPACK, DATA bodies, padding and priority
// stripping, END_STREAM framing, multiplexed streams. HPACK's dynamic table is
// per-connection-direction, so one decoder lives per h2Parser. SETTINGS/PING/etc.
// frames are skipped. Clean-room framing; HPACK via golang.org/x/net.

const h2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// h2PrefaceRelated reports whether b is the client preface or a prefix of it, so
// a request stream is recognized as h2 the moment its first bytes arrive - before
// the HTTP/1.1 parser can mis-read the preface's own "\r\n\r\n" as a bogus PRI
// request. No real HTTP/1.1 method is "PRI", so this cannot false-positive on h1.
func h2PrefaceRelated(b []byte) bool {
	p := []byte(h2ClientPreface)
	return bytes.HasPrefix(b, p) || (len(b) > 0 && len(b) < len(p) && bytes.HasPrefix(p, b))
}

const (
	h2FrameData         = 0x0
	h2FrameHeaders      = 0x1
	h2FrameContinuation = 0x9
)

const (
	h2FlagEndStream  = 0x1
	h2FlagEndHeaders = 0x4
	h2FlagPadded     = 0x8
	h2FlagPriority   = 0x20
)

type h2Stream struct {
	headerBlock bytes.Buffer // accumulates HEADERS + CONTINUATION until END_HEADERS
	headers     map[string]string
	body        bytes.Buffer
	haveHeaders bool
	endStream   bool
	emitted     bool
}

// h2Parser consumes a connection-direction's framed byte stream and emits a
// Message per h2 stream that reaches END_STREAM.
type h2Parser struct {
	direction   string
	dec         *hpack.Decoder
	buf         bytes.Buffer
	streams     map[uint32]*h2Stream
	prefaceDone bool
	// A header block (HEADERS+CONTINUATION) must be a contiguous frame run on one
	// stream; track which stream is mid-block to route CONTINUATION frames.
	openHeaderStream uint32
	inHeaderBlock    bool
}

func newH2Parser(direction string) *h2Parser {
	return &h2Parser{
		direction: direction,
		dec:       hpack.NewDecoder(4096, nil),
		streams:   map[uint32]*h2Stream{},
	}
}

func (p *h2Parser) stream(id uint32) *h2Stream {
	s := p.streams[id]
	if s == nil {
		s = &h2Stream{headers: map[string]string{}}
		p.streams[id] = s
	}
	return s
}

// consume appends data and returns every stream that completed (END_STREAM).
func (p *h2Parser) consume(data []byte, pid uint32, conn uint64) []Message {
	p.buf.Write(data)
	if !p.prefaceDone && p.direction == Request {
		b := p.buf.Bytes()
		if bytes.HasPrefix(b, []byte(h2ClientPreface)) {
			rest := append([]byte(nil), b[len(h2ClientPreface):]...)
			p.buf.Reset()
			p.buf.Write(rest)
			p.prefaceDone = true
		} else if len(b) < len(h2ClientPreface) && bytes.HasPrefix([]byte(h2ClientPreface), b) {
			return nil // preface still arriving
		} else {
			p.prefaceDone = true // no preface (mid-connection capture); parse frames as-is
		}
	}

	var out []Message
	for {
		b := p.buf.Bytes()
		if len(b) < 9 {
			break
		}
		length := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		ftype := b[3]
		flags := b[4]
		streamID := binary.BigEndian.Uint32(b[5:9]) & 0x7fffffff
		if len(b) < 9+length {
			break // payload not fully arrived
		}
		payload := append([]byte(nil), b[9:9+length]...)
		rest := append([]byte(nil), b[9+length:]...)
		p.buf.Reset()
		p.buf.Write(rest)

		if msg, ok := p.handleFrame(ftype, flags, streamID, payload, pid, conn); ok {
			out = append(out, msg)
		}
	}
	return out
}

func (p *h2Parser) handleFrame(ftype, flags byte, streamID uint32, payload []byte, pid uint32, conn uint64) (Message, bool) {
	switch ftype {
	case h2FrameHeaders:
		frag := payload
		if flags&h2FlagPadded != 0 {
			if len(frag) < 1 {
				return Message{}, false
			}
			pad := int(frag[0])
			frag = frag[1:]
			if pad > len(frag) {
				return Message{}, false
			}
			frag = frag[:len(frag)-pad]
		}
		if flags&h2FlagPriority != 0 {
			if len(frag) < 5 {
				return Message{}, false
			}
			frag = frag[5:]
		}
		st := p.stream(streamID)
		st.headerBlock.Write(frag)
		if flags&h2FlagEndStream != 0 {
			st.endStream = true
		}
		if flags&h2FlagEndHeaders != 0 {
			p.decodeHeaders(st)
			return p.maybeEmit(streamID, pid, conn)
		}
		p.inHeaderBlock = true
		p.openHeaderStream = streamID
		return Message{}, false

	case h2FrameContinuation:
		if !p.inHeaderBlock || streamID != p.openHeaderStream {
			return Message{}, false
		}
		st := p.stream(streamID)
		st.headerBlock.Write(payload)
		if flags&h2FlagEndHeaders != 0 {
			p.inHeaderBlock = false
			p.decodeHeaders(st)
			return p.maybeEmit(streamID, pid, conn)
		}
		return Message{}, false

	case h2FrameData:
		body := payload
		if flags&h2FlagPadded != 0 {
			if len(body) < 1 {
				return Message{}, false
			}
			pad := int(body[0])
			body = body[1:]
			if pad > len(body) {
				return Message{}, false
			}
			body = body[:len(body)-pad]
		}
		st := p.stream(streamID)
		st.body.Write(body)
		if flags&h2FlagEndStream != 0 {
			st.endStream = true
		}
		return p.maybeEmit(streamID, pid, conn)

	default:
		return Message{}, false // SETTINGS/PING/WINDOW_UPDATE/RST_STREAM/etc.
	}
}

func (p *h2Parser) decodeHeaders(st *h2Stream) {
	hf, err := p.dec.DecodeFull(st.headerBlock.Bytes())
	st.headerBlock.Reset()
	if err != nil {
		return
	}
	for _, f := range hf {
		st.headers[f.Name] = f.Value
	}
	st.haveHeaders = true
}

func (p *h2Parser) maybeEmit(streamID uint32, pid uint32, conn uint64) (Message, bool) {
	st := p.streams[streamID]
	if st == nil || st.emitted || !st.haveHeaders || !st.endStream {
		return Message{}, false
	}
	st.emitted = true
	msg := Message{
		PID:       pid,
		Conn:      conn,
		Direction: p.direction,
		Protocol:  ProtoH2,
		Headers:   map[string]string{},
		Body:      append([]byte(nil), st.body.Bytes()...),
	}
	for name, val := range st.headers {
		switch name {
		case ":method":
			msg.Method = val
		case ":path":
			msg.Path = val
		case ":authority":
			msg.Host = val
		case ":status":
			msg.Status = atoiSafe(val)
		default:
			msg.Headers[name] = val
		}
	}
	if msg.Method != "" || msg.Path != "" {
		msg.Direction = Request
	} else if msg.Status != 0 {
		msg.Direction = Response
	}
	finalizeSemantics(&msg)
	delete(p.streams, streamID)
	return msg, true
}

// flush emits best-effort Messages for streams that received headers but no
// END_STREAM (e.g. a connection closed mid-response). Marked truncated.
func (p *h2Parser) flush(pid uint32, conn uint64) []Message {
	var out []Message
	for id, st := range p.streams {
		if st.emitted || !st.haveHeaders {
			continue
		}
		st.endStream = true
		if msg, ok := p.maybeEmit(id, pid, conn); ok {
			msg.Truncated = true
			out = append(out, msg)
		}
	}
	return out
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
