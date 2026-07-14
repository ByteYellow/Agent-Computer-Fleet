#!/usr/bin/env python3
"""
Capturing + BLOCKING proxy for the Grok exfil demo — the axis-2 capture point AND the
enforcement point. Grok is pointed here via XAI_API_BASE_URL (plain http, so we see
plaintext; Grok is rustls so a libssl uprobe can't). We:

  - FORWARD chat/auth/models/responses to the REAL api.x.ai (with the real key) and
    stream the response back, so Grok works normally and reads/context-builds for real.
  - Optionally force the data-retention/ZDR config response to "upload enabled" so the
    codebase upload fires regardless of the account (UPSTREAM account type doesn't matter).
  - BLOCK the codebase egress (/v1/upload/storage, /v1/traces): do NOT forward it, dump
    the body (the git bundle) as evidence, return a benign 200 so Grok doesn't error.
    This is the AgentProvenance DENY response enacted at the network boundary.
  - DUMP every request + response so the endpoint adapter can ingest them into the graph.

Env:
  PORT (8088)  UPSTREAM (https://api.x.ai)  XAI_API_KEY (real, for forwarding)
  DUMP_DIR (./proxy-dump)  CANARY_FILE  FORCE_UPLOAD=1 (rewrite config to upload-on)
  BLOCK_UPLOAD=1 (default; set 0 to observe-only without blocking)
"""
import json, os, ssl, sys, time, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8088"))
UPSTREAM = os.environ.get("UPSTREAM", "https://api.x.ai").rstrip("/")
KEY = os.environ.get("XAI_API_KEY", "")
DUMP = os.environ.get("DUMP_DIR", os.path.join(os.getcwd(), "proxy-dump"))
BLOCK_UPLOAD = os.environ.get("BLOCK_UPLOAD", "1") == "1"
FORCE_UPLOAD = os.environ.get("FORCE_UPLOAD", "0") == "1"
os.makedirs(DUMP, exist_ok=True)
CANARIES = open(os.environ["CANARY_FILE"]).read().split() if os.environ.get("CANARY_FILE") and os.path.exists(os.environ.get("CANARY_FILE", "")) else []
_seq = [0]

# Codebase/session-trace egress paths -> BLOCK (this is the exfil we prevent).
EXFIL_PATHS = ("/v1/upload/storage", "/v1/upload", "/v1/traces")


def _record(kind, method, path, body, extra=""):
    _seq[0] += 1
    n = _seq[0]
    safe = "".join(c if c.isalnum() else "_" for c in path)[:50]
    with open(os.path.join(DUMP, f"{n:03d}_{kind}_{safe}.body.bin"), "wb") as f:
        f.write(body or b"")
    with open(os.path.join(DUMP, f"{n:03d}_{kind}_{safe}.meta.json"), "w") as f:
        json.dump({"seq": n, "kind": kind, "method": method, "path": path,
                   "size": len(body or b"")}, f)
    hits = [c for c in CANARIES if c and c.encode() in (body or b"")]
    bundle = (body or b"")[:64].find(b"git bundle") >= 0 or (body or b"")[:4].startswith(b"PACK")
    tag = "  [git-bundle]" if bundle else ""
    flag = f"  !! CANARIES: {hits}" if hits else ""
    print(f"[{time.strftime('%H:%M:%S')}] {kind:10s} {method} {path}  {len(body or b'')}B{tag}{flag}{extra}", flush=True)


def _is_exfil(path):
    p = path.lower()
    return "/upload" in p or "/traces" in p or "/storage" in p


# SuperGrok CLI backend is https://cli-chat-proxy.grok.com and its paths
# (/settings, /bundle/archive, /chat/completions, /traces, ...) are already the real
# upstream paths -- pass through unchanged. (The api.x.ai/v1 developer API is a
# different topology; V1_PREFIX=1 restores /v1-prepending if forwarding there.)
def _upstream_path(path):
    if os.environ.get("V1_PREFIX", "0") == "1" and not path.startswith("/v1") and not path.startswith("/rest"):
        return "/v1" + path
    return path


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _read_body(self):
        n = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(n) if n else b""

    def _forward(self, method, body):
        url = UPSTREAM + _upstream_path(self.path)
        req = urllib.request.Request(url, data=body if body else None, method=method)
        for k, v in self.headers.items():
            if k.lower() in ("host", "content-length", "connection", "accept-encoding"):
                continue
            req.add_header(k, v)
        # Ask upstream for uncompressed responses so we can read/rewrite config JSON
        # (the VM has no brotli decoder).
        req.add_header("Accept-Encoding", "identity")
        if KEY:
            req.add_header("Authorization", f"Bearer {KEY}")
        ctx = ssl.create_default_context()
        try:
            up = urllib.request.urlopen(req, context=ctx, timeout=180)
        except urllib.error.HTTPError as e:
            up = e
        status = getattr(up, "status", 200) or 200
        ctype = up.headers.get("Content-Type", "")
        streamed = "text/event-stream" in ctype.lower()
        if streamed:
            # SSE (chat): pass chunks straight through so grok's streaming client
            # works; accumulate a copy for the endpoint adapter. No Content-Length;
            # close the connection to signal end-of-stream.
            self.send_response(status)
            for k, v in up.headers.items():
                if k.lower() in ("transfer-encoding", "content-length", "connection"):
                    continue
                self.send_header(k, v)
            self.close_connection = True
            self.end_headers()
            acc = bytearray()
            while True:
                chunk = up.read(4096)
                if not chunk:
                    break
                acc += chunk
                try:
                    self.wfile.write(chunk)
                    self.wfile.flush()
                except Exception:
                    break
            _record("resp", method, self.path, bytes(acc))
            return
        resp = up.read()
        # DISCLOSED force: xAI's server sets trace_upload_enabled=false /
        # disable_codebase_upload=true for this account. To demonstrate the exfil
        # mechanism (and that AgentProvenance blocks it), flip those flags in the
        # /settings response so grok proceeds to bundle+upload the codebase. We do
        # NOT hide this -- the original server values are logged.
        if FORCE_UPLOAD and "/settings" in self.path:
            try:
                j = json.loads(resp)
                before = {k: j.get(k) for k in ("trace_upload_enabled", "disable_codebase_upload", "non_git_workspace_capture")}
                j["trace_upload_enabled"] = True
                j["disable_codebase_upload"] = False
                j["non_git_workspace_capture"] = True
                resp = json.dumps(j).encode()
                print(f"           >>> FORCED codebase-upload ON (server had {before}) — DISCLOSED", flush=True)
            except Exception:
                pass
        _record("resp", method, self.path, resp)
        self.send_response(status)
        for k, v in up.headers.items():
            if k.lower() in ("transfer-encoding", "content-length", "connection"):
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def _handle(self, method):
        body = self._read_body()
        if _is_exfil(self.path):
            _record("EXFIL-REQ", method, self.path, body, extra="")
            if BLOCK_UPLOAD:
                # AgentProvenance DENY: do not forward the codebase upload.
                print(f"           >>> BLOCKED codebase egress to {self.path} "
                      f"({len(body)}B) — AgentProvenance policy: DENY", flush=True)
                self.send_response(200)
                data = json.dumps({"ok": True, "id": "accepted"}).encode()
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
        else:
            _record("req", method, self.path, body)
        self._forward(method, body)

    def do_POST(self):
        self._handle("POST")

    def do_GET(self):
        _record("req", "GET", self.path, b"")
        self._forward("GET", b"")

    do_PUT = do_POST
    do_PATCH = do_POST


if __name__ == "__main__":
    print(f"grok-proxy on :{PORT} -> {UPSTREAM}  block_upload={BLOCK_UPLOAD} "
          f"force_retention={FORCE_UPLOAD} key={'set' if KEY else 'MISSING'} dump={DUMP}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
