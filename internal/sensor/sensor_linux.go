//go:build linux

package sensor

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/byteyellow/agentprovenance/internal/tlsintent"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	eventExec    = 1
	eventConnect = 2
	eventOpen    = 3
	eventExit    = 4
	eventSSL     = 5
	eventSSLRead = 6
	eventSetuid  = 7
	eventPtrace  = 8
	eventRename  = 9
	eventUnlink  = 10
	eventDNS     = 11
)

// Options configures optional sensor probes beyond the always-on syscall set.
type Options struct {
	// SSLLib, when set, attaches SSL_write/read and SSL_write_ex/read_ex uprobes
	// to this libssl path to capture TLS plaintext zero-instrumentation.
	SSLLib string
	// LibcLib overrides the libc path for the getaddrinfo DNS uprobe; empty =
	// auto-detect the common system libc paths.
	LibcLib string
	// GoTLSBin, when set, attaches a uprobe to crypto/tls.(*Conn).Write in this Go
	// binary to capture the request/prompt plaintext for Go agents, which use Go's
	// own TLS (no libssl for the SSLLib uprobes to hook). Best-effort: a stripped
	// binary (-ldflags "-s -w") has no symbol to attach.
	GoTLSBin string
	// OnReady, when set, is called exactly once after every probe has attached
	// and the ring buffer reader is open -- i.e. the sensor is genuinely capturing
	// and the caller may safely start the workload it wants observed. Supervisors
	// (launch) gate their exec on this to avoid racing a fast agent past a
	// not-yet-attached sensor. Callable from a goroutine; keep it non-blocking.
	OnReady func()
}

// RunWithOptions loads the configured eBPF probes and writes normalized JSONL
// telemetry until SIGINT/SIGTERM. It requires root or CAP_BPF + CAP_PERFMON.
func RunWithOptions(out io.Writer, opts Options) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	var objs sensorbpfObjects
	if err := loadSensorbpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer objs.Close()

	tpExec, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
	if err != nil {
		return fmt.Errorf("attach sched_process_exec: %w", err)
	}
	defer tpExec.Close()
	tpExecve, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		return fmt.Errorf("attach sys_enter_execve: %w", err)
	}
	defer tpExecve.Close()
	tpConnect, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.HandleConnect, nil)
	if err != nil {
		return fmt.Errorf("attach sys_enter_connect: %w", err)
	}
	defer tpConnect.Close()
	tpOpen, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleOpenat, nil)
	if err != nil {
		return fmt.Errorf("attach sys_enter_openat: %w", err)
	}
	defer tpOpen.Close()
	tpExit, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleExit, nil)
	if err != nil {
		return fmt.Errorf("attach sched_process_exit: %w", err)
	}
	defer tpExit.Close()
	// Privilege-change / tamper probes (privesc + file rename/delete). Each is a
	// simple syscall tracepoint; attach failures are non-fatal so an older kernel
	// missing one tracepoint still runs the rest.
	for _, p := range []struct {
		group, name string
		prog        *ebpf.Program
	}{
		{"syscalls", "sys_enter_setuid", objs.HandleSetuid},
		{"syscalls", "sys_enter_setgid", objs.HandleSetgid},
		{"syscalls", "sys_enter_ptrace", objs.HandlePtrace},
		{"syscalls", "sys_enter_renameat2", objs.HandleRename},
		{"syscalls", "sys_enter_renameat", objs.HandleRename},
		{"syscalls", "sys_enter_rename", objs.HandleRenamePlain},
		{"syscalls", "sys_enter_unlinkat", objs.HandleUnlink},
		{"syscalls", "sys_enter_sendto", objs.HandleSendto}, // universal DNS (UDP:53)
	} {
		if tp, err := link.Tracepoint(p.group, p.name, p.prog, nil); err == nil {
			defer tp.Close()
		}
	}
	if opts.SSLLib != "" {
		ex, err := link.OpenExecutable(opts.SSLLib)
		if err != nil {
			return fmt.Errorf("open ssl lib %s: %w", opts.SSLLib, err)
		}

		var attachErrs []string
		attachedWrite := false
		if up, err := ex.Uprobe("SSL_write", objs.HandleSslWrite, nil); err == nil {
			defer up.Close()
			attachedWrite = true
		} else {
			attachErrs = append(attachErrs, "SSL_write: "+err.Error())
		}
		if up, err := ex.Uprobe("SSL_write_ex", objs.HandleSslWriteEx, nil); err == nil {
			defer up.Close()
			attachedWrite = true
		} else {
			attachErrs = append(attachErrs, "SSL_write_ex: "+err.Error())
		}

		attachedRead := false
		if upEnter, err := ex.Uprobe("SSL_read", objs.HandleSslReadEnter, nil); err == nil {
			if upExit, err := ex.Uretprobe("SSL_read", objs.HandleSslReadExit, nil); err == nil {
				defer upEnter.Close()
				defer upExit.Close()
				attachedRead = true
			} else {
				upEnter.Close()
				attachErrs = append(attachErrs, "SSL_read return: "+err.Error())
			}
		} else {
			attachErrs = append(attachErrs, "SSL_read: "+err.Error())
		}

		if upEnter, err := ex.Uprobe("SSL_read_ex", objs.HandleSslReadExEnter, nil); err == nil {
			if upExit, err := ex.Uretprobe("SSL_read_ex", objs.HandleSslReadExExit, nil); err == nil {
				defer upEnter.Close()
				defer upExit.Close()
				attachedRead = true
			} else {
				upEnter.Close()
				attachErrs = append(attachErrs, "SSL_read_ex return: "+err.Error())
			}
		} else {
			attachErrs = append(attachErrs, "SSL_read_ex: "+err.Error())
		}

		if !attachedWrite || !attachedRead {
			return fmt.Errorf("attach OpenSSL TLS uprobes on %s: write=%v read=%v (%s)", opts.SSLLib, attachedWrite, attachedRead, strings.Join(attachErrs, "; "))
		}
		// A partial attach is non-fatal but silently loses a direction (e.g. a
		// client that only calls SSL_read_ex would go dark if its return probe
		// failed while SSL_read's succeeded). Surface it so it isn't a mystery.
		if len(attachErrs) > 0 {
			fmt.Fprintf(os.Stderr, "agentprov-sensor: partial TLS uprobe attach on %s: %s\n", opts.SSLLib, strings.Join(attachErrs, "; "))
		}
	}

	// Go crypto/tls: Go agents use Go's own TLS stack (no libssl), so the SSLLib
	// uprobes never fire for them. crypto/tls.(*Conn).Write(b []byte) holds the
	// request/prompt plaintext in b at entry; on the arm64 ABIInternal the
	// receiver is x0 and the slice ptr/len land in x1/x2 -- exactly the registers
	// handle_ssl_write reads as (ssl, buf, num), so we reuse that program. Entry
	// uprobe only (the request path); no uretprobe, since Go's moving goroutine
	// stacks make return probes unsafe. Best-effort and non-fatal: a stripped
	// binary exposes no symbol to attach.
	if opts.GoTLSBin != "" {
		if ex, err := link.OpenExecutable(opts.GoTLSBin); err != nil {
			fmt.Fprintf(os.Stderr, "agentprov-sensor: open go-tls bin %s: %v\n", opts.GoTLSBin, err)
		} else if up, err := ex.Uprobe("crypto/tls.(*Conn).Write", objs.HandleSslWrite, nil); err != nil {
			fmt.Fprintf(os.Stderr, "agentprov-sensor: go-tls uprobe not attached (%v; stripped binary?)\n", err)
		} else {
			defer up.Close()
		}
	}

	// DNS uprobe on the system libc's getaddrinfo (best-effort, non-fatal): gives
	// egress the resolved HOSTNAME, not just the IP. Glibc apps only.
	for _, libc := range libcCandidates(opts.LibcLib) {
		ex, err := link.OpenExecutable(libc)
		if err != nil {
			continue
		}
		if up, err := ex.Uprobe("getaddrinfo", objs.HandleGetaddrinfo, nil); err == nil {
			defer up.Close()
			break
		}
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("open ringbuf: %w", err)
	}
	defer rd.Close()

	// All probes are attached and the ring buffer is open: the sensor is now
	// genuinely capturing. Signal readiness so a supervisor can start its
	// workload without racing a not-yet-attached sensor.
	if opts.OnReady != nil {
		opts.OnReady()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
	}()

	resolver := newCgroupResolver()
	enc := json.NewEncoder(out)
	var encMu sync.Mutex
	emit := func(v any) {
		encMu.Lock()
		_ = enc.Encode(v)
		encMu.Unlock()
	}

	// Surface ring-buffer drops as a coverage-gap event so a loaded sensor is
	// never silently blind.
	done := make(chan struct{})
	defer close(done)
	go watchDrops(objs.Drops, emit, done)

	// The SSL_write/read probes emit ordered TLS-plaintext chunks; reassemble them
	// into complete HTTP/1.1 or HTTP/2/HPACK request/response messages before
	// emitting.
	reasm := tlsintent.NewReassembler()
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			continue
		}
		var e sensorbpfSensorEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}
		if e.Kind == eventSSL || e.Kind == eventSSLRead {
			dir := tlsintent.Request
			if e.Kind == eventSSLRead {
				dir = tlsintent.Response
			}
			n := int(e.Daddr) // valid bytes in this chunk's path[]
			if n < 0 || n > len(e.Path) {
				n = len(e.Path)
			}
			for _, msg := range reasm.Add(tlsintent.Chunk{
				PID: e.Pid, Conn: e.Conn, Direction: dir,
				Data: append([]byte(nil), e.Path[:n]...), Truncated: e.Dport == 1,
			}) {
				emit(tlsMessageMap(msg, e, resolver))
			}
			continue
		}
		if m := normalize(e, resolver); m != nil {
			emit(m)
		}
	}
}

// tlsMessageMap turns a reassembled HTTP/1.1 LLM message into the normalized
// event map, reusing the last chunk's process/cgroup context.
func tlsMessageMap(msg tlsintent.Message, e sensorbpfSensorEvent, resolver *cgroupResolver) map[string]any {
	containerID := resolver.resolve(e.CgroupId)
	if containerID == "" {
		containerID = containerIDForPID(e.Pid)
	}
	etype := "tls_write"
	if msg.Direction == tlsintent.Response {
		etype = "tls_read"
	}
	ev := map[string]any{
		"source":       "agentprov_ebpf",
		"pid":          e.Pid,
		"tgid":         e.Tgid,
		"ppid":         e.Ppid,
		"cgroup_id":    strconv.FormatUint(e.CgroupId, 10),
		"container_id": containerID,
		"timestamp":    time.Now().UTC().Format(time.RFC3339Nano),
		"comm":         cstr(e.Comm[:]),
		"event_type":   etype,
		"data":         string(msg.Body),
		"length":       len(msg.Body),
		"protocol":     msg.Protocol,
	}
	if msg.Truncated {
		ev["truncated"] = true
	}
	if msg.Model != "" {
		ev["model"] = msg.Model
	}
	if msg.Endpoint != "" {
		ev["endpoint"] = msg.Endpoint
	}
	if msg.Direction == tlsintent.Request {
		ev["method"], ev["path"], ev["host"] = msg.Method, msg.Path, msg.Host
	} else {
		ev["status"] = msg.Status
	}
	return ev
}

// watchDrops polls the kernel drop counter and emits a resource_pressure event
// whenever it grows, so downstream sees a coverage gap rather than missing data.
func watchDrops(m dropLookuper, emit func(any), done <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var last uint64
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			var n uint64
			if err := m.Lookup(uint32(0), &n); err != nil || n <= last {
				continue
			}
			emit(map[string]any{
				"source":        "agentprov_ebpf",
				"event_type":    "resource_pressure",
				"resource":      "sensor_ringbuf",
				"signal":        "event_drop",
				"dropped":       n,
				"dropped_delta": n - last,
				"timestamp":     time.Now().UTC().Format(time.RFC3339Nano),
			})
			last = n
		}
	}
}

// dropLookuper is the subset of *ebpf.Map used to read the drop counter (kept as
// an interface so the poller is unit-testable without a live map).
type dropLookuper interface {
	Lookup(key, valueOut any) error
}

// cgroupResolver maps the kernel-reported cgroup id (race-free, captured in
// kernel via bpf_get_current_cgroup_id) to a container id by directory inode.
// The container's cgroup directory outlives its short-lived processes, so this
// survives a process whose /proc entry is already gone by the time userspace
// drains the ring buffer - the failure mode of the previous /proc-only lookup.
type cgroupResolver struct {
	root            string
	mu              sync.RWMutex
	refreshMu       sync.Mutex
	byID            map[uint64]string
	lastRefresh     time.Time
	refreshInterval time.Duration
}

func newCgroupResolver() *cgroupResolver {
	return &cgroupResolver{
		root: "/sys/fs/cgroup", byID: map[uint64]string{},
		refreshInterval: time.Second,
	}
}

// resolve returns the container id for a kernel cgroup id, refreshing the cache
// once on a miss (a newly seen container's cgroup dir appears between scans).
func (r *cgroupResolver) resolve(cgroupID uint64) string {
	if cgroupID == 0 {
		return ""
	}
	r.mu.RLock()
	id, ok := r.byID[cgroupID]
	r.mu.RUnlock()
	if ok {
		return id
	}
	r.refreshIfDue()
	r.mu.RLock()
	id = r.byID[cgroupID]
	r.mu.RUnlock()
	return id
}

// refreshIfDue bounds hierarchy scans. A node-wide sensor sees many host
// cgroups that can never map to a container; rescanning the complete hierarchy
// for every such event stalls ring-buffer consumption under normal K8s host
// activity. Unknown ids use the live /proc fallback until the next refresh.
func (r *cgroupResolver) refreshIfDue() {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	interval := r.refreshInterval
	if interval <= 0 {
		interval = time.Second
	}
	r.mu.RLock()
	last := r.lastRefresh
	r.mu.RUnlock()
	if !last.IsZero() && time.Since(last) < interval {
		return
	}
	r.refresh()
}

// refresh walks the cgroup v2 hierarchy and maps each container cgroup
// directory's inode (== the kernel cgroup id) to the 64-hex container id parsed
// from its name (docker-<id>.scope, cri-containerd-<id>.scope, kubepods/<id>...).
func (r *cgroupResolver) refresh() {
	next := map[uint64]string{}
	_ = filepath.WalkDir(r.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		m := dockerCgroupRe.FindString(d.Name())
		if m == "" {
			return nil
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			next[uint64(st.Ino)] = m
		}
		return nil
	})
	r.mu.Lock()
	r.byID = next
	r.lastRefresh = time.Now()
	r.mu.Unlock()
}

// normalize maps a raw kernel event to the normalized telemetry schema consumed
// by `telemetry ingest` (container_id, cgroup_id, pid/tgid/ppid, source,
// event_type, payload). container_id is best-effort from /proc/<pid>/cgroup.
func normalize(e sensorbpfSensorEvent, resolver *cgroupResolver) map[string]any {
	// Prefer the race-free cgroup-id -> container-id resolution; the /proc lookup
	// is a fallback for the live process and for hosts where the cgroup dir name
	// does not carry the id.
	containerID := resolver.resolve(e.CgroupId)
	if containerID == "" {
		containerID = containerIDForPID(e.Pid)
	}
	ev := map[string]any{
		"source":       "agentprov_ebpf",
		"pid":          e.Pid,
		"tgid":         e.Tgid,
		"ppid":         e.Ppid,
		"cgroup_id":    strconv.FormatUint(e.CgroupId, 10),
		"container_id": containerID,
		"timestamp":    time.Now().UTC().Format(time.RFC3339Nano),
		"comm":         cstr(e.Comm[:]),
	}
	switch e.Kind {
	case eventExec:
		ev["event_type"] = "execve"
		ev["path"] = cstr(e.Path[:])
		if command := joinArgs(e.Args[:]); command != "" {
			ev["command"] = command
		}
	case eventConnect:
		ev["event_type"] = "network_connect"
		ev["dst_ip"] = ipv4(e.Daddr)
		ev["dst_port"] = ntohs(e.Dport)
	case eventOpen:
		path := cstr(e.Path[:])
		mode := "write"
		if e.ExitCode == 1 {
			mode = "read"
		}
		// The kernel already dropped noise-prefix reads; here we keep only
		// sensitive reads (writes always pass). Non-sensitive reads are dropped
		// so the store stays focused on credential/secret access.
		if mode == "read" && !sensitiveReadPath(path) {
			return nil
		}
		ev["event_type"] = "file_open"
		ev["path"] = path
		ev["mode"] = mode
	case eventExit:
		ev["event_type"] = "process_exit"
		ev["exit_code"] = e.ExitCode
	case eventSetuid:
		if e.Daddr == 1 {
			ev["event_type"] = "setgid"
			ev["gid"] = e.ExitCode
		} else {
			ev["event_type"] = "setuid"
			ev["uid"] = e.ExitCode
		}
	case eventPtrace:
		ev["event_type"] = "ptrace"
		ev["request"] = e.ExitCode
		ev["target_pid"] = e.Daddr
	case eventRename:
		ev["event_type"] = "file_rename"
		ev["path"] = cstr(e.Path[:])
	case eventUnlink:
		ev["event_type"] = "file_unlink"
		ev["path"] = cstr(e.Path[:])
	case eventDNS:
		ev["event_type"] = "dns_query"
		if e.ExitCode > 0 {
			// raw DNS query bytes (UDP path); parse the qname
			n := int(e.ExitCode)
			if n > len(e.Path) {
				n = len(e.Path)
			}
			ev["host"] = dnsQName(e.Path[:n])
		} else {
			ev["host"] = cstr(e.Path[:]) // getaddrinfo hostname (string)
		}
	case eventSSL:
		ev["event_type"] = "tls_write"
		ev["data"] = cstr(e.Path[:]) // plaintext preview (first path[] bytes)
		ev["length"] = e.ExitCode
	case eventSSLRead:
		ev["event_type"] = "tls_read"
		ev["data"] = cstr(e.Path[:])
		ev["length"] = e.ExitCode
	default:
		ev["event_type"] = "unknown"
	}
	return ev
}

// sensitiveReadPath positively matches the small set of paths whose READ is
// security-relevant (credential/secret/key files). The kernel forwards reads
// coarsely (noise prefixes dropped); this is the precise filter that decides
// which reads reach the store. Mirrors the policy engine's secret patterns and
// adds key/cred file markers.
func sensitiveReadPath(p string) bool {
	for _, s := range []string{
		".ssh", ".aws", "id_rsa", "id_ed25519", "credentials", ".env",
		"secret", "/etc/shadow", "/etc/passwd", ".pem", ".kube/config", "_token",
	} {
		if strings.Contains(p, s) {
			return true
		}
	}
	return false
}

// libcCandidates returns libc paths to try for the getaddrinfo uprobe: the
// explicit override first, then the common multiarch/system locations.
func libcCandidates(override string) []string {
	c := []string{}
	if override != "" {
		c = append(c, override)
	}
	return append(c,
		"/lib/aarch64-linux-gnu/libc.so.6",
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/lib/libc.so.6",
		"/lib/libc.so.6",
	)
}

// dnsQName parses the question name from a raw DNS query message (12-byte header
// then length-prefixed labels) into a dotted hostname, or "" if malformed.
func dnsQName(b []uint8) string {
	if len(b) < 13 {
		return ""
	}
	i := 12
	var sb strings.Builder
	for i < len(b) {
		l := int(b[i])
		i++
		if l == 0 {
			break
		}
		if l > 63 || i+l > len(b) {
			return ""
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		for j := 0; j < l; j++ {
			c := b[i+j]
			if c < 0x20 || c > 0x7e {
				return "" // not a printable hostname
			}
			sb.WriteByte(byte(c))
		}
		i += l
	}
	if sb.Len() == 0 {
		return ""
	}
	return sb.String()
}

// dockerCgroupRe extracts a 64-hex container id from a cgroup path line.
var dockerCgroupRe = regexp.MustCompile(`[0-9a-f]{64}`)

func containerIDForPID(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	if m := dockerCgroupRe.Find(data); m != nil {
		return string(m)
	}
	return ""
}

func ipv4(addr uint32) string {
	// addr is network byte order (big-endian) as read from the kernel.
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, addr)
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

func ntohs(p uint16) uint16 {
	return (p<<8)&0xff00 | p>>8
}

// joinArgs rejoins the fixed-size argv slots emitted by the eBPF side (MAX_ARGS
// slots of ARG_SLOT bytes, each a NUL-terminated, possibly truncated arg) into a
// single space-separated command line, stopping at the first empty slot. These
// constants must match exec.c (ARG_SLOT, MAX_ARGS).
func joinArgs(b []uint8) string {
	const slot = 32
	const maxArgs = 16
	parts := make([]string, 0, maxArgs)
	for i := 0; i < maxArgs; i++ {
		start := i * slot
		if start >= len(b) {
			break
		}
		end := start + slot
		if end > len(b) {
			end = len(b)
		}
		s := cstr(b[start:end])
		if s == "" {
			break
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

func cstr(b []uint8) string {
	if i := bytes.IndexByte(byteSlice(b), 0); i >= 0 {
		b = b[:i]
	}
	return string(byteSlice(b))
}

func byteSlice(b []uint8) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = byte(v)
	}
	return out
}
