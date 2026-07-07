//go:build ignore

// eBPF programs for the self-owned system-telemetry sensor (CO-RE, compiled by
// bpf2go with clang). Three probes -> one ring buffer:
//   - sched_process_exec   -> execve
//   - sys_enter_connect     -> network_connect (AF_INET)
//   - sys_enter_openat      -> file_open
// Each event carries pid/tgid/ppid/comm + the kernel cgroup id; the userspace
// loader (sensor_linux.go) enriches container_id from /proc/<pid>/cgroup and
// maps to the normalized telemetry schema. Linux-only.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
// PoC SSL uprobe arg extraction needs PT_REGS; arm64 is the lab target. Register
// layout is arch-specific, so a future multi-arch build must set this per arch.
#ifndef __TARGET_ARCH_arm64
#define __TARGET_ARCH_arm64
#endif
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EVENT_EXEC 1
#define EVENT_CONNECT 2
#define EVENT_OPEN 3
#define EVENT_EXIT 4
#define EVENT_SSL 5      // SSL_write: plaintext the agent sent (LLM request)
#define EVENT_SSL_READ 6 // SSL_read: plaintext the agent received (LLM response)
#define EVENT_SETUID 7   // setuid/setgid: privilege change (daddr: 0=uid,1=gid)
#define EVENT_PTRACE 8   // ptrace: process injection/inspection
#define EVENT_RENAME 9   // renameat2: file move/tamper
#define EVENT_UNLINK 10  // unlinkat: file delete
#define EVENT_DNS 11     // getaddrinfo uprobe: resolved hostname (egress by name)
#define AF_INET 2

// argv is captured as fixed-size slots (constant offsets keep the BPF verifier
// happy on the per-arg write); each slot holds one NUL-terminated, possibly
// truncated arg. Userspace rejoins non-empty slots with spaces.
#define ARG_SLOT 32
#define MAX_ARGS 16
#define ARGS_BUF (ARG_SLOT * MAX_ARGS)
#define SSL_CHUNK 256      // bytes captured per TLS chunk (= sizeof path[])
#define SSL_MAX_CHUNKS 16  // cap: up to SSL_CHUNK*SSL_MAX_CHUNKS bytes per SSL call

struct sensor_event {
	__u32 kind;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u64 cgroup_id;
	__u64 conn;      // tls: the SSL* pointer identifying the connection (reassembly key)
	__u32 daddr;     // connect: dst IPv4 (net order); tls: valid bytes in this chunk
	__u16 dport;     // connect: dst port (net order); tls: 1 if the message was truncated at the chunk cap
	__s32 exit_code; // exit: process exit code; tls: total plaintext length of the call
	__u8 comm[16];
	__u8 path[256];      // exec filename / open path
	__u8 args[ARGS_BUF]; // exec: MAX_ARGS fixed slots of argv
};

// drops counts ring-buffer reservation failures, so userspace can surface a
// coverage gap instead of going silently blind under load.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

static __always_inline void count_drop(void) {
	__u32 z = 0;
	__u64 *d = bpf_map_lookup_elem(&drops, &z);
	if (d)
		__sync_fetch_and_add(d, 1);
}

// argv_scratch stashes a process's argv (captured at sys_enter_execve) keyed by
// pid, so the successful sched_process_exec emit can attach the real command
// line. exec doesn't change the pid between the two probes.
struct argv_val {
	__u8 args[ARGS_BUF];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct argv_val);
} argv_scratch SEC(".maps");

// Per-CPU scratch to build argv off the 512-byte BPF stack.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct argv_val);
} argv_build SEC(".maps");

// Force bpf2go to emit the Go struct type for sensor_event.
struct sensor_event *unused_sensor_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline void fill_common(struct sensor_event *e) {
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 id = bpf_get_current_pid_tgid();
	e->pid = (__u32)(id >> 32);
	e->tgid = (__u32)id;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// Capture argv at execve entry into the per-pid scratch map. The space-joined
// command line is attached on the matching successful sched_process_exec.
SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
	__u32 zero = 0;
	struct argv_val *val = bpf_map_lookup_elem(&argv_build, &zero);
	if (!val)
		return 0;
	__builtin_memset(val->args, 0, sizeof(val->args));
	const char *const *argv = (const char *const *)ctx->args[1];
#pragma unroll
	for (int i = 0; i < MAX_ARGS; i++) {
		const char *argp = NULL;
		if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) || !argp)
			break;
		// Constant offset (i unrolled) and constant size -> verifier-safe.
		bpf_probe_read_user_str(&val->args[i * ARG_SLOT], ARG_SLOT, argp);
	}
	__u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	bpf_map_update_elem(&argv_scratch, &pid, val, BPF_ANY);
	return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->exit_code = 0;
	e->kind = EVENT_EXEC;
	e->daddr = 0;
	e->dport = 0;
	fill_common(e);
	unsigned int off = ctx->__data_loc_filename & 0xffff;
	bpf_probe_read_kernel_str(&e->path, sizeof(e->path), (void *)ctx + off);
	struct argv_val *val = bpf_map_lookup_elem(&argv_scratch, &e->pid);
	if (val) {
		__builtin_memcpy(e->args, val->args, sizeof(e->args));
		bpf_map_delete_elem(&argv_scratch, &e->pid);
	} else {
		e->args[0] = 0;
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
	struct sockaddr_in sa = {};
	void *uaddr = (void *)ctx->args[1];
	if (bpf_probe_read_user(&sa, sizeof(sa), uaddr))
		return 0;
	if (sa.sin_family != AF_INET)
		return 0;
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->exit_code = 0;
	e->kind = EVENT_CONNECT;
	fill_common(e);
	e->daddr = sa.sin_addr.s_addr;
	e->dport = sa.sin_port;
	e->path[0] = 0;
	e->args[0] = 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// O_WRONLY|O_RDWR|O_CREAT|O_TRUNC -- only writes/creates, to avoid the firehose
// of read-only opens. (Sensitive-read detection is a separate, filtered probe.)
#define OPEN_WRITE_MASK (00000001 | 00000002 | 00000100 | 00001000)

// noise_read_prefix drops the high-volume read paths (shared libs, procfs, sysfs,
// device nodes, etc.) in-kernel so capturing READS does not firehose the ring
// buffer. It is a coarse NEGATIVE filter on the first path bytes (cheap, verifier
// friendly); userspace then POSITIVELY matches the small sensitive set. Writes
// are never dropped here.
static __always_inline int noise_read_prefix(const char *p) {
	if (p[0] != '/')
		return 0;
	char a = p[1], b = p[2], c = p[3];
	if (a == 'u' && b == 's' && c == 'r') return 1; // /usr
	if (a == 'l' && b == 'i' && c == 'b') return 1; // /lib
	if (a == 'p' && b == 'r' && c == 'o') return 1; // /proc
	if (a == 's' && b == 'y' && c == 's') return 1; // /sys
	if (a == 'd' && b == 'e' && c == 'v') return 1; // /dev
	if (a == 'r' && b == 'u' && c == 'n') return 1; // /run
	if (a == 's' && b == 'n' && c == 'a') return 1; // /snap
	return 0;
}

// noise_file_prefix extends noise_read_prefix with /var and /tmp: the container
// runtime (containerd/runc) does a storm of unlink/rename under /var/lib/docker,
// /run/containerd, /tmp/containerd-mount during setup/teardown. Without this the
// ring buffer floods and drops real events. Agent-relevant tamper is in
// /home,/root,/workspace,/app, which are kept.
static __always_inline int noise_file_prefix(const char *p) {
	if (noise_read_prefix(p))
		return 1;
	if (p[0] != '/')
		return 0;
	char a = p[1], b = p[2], c = p[3];
	if (a == 'v' && b == 'a' && c == 'r') return 1; // /var
	if (a == 't' && b == 'm' && c == 'p') return 1; // /tmp
	return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
	long flags = (long)ctx->args[2];
	int is_write = (flags & OPEN_WRITE_MASK) != 0;
	// Filter noise reads BEFORE reserving: a discarded ringbuf record still
	// occupies space until drained, so the prefix check must precede reserve.
	if (!is_write) {
		char pfx[8] = {};
		bpf_probe_read_user(pfx, sizeof(pfx), (void *)ctx->args[1]);
		if (noise_read_prefix(pfx))
			return 0;
	}
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->kind = EVENT_OPEN;
	e->daddr = 0;
	e->dport = 0;
	fill_common(e);
	e->args[0] = 0;
	bpf_probe_read_user_str(&e->path, sizeof(e->path), (void *)ctx->args[1]);
	e->exit_code = is_write ? 0 : 1; // 0 = write, 1 = read
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Process (thread-group-leader) exit: bounds the process lifetime so the
// correlation engine can close time windows and resist pid reuse. Also frees any
// stale argv stash for the pid.
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	if ((__u32)(id >> 32) != (__u32)id)
		return 0; // only the group leader == process exit, not per-thread
	__u32 pid = (__u32)(id >> 32);
	bpf_map_delete_elem(&argv_scratch, &pid);
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->kind = EVENT_EXIT;
	e->daddr = 0;
	e->dport = 0;
	fill_common(e);
	e->path[0] = 0;
	e->args[0] = 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Privilege change: setuid/setgid. setuid(0) is the classic root escalation; a
// sandboxed agent that calls it is a red flag. daddr distinguishes uid vs gid.
SEC("tp/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx) {
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->kind = EVENT_SETUID;
	e->daddr = 0; // uid
	e->dport = 0;
	fill_common(e);
	e->path[0] = 0;
	e->args[0] = 0;
	e->exit_code = (int)ctx->args[0]; // target uid
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_setgid")
int handle_setgid(struct trace_event_raw_sys_enter *ctx) {
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->kind = EVENT_SETUID;
	e->daddr = 1; // gid
	e->dport = 0;
	fill_common(e);
	e->path[0] = 0;
	e->args[0] = 0;
	e->exit_code = (int)ctx->args[0]; // target gid
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ptrace: process injection / memory inspection -- a credential-theft and
// sandbox-escape vector. daddr carries the target pid, exit_code the request.
SEC("tp/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx) {
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->kind = EVENT_PTRACE;
	e->daddr = (__u32)ctx->args[1]; // target pid
	e->dport = 0;
	fill_common(e);
	e->path[0] = 0;
	e->args[0] = 0;
	e->exit_code = (int)ctx->args[0]; // ptrace request
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// File rename/unlink: tampering, trace cleanup, exfil staging. We capture the
// source path (renameat2 oldname / unlinkat pathname).
// renameat/renameat2: oldname is args[1]. (Used by modern libc.)
SEC("tp/syscalls/sys_enter_renameat2")
int handle_rename(struct trace_event_raw_sys_enter *ctx) {
	char pfx[8] = {};
	bpf_probe_read_user(pfx, sizeof(pfx), (void *)ctx->args[1]); // oldname
	if (noise_file_prefix(pfx))
		return 0;
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->kind = EVENT_RENAME;
	e->daddr = 0;
	e->dport = 0;
	fill_common(e);
	e->args[0] = 0;
	e->exit_code = 0;
	bpf_probe_read_user_str(&e->path, sizeof(e->path), (void *)ctx->args[1]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// rename(2): oldname is args[0] (busybox/coreutils mv on the same filesystem).
SEC("tp/syscalls/sys_enter_rename")
int handle_rename_plain(struct trace_event_raw_sys_enter *ctx) {
	char pfx[8] = {};
	bpf_probe_read_user(pfx, sizeof(pfx), (void *)ctx->args[0]); // oldname
	if (noise_file_prefix(pfx))
		return 0;
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->kind = EVENT_RENAME;
	e->daddr = 0;
	e->dport = 0;
	fill_common(e);
	e->args[0] = 0;
	e->exit_code = 0;
	bpf_probe_read_user_str(&e->path, sizeof(e->path), (void *)ctx->args[0]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_unlinkat")
int handle_unlink(struct trace_event_raw_sys_enter *ctx) {
	char pfx[8] = {};
	bpf_probe_read_user(pfx, sizeof(pfx), (void *)ctx->args[1]); // pathname
	if (noise_file_prefix(pfx))
		return 0;
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->kind = EVENT_UNLINK;
	e->daddr = 0;
	e->dport = 0;
	fill_common(e);
	e->args[0] = 0;
	e->exit_code = 0;
	bpf_probe_read_user_str(&e->path, sizeof(e->path), (void *)ctx->args[1]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Universal DNS: a UDP query to port 53 carries the DNS message in the sendto
// buffer. We copy the raw bytes (exit_code = length) and parse the qname in
// userspace. This catches musl/busybox, Go's own resolver, and any app doing
// raw UDP:53 -- including INSIDE containers, which the libc uprobe below cannot.
SEC("tp/syscalls/sys_enter_sendto")
int handle_sendto(struct trace_event_raw_sys_enter *ctx) {
	void *buf = (void *)ctx->args[1];
	long len = (long)ctx->args[2];
	void *dest = (void *)ctx->args[4];
	if (!buf || !dest || len < 13)
		return 0;
	struct sockaddr_in sa = {};
	if (bpf_probe_read_user(&sa, sizeof(sa), dest))
		return 0;
	if (sa.sin_family != AF_INET || sa.sin_port != bpf_htons(53))
		return 0;
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->kind = EVENT_DNS;
	e->daddr = 0;
	e->dport = 0;
	fill_common(e);
	e->args[0] = 0;
	__u32 n = (__u32)len;
	if (n > 250)
		n = 250; // raw DNS bytes; exit_code carries the length for userspace
	e->exit_code = n;
	bpf_probe_read_user(&e->path, n, buf);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// DNS: a uprobe on libc getaddrinfo(node, ...) captures the HOSTNAME an app
// resolves -- the egress destination by name, not just the IP a connect reveals.
// Covers dynamically-linked glibc apps (Python, Node, curl); musl/static/Go
// resolve via other paths and are not seen here.
SEC("uprobe/getaddrinfo")
int BPF_UPROBE(handle_getaddrinfo, const char *node) {
	if (!node)
		return 0;
	struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	e->kind = EVENT_DNS;
	e->daddr = 0;
	e->dport = 0;
	fill_common(e);
	e->args[0] = 0;
	e->exit_code = 0;
	bpf_probe_read_user_str(&e->path, sizeof(e->path), node);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Boundary tracing: uprobes on SSL_write/SSL_read and the modern *_ex variants
// capture the plaintext an agent sends/receives over TLS (the LLM
// request/response) without instrumenting it. Attached to a libssl path only
// when --ssl-lib is given. We emit the FULL buffer as ordered SSL_CHUNK-sized
// chunks keyed by the SSL* pointer (conn); userspace reassembles them into
// complete HTTP/1.1 or HTTP/2 messages.
static __always_inline void emit_ssl_chunks(__u32 kind, __u64 conn, const char *buf, int total) {
	for (int i = 0; i < SSL_MAX_CHUNKS; i++) {
		int off = i * SSL_CHUNK;
		if (off >= total)
			break;
		// off < total here, so total - off > 0: cast to unsigned so the verifier
		// knows the read size is non-negative, then clamp to the 256B path[].
		__u32 len = (__u32)(total - off);
		if (len > SSL_CHUNK)
			len = SSL_CHUNK; // len in [1, SSL_CHUNK]
		struct sensor_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (!e) {
			count_drop();
			return;
		}
		e->kind = kind;
		e->conn = conn;
		e->daddr = len; // valid bytes in this chunk's path[]
		e->dport = (total > SSL_CHUNK * SSL_MAX_CHUNKS && i == SSL_MAX_CHUNKS - 1) ? 1 : 0;
		e->exit_code = total;
		fill_common(e);
		e->args[0] = 0;
		bpf_probe_read_user(&e->path, len, buf + off);
		bpf_ringbuf_submit(e, 0);
	}
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(handle_ssl_write, void *ssl, const void *buf, int num) {
	if (!buf || num <= 0)
		return 0;
	emit_ssl_chunks(EVENT_SSL, (__u64)ssl, (const char *)buf, num);
	return 0;
}

// SSL_write_ex(ssl, buf, num, *written): the size_t-taking variant modern
// OpenSSL 3.x clients use (notably CPython's _ssl, which never calls SSL_write).
// The plaintext is in buf at entry, exactly like SSL_write, so we emit here and
// ignore the *written out-param. num is size_t; clamp before the signed emit.
SEC("uprobe/SSL_write_ex")
int BPF_UPROBE(handle_ssl_write_ex, void *ssl, const void *buf, __u64 num) {
	if (!buf || num == 0 || num > (1u << 20))
		return 0;
	emit_ssl_chunks(EVENT_SSL, (__u64)ssl, (const char *)buf, (int)num);
	return 0;
}

// SSL_read(ssl, buf, num): the plaintext lands in buf only AFTER the call, so we
// stash (buf, ssl) at entry and read it on return (the return value is the count).
struct ssl_read_ctx {
	__u64 buf;
	__u64 ssl;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct ssl_read_ctx);
} ssl_read_bufs SEC(".maps");

SEC("uprobe/SSL_read")
int BPF_UPROBE(handle_ssl_read_enter, void *ssl, void *buf, int num) {
	__u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	struct ssl_read_ctx c = {.buf = (__u64)buf, .ssl = (__u64)ssl};
	bpf_map_update_elem(&ssl_read_bufs, &pid, &c, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(handle_ssl_read_exit, int ret) {
	__u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	struct ssl_read_ctx *c = bpf_map_lookup_elem(&ssl_read_bufs, &pid);
	if (!c)
		return 0;
	__u64 buf = c->buf, ssl = c->ssl;
	bpf_map_delete_elem(&ssl_read_bufs, &pid);
	if (ret <= 0 || buf == 0)
		return 0;
	emit_ssl_chunks(EVENT_SSL_READ, ssl, (const char *)buf, ret);
	return 0;
}

// SSL_read_ex(ssl, buf, num, *readbytes): the modern variant. Unlike SSL_read,
// the byte count is written to *readbytes (not the return value, which is 1/0
// success), so we stash the out-param pointer at entry and read *readbytes on
// return. Separate map from SSL_read so the two paths never clobber each other.
struct ssl_read_ex_ctx {
	__u64 buf;
	__u64 ssl;
	__u64 readbytes; // *size_t out-param holding the count after the call
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct ssl_read_ex_ctx);
} ssl_read_ex_bufs SEC(".maps");

SEC("uprobe/SSL_read_ex")
int BPF_UPROBE(handle_ssl_read_ex_enter, void *ssl, void *buf, __u64 num, __u64 *readbytes) {
	__u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	struct ssl_read_ex_ctx c = {.buf = (__u64)buf, .ssl = (__u64)ssl, .readbytes = (__u64)readbytes};
	bpf_map_update_elem(&ssl_read_ex_bufs, &pid, &c, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_read_ex")
int BPF_URETPROBE(handle_ssl_read_ex_exit, int ret) {
	__u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	struct ssl_read_ex_ctx *c = bpf_map_lookup_elem(&ssl_read_ex_bufs, &pid);
	if (!c)
		return 0;
	__u64 buf = c->buf, ssl = c->ssl, rbptr = c->readbytes;
	bpf_map_delete_elem(&ssl_read_ex_bufs, &pid);
	if (ret <= 0 || buf == 0 || rbptr == 0)
		return 0;
	__u64 n = 0;
	bpf_probe_read_user(&n, sizeof(n), (void *)rbptr);
	if (n == 0 || n > (1u << 20))
		return 0;
	emit_ssl_chunks(EVENT_SSL_READ, ssl, (const char *)buf, (int)n);
	return 0;
}
