# AgentProvenance Infra v1 -- Definition of Done

> Status: release-scope doc. Turns the `north-star-three-pillars.md` vision into a
> checkable v1 acceptance list. Decisions below were taken 2026-06-27 and the
> status table was reconciled with completed gates on 2026-08-05 after a
> file-grounded audit of the whole repo. Each item is DONE / PARTIAL / DEFERRED
> with the evidence symbol. "DEFERRED" means explicitly out of v1, into v2.

## 0. The one decision that frames v1

The differentiated asset is the **correlation primitive** turned into a
**verifiable, queryable evidence graph**. v1 ships that core for the two deploy
shapes that have users today (Library/CLI and sidecar daemon). v1 is **hardening
+ honesty**, not new features -- the evidence-graph core (storage, ingest,
correlation, observability, provenance, risk, forensics) is already implemented
and verified by a live binary run.

### Honesty scoping (load-bearing)

v1 makes an **integrity** claim, NOT a **tamper-evidence** claim. `graph verify`
recomputes hashes from the local SQLite store, which a host-root attacker can
edit; it detects accidental corruption and object-hash/parent breaks, not an
attacker who rewrites the store and re-derives the chain. Off-host
capture-time anchoring (KMS/TPM/transparency log) is the thing that would make
"tamper-evident" true, and it is **v2** (see Sec 3). Do not market v1 as
tamper-evident against a malicious host root.

## 1. What v1 includes (status from the 2026-06-27 audit)

| # | Area | Status | Evidence (file:symbol) |
|---|---|---|---|
| 1 | Data-plane: spool / backpressure / drop | DONE | `telemetry/spool.go` bounds batch count, total bytes, and per-batch bytes; reject\|drop_oldest + HTTP 429; `telemetry producer-health`; pressure/spool acceptance scripts |
| 1 | Data-plane: collector as a *separate process* | DEFERRED -> v2 | `cmd/agentprov-sensor` is a separate producer; ingest remains in-daemon for Deploy 1/2. Full process-level data-plane isolation is coupled to Deploy 3 |
| 2 | Control: daemon holds correlation/policy/risk/response/verify | DONE | `daemon/server.go` /v1 routes |
| 2 | Control: CLI as client | DEFERRED -> v2 | reads route via daemon; some local-first writes remain in-process. WAL plus the daemon advisory lock make the Deploy 1/2 boundary explicit; a daemon-only write surface belongs to Deploy 3 |
| 2 | Control: stable JSON schema | DONE for v1 | core JSON surfaces carry versioned response contracts; a single universal envelope would change existing wire formats and is deferred to v2 |
| 2 | Control: authn | DONE | `withAuth` bearer token, constant-time, open-by-default |
| 2 | Control: authz / scopes | DEFERRED | no roles/scopes; single all-or-nothing token -> **v2** (rides with Deploy 3) |
| 3 | Storage: WAL + busy_timeout (all conns) | DONE | `store/store.go` DSN `_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)` |
| 3 | Storage: raw retention | DONE | `telemetry/retention.go` PruneRawEvents (manual CLI; no scheduler) |
| 3 | Storage: 10s/60s windows | DONE | `telemetry/windows.go` (10s built but unasserted -- see Sec 2 tests) |
| 3 | Storage: content-addressed objects | DONE | `provenance/objects.go` MaterializeRun; forensics/replay manifests |
| 3 | Storage: graph verify object hash/parent/chain | DONE | `provenance/verify.go` verifyObjects + verifyRiskAndResponses |
| 4 | Ingest: Falco | DONE | `IngestFalco`; `accept_falco_risk_realistic.sh` |
| 4 | Ingest: Tetragon | DONE | `mapTetragon`; unit + demo (no accept script -- see Sec 2 tests) |
| 4 | Ingest: own eBPF sensor -- receiver | DONE | `mapNative` native format; `accept_native_sensor_risk.sh`; live VM E2E 2026-06-27 |
| 4 | Ingest: own eBPF sensor -- capture binary build | DONE | bpf2go bindings committed (`internal/sensor/sensorbpf_bpf*.go/.o`); fresh Linux `go build ./cmd/agentprov-sensor` works without clang; `scripts/regen-sensor.sh --check` + CI guard drift |
| 4 | Ingest: raw events need no tool_call_id | DONE | `telemetry/service.go` IngestFiltered -> correlation.Resolve fallback |
| 4 | Correlation by container/cgroup/pid/time | DONE | `correlation/binding.go`: process 1.0 / cgroup 0.98 / container 0.92 / pid 0.85 |
| 4 | Child/async/delayed -> original scope | DONE | time-window open bindings + root_pid + container/cgroup co-membership (not ppid lineage); supervised `record` can launch into a real cgroup-per-scope |
| 5 | Observability: timeline app+runtime | DONE | `provenance/timeline.go` BuildTimeline, lanes + correlation_status |
| 5 | observe summary/coverage/scopes/event/process/flow | DONE | `cli/observe_cmd.go` (6/6) |
| 5 | graph explain event/process/tool_call/file/risk/artifact | DONE | `provenance/explain.go` (+execution scope,+run; `attempt` remains a storage compatibility alias) |
| 5 | core queries JSON + schema_version | DONE | all commands `--json` |
| 6 | record base state / changed files / process obs | DONE | `record/service.go` (self-recursion bug fixed 2026-06-27; physical table still uses snapshot compatibility names) |
| 6 | diff / blame(4-state) / artifact(hash,source,parent) / replay | DONE | `provenance/diff.go`, `objects.go`, `replay.go` |
| 7 | metadata_ip / private_cidr / secret_path -> risk -> response | DONE | `security/policy.go` DefaultRules, EvaluateRuntimeEvent |
| 7 | verify policy->risk->response->unified security signal | DONE | `verify.go` verifyRiskAndResponses (requires unified signal) |
| 7 | quarantine/kill/deny disposition (record-level) | DONE | state mutation, not real enforcement (acceptable for v1) |
| 7 | Feishu/DingTalk/webhook notifier | DEFERRED | zero implementation -> **v2** |
| 8 | forensics export bundle + sha256 | DONE | `forensics/export.go` ExportBundle |
| 8 | bundle contents (events/policy/risk/response/edges/manifest/cost) | DONE | export.go bundle map; `accept_forensics_bundle.sh` |
| 8 | sign + offline verify (hash + schema) | DONE | `attest/` in-toto + DSSE + ed25519; VerifyBundleAttestation |
| 8 | graph verify proves run chain unbroken | DONE | integrity only -- see Sec 0 honesty scoping |
| 9 | 100k ingest keeps query responsive | DONE (measured baseline, not SLA) | bounded paging and health are asserted; the script emits ingest throughput, query/health p50/p95/p99, daemon CPU/RSS, queue/drop state, and coverage JSON |
| 9 | concurrent record/ingest preserves consistency | DONE | WAL-serialized writes plus `record.TestConcurrentRecordPreservesGraphConsistency` verify logical graph consistency under concurrent writers |
| 9 | raw retention effective | DONE | `accept_daemon_evidence_api.sh` prune |
| 9 | pagination / cursor | DONE | ListEventsPage opaque cursor |
| 9 | scenarios normal/risk/high-pressure/corrupted-chain | DONE | acceptance gates cover normal/risk/high-pressure; `accept_evidence_tamper_detection.sh` proves object-file and in-DB record-manifest tamper detection |
| 10 | Deploy 1 Library/CLI | DONE | single binary + python helper; `accept_deploy1_batch_pipeline.sh` |
| 10 | Deploy 2 Sidecar/local daemon | DONE | `daemon serve` + REST + bearer auth |
| 10 | Deploy 3 Central evidence service | DEFERRED | no object storage / multi-tenant / mTLS -> **v2** |

## 2. v1 must-close (hardening + honesty, no new features) -- ALL DONE 2026-06-27

1. **[DONE]** record self-recursion crash -- `CopyDirFiltered` excludes the dst
   subtree + .agentprov (commit 28700d4).
2. **[DONE]** Confidence semantics split -- `telemetry.CorrelationClass` ->
   self_observed | context_asserted | kernel_correlated | uncorrelated, surfaced
   on the telemetry-list and event-explain JSON (commit 4e1a6f7).
3. **[DONE]** Two-writer guard -- `daemon serve` holds an advisory `.daemon.lock`;
   CLI writes warn via `daemon.WarnIfDaemonActive` (WAL keeps it file-safe; the
   warning points at `--daemon-url`). Commit 9f2204a.
4. **[DONE]** eBPF sensor reproducible build -- bpf2go bindings committed; fresh
   Linux `go build ./cmd/agentprov-sensor` works without clang; `scripts/regen-sensor.sh`
   (+ `--check`) and two CI jobs guard build + drift (commit 50f1106).
5. **[DONE]** Adversarial / coverage tests:
   - object-file + in-DB tamper -> `graph verify` (object_hash_mismatch /
     record_manifest_mismatch); `scripts/accept_evidence_tamper_detection.sh` (6692c62)
   - concurrent writers -> graph consistency; record TestConcurrentRecord... (d84812a)
   - child pid != binding pid attributes via container; correlation test (f7f2a6b)
   - Tetragon `scripts/accept_tetragon_ingest.sh`; 10s window assertion (f7f2a6b)
   - 100k latency uses a persisted measured report rather than a fixed SLA;
     machine-specific latency assertions remain intentionally avoided.
6. **[DONE]** Contract: daemon `health` now emits `schema_version` (the one
   passthrough-less response; report handlers already carried it). Commit 2f2b4d7.
   A single universal envelope across all responses remains a v2 item (it would
   change existing wire formats).

**v1 hardening is complete.** Remaining open work is all v2 (Sec 3).

## 3. Explicitly DEFERRED to v2 (decided 2026-06-27)

- **Off-host capture-time tamper-evidence anchoring** (KMS/TPM/transparency log).
  Until then the v1 security claim is integrity, not tamper-evidence (Sec 0). This
  is north-star Tier B "existential for the security customer" -- v2 headline.
- **Deploy 3 central evidence service** + the strong process-level data-plane
  isolation and authz/scopes it requires (object storage, multi-tenant, mTLS).
  Deploy 2 (sidecar daemon) already serves single-node security harnesses, so
  deferring Deploy 3 does **not** drop the security track -- it defers scale-out.
  north-star Sec 7: earn it through Mode 1/2 adoption.
- **Daemon-only write API and one universal JSON envelope.** Deploy 1 remains
  intentionally local-first; changing every existing response and write path is
  coupled to the Deploy 3 API boundary rather than required for v1 correctness.
- **Notifications** (Feishu/DingTalk/webhook response adapters).
- Cross-host identity / clock-skew correlation (A2); auditd/extra substrates;
  rootless container cgroup-delegation validation; broader multi-arch sensor
  hardening.

## 4. v1 done gate

v1 is done when every included item above is DONE, every excluded item is
explicitly in Sec 3, all Sec 2 items are closed, and the full gate is green --
`go vet/test ./...`, every `scripts/accept_*.sh`, gofmt + non-ASCII + `git diff --check`.
