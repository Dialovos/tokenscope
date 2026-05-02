# TokenScope — Universal LLM Observability via eBPF

**Status:** Draft v0.1
**Owner:** Hoang Le
**Last updated:** 2026-04-30
**Repo:** `~/code/personal/active/tokenscope`

---

## 1. Vision

TokenScope is a **zero-instrumentation, kernel-level observability platform** for every LLM workload running on a Linux host — local engines (Ollama, vLLM, llama.cpp, MLC), cloud APIs (Anthropic, OpenAI, Gemini, Bedrock, Vertex), and orchestration layers (LangChain, LlamaIndex, Claude Agent SDK, MCP servers).

It uses **eBPF (kprobes, uprobes, tracepoints, fentry, ringbuf, cgroup hooks)** to attach to the kernel without touching the apps it observes. There is no SDK, no sidecar, no patch, no env-var dance. You drop a single static binary on a host, and within 200 ms every LLM byte that crosses a syscall boundary is accounted for.

**One-line pitch:** *"`htop` for LLMs — but it sees your encrypted Anthropic traffic, your local Ollama tokens, and your MCP tool calls without a single line of code change."*

### 1.1 Why this matters personally
- Directly applicable to **Olivia** (local Ollama), **Sentry HOA** (Claude API), and the **knowledge-graph** project (MCP servers).
- eBPF is one of the highest-leverage infra skills for 2026 — Cilium, Falco, Tetragon, Parca, Pixie all built billion-dollar reputations on it.
- Forces deep mastery of: Linux syscalls, TLS internals, BPF verifier, CO-RE, BTF, ringbuf, perf events, cgroups v2, network namespaces, Rust unsafe FFI.
- Portfolio gold — the intersection of *systems* + *AI* + *observability* is rare.

---

## 2. Goals & Non-Goals

### 2.1 Goals
1. **Zero-instrumentation** — no SDK, no LD_PRELOAD requirement (LD_PRELOAD is opt-in fallback only).
2. **Universal coverage** — local + cloud + agentic + tool-call telemetry from one agent.
3. **Sub-1% CPU overhead** at 1k req/s steady state.
4. **CO-RE portability** — one binary, kernels 5.8 → 6.x, x86_64 + aarch64.
5. **Privacy-first** — prompt redaction, API key masking, opt-in payload capture.
6. **Cost accounting** — real-time $/hour by provider, model, project, cgroup, user.
7. **Real-time TUI** + **Prometheus exporter** + **OTLP exporter** + **DuckDB warehouse**.
8. **Anomaly detection** — rate-limit prediction, prompt-injection signatures, runaway-loop detection, token-budget alerts.

### 2.2 Non-Goals (v1)
- Windows / macOS host support (eBPF on macOS is a different beast — possible v3 via DTrace/Instruments).
- Replacing Langfuse / Helicone / Langsmith (TokenScope complements them; it sees what they can't because it's below the app).
- Modifying or blocking traffic (read-only initially; v2 adds policy enforcement via XDP/sockmap).
- Supporting GGUF model introspection (out of scope — that's `llama.cpp --verbose`).
- Multi-host distributed tracing (v2 via OTLP; v1 ships single-host only).
- Internationalization — English-only UI for v1; all user-facing strings funneled through `t!()` macro so future translation is mechanical.
- Mobile app — Tailscale + `ts-web` is the remote story; explicitly no native iOS/Android client.

---

## 3. Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                          User Space (Rust)                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────┐  │
│  │   TUI    │  │  Prom    │  │   OTLP   │  │ DuckDB   │  │ Web  │  │
│  │ (ratatui)│  │ exporter │  │ exporter │  │  sink    │  │  UI  │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──┬───┘  │
│       │             │             │             │           │      │
│       └─────────────┴──────┬──────┴─────────────┴───────────┘      │
│                            │                                       │
│                  ┌─────────▼──────────┐                            │
│                  │   Event Pipeline   │  enrichment, dedup,        │
│                  │   (tokio + Arrow)  │  cost calc, redaction      │
│                  └─────────▲──────────┘                            │
│                            │                                       │
│                  ┌─────────┴──────────┐                            │
│                  │  ringbuf consumer  │  one consumer per CPU      │
│                  │  (libbpf-rs)       │                            │
│                  └─────────▲──────────┘                            │
└────────────────────────────┼───────────────────────────────────────┘
                             │  BPF_MAP_TYPE_RINGBUF
┌────────────────────────────┼───────────────────────────────────────┐
│                       Kernel Space (BPF)                           │
│  ┌──────────────────┐  ┌──▼──────────────┐  ┌────────────────┐    │
│  │ kprobe: tcp_send │  │ uprobe: SSL_write│  │ tracepoint:    │    │
│  │ kprobe: tcp_recv │  │ uprobe: SSL_read │  │  sched_process │    │
│  └──────────────────┘  └─────────────────┘  └────────────────┘    │
│  ┌──────────────────┐  ┌─────────────────┐  ┌────────────────┐    │
│  │ cgroup/connect4  │  │ uprobe: write @ │  │ fentry:        │    │
│  │ cgroup/sendmsg   │  │  ollama binary  │  │  do_sys_open   │    │
│  └──────────────────┘  └─────────────────┘  └────────────────┘    │
└────────────────────────────────────────────────────────────────────┘
```

### 3.1 Component breakdown
| Component         | Lang | Purpose |
|-------------------|------|---------|
| `tsd`             | Rust + libbpf-rs | Daemon: loads BPF, drains ringbuf, runs pipeline |
| `tsctl`           | Rust | CLI: status, attach/detach probes, query DuckDB |
| `tstop`           | Rust + ratatui | Live TUI dashboard |
| `ts-web`          | Rust + axum + htmx | Optional local web UI (port 7666) |
| `bpf/`            | C | All BPF programs (compiled with clang -target bpf) |
| `vmlinux.h`       | gen | Per-kernel BTF dump for CO-RE |
| `prices.toml`     | data | Provider price table, updated weekly via cron |

### 3.2 Build & Distribution

**Repo layout** (cargo workspace):
```
tokenscope/
├── Cargo.toml                # workspace root
├── crates/
│   ├── tsd/                  # daemon binary
│   ├── tsctl/                # CLI binary
│   ├── tstop/                # TUI binary
│   ├── ts-web/               # web UI binary (optional feature)
│   ├── ts-core/              # shared types, pipeline, parsers
│   ├── ts-bpf-sys/           # libbpf-rs skeleton bindings (build.rs)
│   └── ts-providers/         # per-provider parsers (Anthropic, OpenAI, ...)
├── bpf/                      # *.bpf.c source
├── vmlinux/                  # per-kernel BTF dumps + fetch script
├── prices/prices.toml        # provider prices
├── policies/                 # AppArmor, SELinux, systemd unit
├── packaging/                # deb/rpm/AUR/brew/Dockerfile/Helm
├── tests/                    # integration tests + fixtures (pcap, ringbuf dumps)
└── docs/                     # mdbook source
```

**BPF compile pipeline:** `build.rs` invokes `clang -target bpf -O2 -g -Wall -c bpf/*.bpf.c -o OUT/*.bpf.o`, then `bpftool gen skeleton` to produce a Rust-callable struct, embedded in the binary at compile time. Skeleton regen on probe change is fast (<1s).

**Release artifact matrix:**
| Format | Linkage | Targets |
|--------|---------|---------|
| Static binary | musl | x86_64, aarch64 (universal — no glibc dep) |
| Dynamic binary | glibc | x86_64, aarch64 (slightly smaller) |
| .deb | systemd unit | Ubuntu 22.04+, Debian 12+ |
| .rpm | systemd unit | Fedora 40+, RHEL 9+ |
| AUR `PKGBUILD` | systemd unit | Arch |
| Homebrew formula | launchd N/A — Linux only | linuxbrew |
| OCI image | distroless base | Docker, Podman, k8s |
| Helm chart | DaemonSet | k8s clusters |

**Reproducible builds:** pin Rust toolchain in `rust-toolchain.toml`, lock cargo deps, `SOURCE_DATE_EPOCH` for timestamps. Document SHA256 verification.

**Signing:** release artifacts signed with cosign; SBOM via `cargo-cyclonedx`.

### 3.3 Configuration

**Precedence (highest wins):** CLI flags → environment variables (`TS_*`) → config file → built-in defaults.

**File location** (first match):
1. `--config <path>` flag
2. `$TOKENSCOPE_CONFIG`
3. `$XDG_CONFIG_HOME/tokenscope/config.toml`
4. `~/.config/tokenscope/config.toml`
5. `/etc/tokenscope/config.toml` (system-wide; requires root to edit)

**Format:** TOML, schema-validated against `ts-core::config::Schema` (JSON Schema also exported for editor support).

**Example:**
```toml
[daemon]
log_level = "info"
log_format = "json"          # "json" | "human"
data_dir = "~/.local/share/tokenscope"
ringbuf_size_kb = 256
mem_limit_mb = 256
oom_score_adj = -500

[probes]
enabled = ["network", "tls", "ollama", "lifecycle"]
disabled = ["gpu"]            # WSL2 default

[capture]
payloads = false              # opt-in per process via `tsctl capture allow`
hash_prompts = true
redaction_pack = "default"    # or path to custom

[sampling]
default_rate = 1.0            # 1.0 = capture all
rules = [
  { match = { provider = "ollama", model = "llama3*" }, rate = 0.1 },
]

[exporters.prometheus]
enabled = true
listen = "127.0.0.1:9464"

[exporters.otlp]
enabled = false
endpoint = "https://otlp.example.com:4317"
headers = { authorization = "Bearer $OTLP_TOKEN" }   # env var interpolation

[storage]
duckdb_path = "auto"          # = "$data_dir/events.duckdb"
retention_hot_minutes = 60
retention_warm_days = 90
compaction_schedule = "0 3 * * *"

[telemetry]
enabled = false               # tsd never phones home; this is here so users can verify
```

**Hot reload:** `tsctl reload` re-reads config without restart; probe set diff-applied. Schema-incompatible changes refused with diff explanation.

**Validation:** `tsctl config check` parses config and prints effective settings (with sources).

### 3.4 Logging & Self-Diagnostics

**Logging:** `tracing` crate, structured JSON by default, human-readable with `--log-format human`. Targets: stderr, syslog (`--log-target syslog`), file with rotation (size + age based, via `tracing-appender`).

**Levels per module:** `RUST_LOG=tsd=info,ts_bpf=debug,ts_providers::anthropic=trace`.

**Audit log:** every config change, every payload-capture grant/revoke, every probe attach/detach written to `$data_dir/audit.log` (append-only, world-readable, root-writable).

**`tsctl doctor`** — single command that diagnoses why the daemon can't do its job. Checks:

| Check | Failure surfacing |
|-------|-------------------|
| Kernel version >= 5.8 | "Kernel 5.4 found — ringbuf needs 5.8+. Options: upgrade, or run with `--legacy-perfbuf`." |
| BTF available (`/sys/kernel/btf/vmlinux`) | "Missing BTF. Auto-fetch from BTFHub? [Y/n]" |
| Capabilities (CAP_BPF, CAP_PERFMON) | "Missing CAP_BPF. Run with sudo or `setcap cap_bpf,cap_perfmon+ep $(which tsd)`." |
| Lockdown mode | "Lockdown=integrity blocks uprobes. Network-only mode will work." |
| AppArmor / SELinux | "AppArmor profile blocks `bpf()`. Apply included profile: `sudo cp policies/apparmor/tsd /etc/apparmor.d/`" |
| WSL kernel BTF | "WSL2 kernel detected. BTF present: yes." |
| Cgroup v2 mounted | "Cgroup v1 detected — only host-PID grouping available." |
| Disk space at `data_dir` | "12 GB free, retention will hold ~80 days at current rate." |
| Time sync (chrony / systemd-timesyncd) | "Clock skew 4.2s vs NTP — costs may be misattributed." |
| `tsd` reachable & ringbuf flowing | "Daemon up 3h12m, 12.4k events/min, 0 drops." |

Output: human-readable by default, `--json` for scripts. Exit code = number of failed checks.

**`tsctl probes inspect <name>`** — show BPF program disassembly, verifier log, attached kprobes, map sizes, drop counters.

### 3.5 Versioning & Compatibility

**SemVer scope per artifact:**
| Artifact | What semver covers |
|----------|---------------------|
| `tsctl` CLI flags & exit codes | breaking flag removal = major |
| `tsctl tail` event JSON schema | field removal/rename = major; addition = minor |
| Config file schema | required-key change = major; new optional key = minor |
| Prometheus metric names & labels | rename/removal = major |
| OTLP attribute names | follow OTel semantic conventions; deviations = major |
| DuckDB on-disk schema | always migrated forward, never breaks |
| BPF skeleton ABI (internal) | not stable, no guarantees |
| Plugin API (see §8) | semver from v1.0 |

**Migration:** on startup, `tsd` checks `$data_dir/SCHEMA_VERSION`; if older, runs migrations from `migrations/NNN_*.sql` then bumps the version. Refuses to run if newer (downgrade requires explicit `--allow-downgrade`).

**Deprecation policy:** anything deprecated in version N is removed no earlier than N+2 (one minor of warnings, one minor of error-with-override, then gone). All deprecations logged with `WARN deprecated.<thing>`.

**Kernel matrix promise:** any kernel that's still receiving upstream LTS updates is supported. Currently: 5.10, 5.15, 6.1, 6.6, 6.11. CI green on all five before any release.

### 3.6 Kubernetes Deployment

**DaemonSet topology** — one `tsd` Pod per node, sharing the host PID and network namespaces (necessary for cross-container visibility):

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: tokenscope
  namespace: tokenscope-system
spec:
  selector: { matchLabels: { app: tokenscope } }
  template:
    metadata: { labels: { app: tokenscope } }
    spec:
      hostPID: true
      hostNetwork: false           # only true if we need to see host-net traffic
      serviceAccountName: tokenscope
      tolerations: [{ operator: Exists }]
      containers:
      - name: tsd
        image: ghcr.io/tokenscope/tsd:1.0.0
        securityContext:
          privileged: false
          capabilities:
            add: [BPF, PERFMON, SYS_PTRACE, NET_ADMIN]
            drop: [ALL]
          readOnlyRootFilesystem: true
        resources:
          requests: { cpu: 100m, memory: 128Mi }
          limits:   { cpu: 2,    memory: 512Mi }
        volumeMounts:
        - { name: bpffs,        mountPath: /sys/fs/bpf, mountPropagation: Bidirectional }
        - { name: cgroupfs,     mountPath: /sys/fs/cgroup, readOnly: true }
        - { name: btf,          mountPath: /sys/kernel/btf, readOnly: true }
        - { name: data,         mountPath: /var/lib/tokenscope }
      volumes:
      - { name: bpffs,    hostPath: { path: /sys/fs/bpf, type: Directory } }
      - { name: cgroupfs, hostPath: { path: /sys/fs/cgroup, type: Directory } }
      - { name: btf,      hostPath: { path: /sys/kernel/btf, type: Directory } }
      - { name: data,     hostPath: { path: /var/lib/tokenscope, type: DirectoryOrCreate } }
```

**RBAC:** ServiceAccount + ClusterRole granting `get/list/watch` on `pods`, `nodes`, `namespaces` (for label/annotation enrichment); no write permissions ever.

**Pod enrichment pipeline:** `tsd` watches the kubelet's local pod list (`/var/lib/kubelet/pods/`) for zero-API-server overhead in the hot path; falls back to the API server when kubelet read fails. Enriches `LlmCall` with `pod`, `namespace`, `pod_labels`, `node_name`, owning `Deployment`/`StatefulSet`.

**Service exposure:** ClusterIP `tokenscope-metrics` (port 9464) for Prometheus scrape; optional `tokenscope-web` Service for `ts-web`.

**Helm chart:** `helm install tokenscope tokenscope/tokenscope` with values for image tag, resource limits, exporter config, sampling rules, and node selectors. Schema-validated `values.schema.json` ships in chart.

**OpenShift compatibility:** SCC `tokenscope-scc` with `allowedCapabilities: [BPF, PERFMON, SYS_PTRACE, NET_ADMIN]`; documented `oc adm policy add-scc-to-user` step.

**Multi-cluster:** each cluster has its own `tsd` DaemonSet; aggregation happens at the OTLP collector or Prometheus federation layer (out of scope for `tsd` itself).

---

## 4. Probes & Data Sources

### 4.1 Network probes (cloud LLM detection)

| Hook | Type | Captures |
|------|------|----------|
| `cgroup/connect4`, `cgroup/connect6` | cgroup BPF | All outbound connect() with PID, cgroup, dst IP/port |
| `kprobe:tcp_sendmsg` / `tcp_recvmsg` | kprobe | Bytes per socket per PID |
| `uprobe:SSL_write` / `SSL_read` | uprobe on libssl | **Plaintext** before encryption (key insight!) |
| `uprobe:gnutls_record_send` / `recv` | uprobe on gnutls | Same for gnutls users |
| `uprobe:rustls::*` | uprobe on Rust binaries | For Rust apps statically linked with rustls |
| `tracepoint:syscalls:sys_enter_write` | tracepoint | Fallback for unencrypted HTTP (rare for LLM APIs) |

**Key trick:** by attaching uprobes to `SSL_write`/`SSL_read` *before* the TLS layer encrypts/decrypts, we capture the plaintext HTTP request/response — including the JSON prompt body and streaming SSE chunks — *without* MITM, *without* a CA cert, *without* a proxy. This works for any app that links OpenSSL dynamically (Python `requests`, `httpx`, `curl`, Node `https`, Go `net/http` with cgo, etc.).

For statically-linked binaries (Go default, Rust rustls), we fall back to:
- USDT probes if available
- Symbol-based uprobes via `/proc/PID/maps` BTF parsing
- Last resort: BPF_PROG_TYPE_SK_MSG to peek at `sendmsg` payload before kernel-side TLS (kTLS) — only works if app uses kTLS.

### 4.2 Local LLM probes (Ollama / vLLM / llama.cpp)

| Engine | Detection | Probe |
|--------|-----------|-------|
| Ollama | bin path matches `**/ollama` or `**/ollama-*` | uprobe on `serveCompletion`, `serveChat` Go funcs (Go symbols via BTF) |
| vLLM | python proc with `vllm.entrypoints` in cmdline | uprobe on `engine.generate` via Python USDT |
| llama.cpp | bin matches `**/llama-*` or `**/main` w/ ggml symbols | uprobe on `llama_decode` |
| MLC-LLM | TVM runtime symbols | uprobe on `mlc::llm::Generate` |
| Generic HTTP server on Ollama port (11434) | port heuristic | network probes only |

### 4.3 GPU probes (sidecar, not eBPF)

eBPF can't see GPU memory directly. Sidecar uses NVML / ROCm SMI in a 100ms poll loop, joined to PID via cgroup membership. Future: explore `nvidia-bpf` (experimental NVIDIA upstream).

### 4.4 Process & lifecycle

| Hook | Captures |
|------|----------|
| `tracepoint:sched:sched_process_exec` | New process — populate process cache (cmdline, cgroup, container ID) |
| `tracepoint:sched:sched_process_exit` | Cleanup, finalize per-PID counters |
| `tracepoint:sched:sched_process_fork` | Parent→child PID linkage for agent call trees |
| `tracepoint:cgroup:cgroup_mkdir` / `rmdir` | Track container lifecycles (k8s pods, docker, podman) |
| `fentry:__x64_sys_openat` | Optional: detect model file loads (.gguf, .safetensors) |

### 4.5 MCP (Model Context Protocol) Instrumentation

MCP is becoming the standard agent↔tool wire format (Claude Code, Claude Desktop, Cursor, Continue, custom agents). TokenScope is **first-class for MCP** because the user's `knowledge-graph` project plus most agentic stacks depend on it.

**Three transports, three probe strategies:**

| Transport | Wire format | Probe |
|-----------|-------------|-------|
| stdio (spawn-and-pipe) | newline-delimited JSON-RPC | `kprobe:vfs_read` + `vfs_write` filtered to MCP server PIDs (detected via parent process being a known agent + `mcp` in argv) |
| SSE over HTTP | JSON-RPC inside SSE events | re-use SSL_read/write uprobes; demuxed by `Content-Type: text/event-stream` and `jsonrpc` field presence |
| HTTP streamable (`POST /mcp`) | JSON-RPC, may stream | re-use SSL_read/write uprobes; correlated by JSON-RPC `id` field |

**MCP-specific events captured:**
- `initialize` handshake → server name, version, capabilities
- `tools/list` → tool catalog snapshot
- `tools/call` → tool invocation with arg sizes (args themselves redacted by default)
- `resources/read` → resource URI accessed
- `prompts/get` → prompt template fetched
- `notifications/*` → progress, cancellation, log messages
- Server lifecycle (spawn, ready, error, exit)

**Attribution:** every MCP event linked to:
- Initiating agent process (the LLM client that spawned the MCP server)
- The LLM call ID that triggered the tool use (correlated via Anthropic `tool_use_id` / OpenAI `tool_call_id`)
- The MCP server's own process & cmdline (for "which server is slow?" queries)

**MCP-specific TUI view:** `tstop --view mcp` shows per-server call counts, p95 latency, error rate, and the agent→server→tool fan-out tree.

**MCP discovery:** scan `~/.config/claude/`, `~/.cursor/`, `~/Library/Application Support/Claude/` (when relevant) at startup for declared MCP servers; pre-warm symbol caches; surface uninvoked-but-configured servers in `tsctl status`.

**Edge cases:**
- Long-running MCP servers (knowledge-graph indexes) → don't double-count "always-on" cost
- MCP server invoking *its own* LLM (recursive) → tag with `recursion_depth`
- MCP-over-Unix-socket (rare but spec-allowed) → covered by `kprobe:unix_stream_sendmsg`

---

## 5. Data Model

### 5.1 Event types (ringbuf records)

```c
enum ts_event_type {
    TS_NET_CONNECT     = 1,  // outbound connection
    TS_NET_BYTES       = 2,  // periodic byte counter flush
    TS_TLS_PLAINTEXT   = 3,  // SSL_read/write payload chunk
    TS_LLM_REQ_START   = 4,  // detected LLM request begin
    TS_LLM_REQ_END     = 5,  // detected LLM request complete
    TS_LLM_TOKEN       = 6,  // streaming token observed
    TS_PROC_EXEC       = 7,
    TS_PROC_EXIT       = 8,
    TS_CGROUP_NEW      = 9,
    TS_CGROUP_GONE     = 10,
    TS_ANOMALY         = 11,
    TS_GPU_SAMPLE      = 12,
};

struct ts_event_hdr {
    u64 ts_ns;          // CLOCK_MONOTONIC
    u32 cpu;
    u32 pid;
    u32 tgid;
    u64 cgroup_id;
    u16 type;
    u16 len;            // payload length
    // payload follows
};
```

Payload size cap: 4KB per event. Larger TLS payloads are chunked across N events with same `req_id`.

### 5.2 Enriched record (after userspace pipeline)

```rust
struct LlmCall {
    id: Uuid,
    started_at: SystemTime,
    finished_at: Option<SystemTime>,

    // process attribution
    pid: u32,
    tgid: u32,
    uid: u32,
    gid: u32,
    cmdline: String,
    exe_path: PathBuf,
    cgroup_path: String,
    container_id: Option<String>,
    container_image: Option<String>,    // sha256 if known
    pod: Option<String>,                // k8s pod name
    pod_labels: BTreeMap<String, String>,
    namespace: Option<String>,          // k8s namespace
    git_repo: Option<PathBuf>,          // walks up from cwd looking for .git
    git_branch: Option<String>,
    virtualenv: Option<PathBuf>,        // VIRTUAL_ENV / CONDA_PREFIX / poetry .venv
    project_hint: Option<String>,       // user-tagged via `tsctl tag`

    // request shape
    provider: Provider,                 // Anthropic | OpenAI | Ollama | Gemini | Custom
    endpoint: String,                   // /v1/messages, /api/generate, ...
    model: String,                      // claude-opus-4-7, gpt-4o, llama3:70b
    direction: Direction,
    api_key_fingerprint: Option<String>, // SHA-256 prefix(8) of the bearer token; never the key itself

    // metering
    prompt_tokens: Option<u32>,
    completion_tokens: Option<u32>,
    cached_tokens: Option<u32>,         // prompt cache hits
    cost_usd: Option<f64>,
    latency_ms: u32,
    ttft_ms: Option<u32>,               // time to first token
    stream: bool,

    // semantics
    tool_calls: Vec<ToolCall>,
    error: Option<ErrorKind>,
    rate_limit_remaining: Option<u32>,  // from response headers when present

    // payload (gated by capture policy)
    redacted_prompt: Option<String>,
    redacted_completion: Option<String>,
    prompt_hash: Option<[u8; 32]>,      // SHA-256 of canonical prompt for dedup
    raw_payload_path: Option<PathBuf>,  // only if `tsctl capture allow PID`

    // distributed tracing correlation
    traceparent: Option<String>,        // W3C trace context if present in HTTP headers
    tracestate: Option<String>,
    sampled: bool,                      // post-sampling decision (see §5.4)
}
```

### 5.3 Storage
- **Hot path:** Arrow record batches in memory, 60s rolling window for TUI.
- **Warm:** DuckDB file at `~/.local/share/tokenscope/events.duckdb`, partitioned by day.
- **Cold:** optional Parquet export to S3/GCS/local dir.
- Retention default: 7 days hot, 90 days warm, configurable.

### 5.4 Sampling

At high QPS (e.g., a vLLM server doing 5k req/s of llama3 completions), full capture is wasteful. Sampling rules in `[sampling]` config:

```toml
[sampling]
default_rate = 1.0
rules = [
  # always capture cloud (cheap, expensive money-wise)
  { match = { provider = "anthropic" }, rate = 1.0 },
  { match = { provider = "openai" }, rate = 1.0 },
  # tail-sample local Ollama at 10%
  { match = { provider = "ollama", model = "llama3*" }, rate = 0.1 },
  # always capture errors
  { match = { error = true }, rate = 1.0 },
  # always capture slow tail
  { match = { latency_ms_gte = 5000 }, rate = 1.0 },
]
```

**Sampling kind:** *tail-based* by default (decide after the call ends, so error/slow rules fire). Head-based available for ultra-high throughput (decide on first event, lose error/slow guarantees).

**Determinism:** sampling decision = `hash(trace_id) < rate * u64::MAX`. Same trace sampled the same way across processes.

**Counters always full-rate:** byte and request *counts* are unsampled (kept in BPF maps as aggregates); only *records* are sampled.

### 5.5 Compaction & Retention

DuckDB will balloon at 10k events/sec. Tiered rollups, scheduled via internal cron (no external cron needed):

| Tier | Resolution | Retention default | Storage |
|------|------------|-------------------|---------|
| raw  | per-event | 7 days | DuckDB `events_raw` partitioned by day |
| 1m   | 60s buckets | 30 days | `events_1m` |
| 1h   | 1h buckets | 1 year | `events_1h` |
| 1d   | 1d buckets | forever | `events_1d` |

Rollup columns: `count, prompt_tokens_sum, completion_tokens_sum, cost_usd_sum, latency_ms_p50/p95/p99` per `(provider, model, cgroup, project_hint, error_kind)`.

Compaction job runs at `[storage.compaction_schedule]` (default 03:00 local). Drops raw data past retention. Vacuum after compaction. Surfaces `compaction_lag_seconds` metric.

Manual: `tsctl compact --since '24h ago'`.

### 5.6 Backfill & Import

Import historical data so TokenScope can show pre-install spend:

| Source | Command | Notes |
|--------|---------|-------|
| Anthropic console CSV | `tsctl import anthropic-csv usage.csv` | per-day spend, no per-call detail |
| OpenAI usage CSV | `tsctl import openai-csv usage.csv` | same |
| `~/.claude/` session logs | `tsctl import claude-code ~/.claude/projects` | full call detail, token-accurate |
| Langfuse JSONL export | `tsctl import langfuse export.jsonl` | full detail |
| Helicone export | `tsctl import helicone export.json` | full detail |
| OTLP file | `tsctl import otlp file.json` | generic |
| pcap (replay) | `tsctl import pcap session.pcap` | runs through live parsers; useful for testing |

Imports tagged with `source != "live"`; segregated in queries unless `--include-imported`. Idempotent via stable `id` derivation from source.

### 5.7 Cost Calculation

Pricing is not "tokens × rate". The `prices.toml` schema covers every real-world pricing dimension:

```toml
[providers.anthropic.models."claude-opus-4-7"]
input_per_million          = 15.00
output_per_million         = 75.00
cache_write_per_million    = 18.75      # 1.25× input
cache_read_per_million     = 1.50       # 0.10× input
batch_input_per_million    = 7.50       # 50% off when via /v1/messages/batches
batch_output_per_million   = 37.50
image_per_million_tokens   = 15.00      # vision tokens use input rate
audio_per_second           = 0.0        # n/a here; placeholder for OAI-realtime
fine_tune_premium_pct      = 0          # base model
free_tier_per_day          = 0
context_window             = 200000
deprecated_after           = ""

[providers.openai.models."gpt-4o"]
input_per_million          = 2.50
output_per_million         = 10.00
cache_read_per_million     = 1.25       # 50% off
audio_input_per_second     = 0.06
audio_output_per_second    = 0.24
image_per_image            = 0.001275   # base detail
batch_discount_pct         = 50
```

**Effective cost formula (per call):**
```
cost = (uncached_input × input_rate)
     + (cached_input × cache_read_rate)
     + (cache_write_input × cache_write_rate)
     + (output × output_rate)
     + (image_count × image_rate OR image_tokens × image_token_rate)
     + (audio_seconds × audio_rate)
   × (1 - batch_discount_pct/100  if batch_endpoint else 0)
   × (1 + fine_tune_premium_pct/100  if is_fine_tune else 0)
```

**Free tier:** subtracted from running daily counter per `(provider, api_key_fingerprint)`; surfaced in TUI as "$X (after $Y free tier)".

**Self-hosted models:** electricity cost via `[local_costs]` config:
```toml
[local_costs]
electricity_per_kwh = 0.12
gpu_idle_watts      = 50
gpu_active_watts    = 350
amortize_hardware   = false             # if true, prorate GPU $cost / lifetime hours
```
Joined with the GPU sidecar's wattage poll, yields `cost_usd` for Ollama/vLLM/llama.cpp calls.

**Currency display:** stored as USD canonically; UI converts via `[ui.currency]` (default = system locale) using daily ECB FX rates fetched on `tsctl prices update`.

**Price staleness:** every cost field tagged with `prices_version`; if `prices.toml` is > 14 days old, TUI shows `~$X` (tilde) and a banner.

**Pricing reconciliation:** `tsctl reconcile anthropic --csv usage.csv` compares TokenScope's computed cost vs the provider invoice; surfaces deltas and (likely) reveals untracked endpoints or pricing changes.

---

## 6. CLI & UX

```
# core
tsd                              # daemon (systemd unit ships in /etc/systemd/system/)
tsctl status                     # which probes attached, drop rate, throughput
tsctl doctor                     # full self-diagnostic (see §3.4)
tsctl reload                     # hot-reload config without restart
tsctl config check               # parse + validate config, print effective settings
tsctl version                    # CLI/daemon/BPF skeleton/schema versions

# probes
tsctl probes list
tsctl probes attach openai
tsctl probes detach openai
tsctl probes inspect ssl_uprobe  # disassembly, verifier log, attached pids

# live / query
tsctl tail [--filter 'provider=anthropic']
tsctl query "SELECT model, SUM(cost_usd) FROM calls WHERE ts > now() - interval 1 day GROUP BY 1"
tsctl tag <pid|cgroup> <project_hint>     # manual project attribution
tstop                            # ratatui dashboard
tstop --by cgroup|model|project|user
tstop --plain                    # screen-reader-friendly text mode (no box-drawing chars)
tstop --palette colorblind       # deuteranopia-safe palette
ts-web                           # localhost:7666 (htmx UI)

# privacy
tsctl capture allow <pid>        # opt-in raw payload capture for one process
tsctl capture revoke <pid>
tsctl redact test sample.json    # validate redaction rules against a file
tsctl redact rules               # list active redaction patterns

# data lifecycle
tsctl compact --since '24h ago'
tsctl vacuum
tsctl export prom                # one-shot prom dump
tsctl export otlp --endpoint ...
tsctl export parquet --since '7d ago' --out ./out/
tsctl import anthropic-csv usage.csv
tsctl import claude-code ~/.claude/projects
tsctl import pcap session.pcap

# alerts
tsctl alerts list                # show active alert rules
tsctl alerts test <rule>         # dry-run a rule against last 24h
tsctl alerts ack <id>
```

### 6.1 Alerting

Alerts are evaluated in the pipeline, not as cron — sub-second latency. Rules in config:

```toml
[[alerts]]
name = "anthropic_daily_budget"
match = { provider = "anthropic" }
window = "1d"
condition = "sum(cost_usd) > 50"
severity = "warning"
sinks = ["webhook:budget", "desktop"]

[[alerts]]
name = "runaway_agent"
match = { tool_calls_count_gte = 1 }
window = "1m"
condition = "count() > 100 AND distinct(prompt_hash) < 5"   # same prompt looping
severity = "critical"
sinks = ["webhook:pager"]

[alerts.sinks.webhook.budget]
url = "https://hooks.slack.com/..."
template = "slack-blocks"

[alerts.sinks.webhook.pager]
url = "https://events.pagerduty.com/v2/enqueue"
template = "pagerduty-v2"

[alerts.sinks.desktop]
type = "notify-send"          # uses libnotify on Linux
```

Built-in sinks: `webhook` (any HTTP POST, templated), `desktop` (libnotify), `email` (SMTP), `stdout` (for piping to other tools), `file` (append-only log). Plugin API (§8) lets users add more.

Alert state (firing / resolved) tracked in DuckDB `alert_history`; deduplication window per `(rule, fingerprint)`.

### 6.2 Accessibility & Inclusion

- `--palette colorblind` — deuteranopia/protanopia-safe palette across TUI, web UI, Grafana JSON.
- `--plain` — TUI without box-drawing characters; lines aligned with spaces; works in screen readers.
- All TUI controls reachable by keyboard alone (no mouse-required action).
- Web UI: WCAG 2.1 AA targets (color contrast ≥ 4.5:1, focus rings, semantic HTML, aria-labels on htmx-swapped regions).
- High-contrast theme (`--theme high-contrast`) for outdoor laptop use.

### 6.3 Telemetry (or rather, the lack thereof)

`tsd` makes **zero outbound network calls** by default. The only outbound traffic ever is to user-configured exporters (OTLP endpoint, webhook URLs, prices CDN if enabled). To verify:

```
tsctl doctor --check-egress     # asserts no outbound socket from tsd PID over 60s
strace -e trace=connect -p $(pidof tsd)   # also works
```

`prices.toml` updates are **opt-in**:
```toml
[prices]
auto_update = false             # default; you must `tsctl prices update` manually
update_url = "https://prices.tokenscope.dev/v1/prices.toml"
```
The default-off posture means there is no version of TokenScope that "phones home" — even for crash reports. If we ever add opt-in usage telemetry, it'll be a separate, clearly-named binary (`ts-telemetry`) that ships uninstalled.

### 6.4 First-Run Experience

The promise: **value within 5 minutes of `apt install tokenscope`** (or curl-pipe-bash for non-packaged systems). The first-run flow:

```
$ sudo systemctl start tokenscope
$ tstop

(if tsctl doctor would fail, tstop refuses to start and prints the doctor report)

(if everything is green, the TUI launches with a top banner)
┌─ Welcome to TokenScope ──────────────────────────────────────────────┐
│ No LLM traffic seen yet. Try:                                        │
│   curl https://api.anthropic.com/v1/messages \                       │
│        -H "x-api-key: $ANTHROPIC_API_KEY" -H "anthropic-version: ..."│
│        -d '{...}'                                                    │
│ or:                                                                  │
│   ollama run llama3.1 "say hi"                                       │
│ Press d for demo mode (replays a recorded session).                  │
└──────────────────────────────────────────────────────────────────────┘
```

**Demo mode** (`tstop --demo` or `d` keypress on first run): replays a curated 5-minute session of mixed Anthropic + Ollama + MCP traffic from `tests/fixtures/demo.tsdump` so a new user sees what the tool *can* show without needing to generate real traffic.

**`tsctl init`** — interactive wizard for advanced setup:
1. Detects user's likely workflows (Ollama running? Claude Code present? Sentry HOA repo nearby?)
2. Suggests sampling rules tailored to detected workloads
3. Optionally configures Prometheus/OTLP exporters
4. Optionally sets up Grafana dashboard import
5. Writes `~/.config/tokenscope/config.toml` with comments explaining every choice

**`tsctl uninstall`** — graceful removal:
- Detach all BPF programs
- Remove pinned maps from `/sys/fs/bpf/tokenscope/`
- Stop & disable systemd unit
- `--purge` flag also deletes DuckDB, audit log, config, `/var/lib/tokenscope/`
- `--keep-data` flag (default) preserves DB for reinstall
- Per-user data wipe: `tsctl forget --user <uid>` and `tsctl forget --pid <pid>` for GDPR right-to-erasure

**Friction-free upgrade:** `apt upgrade tokenscope` (or `tsctl self-update` if opted in) handles BPF skeleton swap atomically — `tsd` re-attaches to the pinned maps from the previous version, no data loss, no observed downtime > 100ms.

### 6.1 TUI sketch (`tstop`)

```
┌─ TokenScope ── kernel 6.6 ── 4 probes ── 0 drops/s ── uptime 3h12m ──┐
│                                                                       │
│  Provider          Reqs   Tok/s    p50    p95   $ /hr    Errors      │
│  anthropic-api     142   3.1k    412ms   1.8s   $4.20    0           │
│  ollama-local      891   12.4k    88ms   240ms   ----    2           │
│  openai-api         12    640    520ms   2.1s   $0.18    0           │
│                                                                       │
│  Top processes                                                        │
│   1. olivia.py             ollama       891 reqs   12.4k tok/s        │
│   2. claude (Code)         anthropic    102 reqs    2.8k tok/s        │
│   3. sentry-hoa-worker     anthropic     40 reqs    320 tok/s         │
│                                                                       │
│  Live tail  (j/k scroll, / filter, p pause)                           │
│  14:02:31  claude → anthropic  msg id_xx  in 1240t  out 89t  890ms    │
│  14:02:32  olivia → ollama     llama3.1   in 240t   out 18t   210ms   │
│  ...                                                                  │
└───────────────────────────────────────────────────────────────────────┘
```

---

## 7. Edge Cases & Failure Modes

This section is exhaustive on purpose. Anything not listed here is a discovery for v1 hardening.

### 7.1 Kernel & BPF
- **Kernel < 5.8:** ringbuf unavailable → fall back to perf buffer; warn user.
- **Kernel < 5.13:** no CO-RE for some struct fields → ship per-kernel `vmlinux.h` for top 20 distros; refuse to start otherwise with actionable error.
- **No BTF on host (`/sys/kernel/btf/vmlinux` missing):** fetch matching BTF from BTFHub at install; cache in `/var/lib/tokenscope/btf/`.
- **Lockdown mode (`kernel_lockdown=integrity`):** uprobes blocked → degrade to network-only mode, emit warning, document workaround.
- **SELinux/AppArmor:** ship policy snippets; document `setenforce 0` is not the answer.
- **BPF verifier rejection:** unit test every program against kernel matrix in CI (kernels 5.8, 5.10, 5.15, 6.1, 6.6, 6.11) using vng + qemu.
- **Verifier complexity limit (1M instructions):** keep programs small, push logic to userspace; use bpf2bpf calls and tail calls when needed.
- **Stack size cap (512B):** all big buffers in per-CPU arrays.
- **Map size limits:** ringbuf default 256KB → make configurable; auto-scale based on event rate.
- **Lost samples under burst:** track `dropped` counter per CPU; surface in TUI; auto-grow ringbuf if drops > 0.1% sustained.

### 7.2 TLS & encryption
- **Statically-linked OpenSSL (rare but exists):** symbol resolution via per-binary BTF; warn if symbol not found.
- **BoringSSL (Cloudflare, gRPC):** different symbol names → maintain symbol map.
- **Rustls (no libssl):** can't uprobe → must use kTLS path or app-level instrumentation.
- **Go `crypto/tls`:** Go runtime doesn't expose stable symbols across versions → use `goresym` to discover at attach time; pin per Go version.
- **Node.js TLS:** Node bundles OpenSSL → uprobe works on the bundled `.so` inside the Node binary.
- **Python with custom TLS (e.g., pyOpenSSL):** different code path → cover both stdlib `ssl` and `pyOpenSSL`.
- **HTTP/2 multiplexing:** multiple streams per TCP connection → must demux by stream ID from HEADERS frames.
- **HTTP/3 (QUIC over UDP):** **major gap** — UDP + userspace QUIC stacks (quinn, msquic) bypass kernel TCP probes; uprobe quiche/quinn `send`/`recv` symbols; fall back to userspace QUIC parsing.
- **gRPC streaming:** treat as long-lived connection; demux by gRPC frame.
- **Compressed responses (gzip, br):** decompress in userspace before token counting.
- **mTLS:** doesn't matter, we're below the cert layer.
- **TLS session resumption / 0-RTT:** still triggers SSL_read/write — covered.
- **Kernel TLS (kTLS):** SSL_write skipped → use `tls_sw_sendmsg` kprobe instead; auto-detect via socket option `TLS_TX`.
- **HTTP/1.1 keep-alive:** N requests over one TCP socket → request boundaries detected by `Content-Length` / `Transfer-Encoding: chunked` / `\r\n\r\n` framing in the parser.
- **HTTP/2 connection multiplexing:** N concurrent streams over one socket → state machine keyed by `(socket_cookie, stream_id)`; HEADERS + DATA + RST_STREAM + GOAWAY + WINDOW_UPDATE all handled.
- **Mid-stream client disconnect (Ctrl+C):** detect via `tcp_close` while a stream is open → mark call as `partial_completion`, count tokens up to disconnect, prorate cost.
- **Mid-stream server error:** Anthropic emits `event: error` after `message_start`; OpenAI emits `data: {error: ...}` then closes; both attribute partial cost (input always charged, output = tokens received before error).
- **Mid-stream rate limit:** rare but happens (`429` between SSE events) → captured the same way as mid-stream errors.
- **HTTP retries:** httpx/requests/openai-python auto-retry on 5xx and rate-limit. Same logical call = N wire calls. Detect via `Idempotency-Key` header (Anthropic & OpenAI both set this) or by matching `(pid, request_body_hash)` within a 60s window. Surface as `retries: N` on the parent record.
- **Connection pooling:** persistent HTTP/2 connections across long-running processes are normal — never assume "connection close = process done".
- **Server-Sent Events keep-alive comments:** `: keep-alive\n\n` lines must be tolerated, not parsed as data.
- **Transfer-Encoding: chunked + gzip:** dechunk before decompressing before parsing.
- **WebSocket upgrade:** `Upgrade: websocket` switches the socket out of HTTP framing; need separate WS frame parser (covered for OpenAI Realtime, Anthropic Batch polling, custom enterprise APIs).
- **HTTP/3 fallback negotiation:** Alt-Svc header advertises h3; if the next request goes UDP/QUIC, our TCP probes go silent — surface as `http3_blind_spot` warning per `(provider, endpoint)` until QUIC support lands.

### 7.3 LLM provider quirks
- **Anthropic streaming:** SSE with `event: message_start`, `content_block_delta`, `message_delta`, `message_stop` — parse all five.
- **OpenAI streaming:** SSE `data: {...}` then `data: [DONE]`.
- **Ollama:** newline-delimited JSON, not SSE.
- **Bedrock:** AWS SigV4 signed; payload is JSON inside a binary event-stream wrapper.
- **Vertex:** gRPC by default — needs HTTP/2 + protobuf parsing.
- **Azure OpenAI:** different URL shape; same wire format as OpenAI.
- **Cohere / Mistral / Together / Groq / Fireworks / OpenRouter:** each has subtly different SSE formats — maintain a `providers/` directory of parsers; each parser is ≤200 LoC.
- **Custom self-hosted (LocalAI, LM Studio, KoboldCpp):** OpenAI-compatible mostly; auto-detect via `/v1/models` probe.
- **Token counts in headers vs body:** Anthropic puts `usage` in final event; OpenAI in final delta; Ollama in `done: true` chunk.
- **Tool/function calls:** parse from `tool_use` blocks (Anthropic), `function_call`/`tool_calls` (OpenAI), Ollama `tool_calls`.
- **Vision/audio payloads:** can be huge (MB-scale images base64-encoded) — sample-and-hash, never store.
- **Embedding endpoints:** different cost model (per-token, no completion); track separately.

### 7.4 Process / cgroup
- **PID reuse:** PIDs wrap → key everything by `(pid, start_time_ns)` tuple.
- **fork() without exec():** child inherits FDs but we want to keep counters per child too — listen on `sched_process_fork`.
- **PID namespaces (containers):** kernel sees host PID; show both host and namespaced PID.
- **cgroup v1 vs v2:** detect at startup; only v2 supported in v1, document v1 fallback.
- **Containers without cgroup (rare):** group by parent PID heuristic.
- **Short-lived processes (<10ms):** still capture exec/exit; may miss request body if process exits before SSL_write returns.
- **Forking servers (gunicorn, uvicorn workers):** each worker is separate PID — aggregate by parent.
- **Threads:** use `tgid` (thread group leader) as the canonical "process".
- **Daemonized processes started before tsd:** scan `/proc` on startup, attach uprobes retroactively.

### 7.5 WSL2 specifically (your dev environment)
- **WSL2 kernel:** Microsoft custom kernel; verify BTF available — recent WSL kernels (5.15+) have it.
- **No systemd by default** in older WSL → ship plain init script too.
- **Cgroup v2** is default in WSL 2.0 but v1 in some configs — detect.
- **Networking:** WSL uses Hyper-V virtual switch; cgroup/connect hooks still work, but the destination IP may be the WSL NAT, not the real remote — resolve via `/etc/resolv.conf` + connection tracking.
- **No GPU passthrough by default:** GPU module disabled gracefully.
- **`/sys/kernel/btf/vmlinux` permissions:** require CAP_SYS_ADMIN or root in WSL.

### 7.6 Privacy & security
- **Prompt may contain secrets** (API keys pasted by user, PII, etc.) — never log raw payloads by default; payload capture is opt-in per-process via `tsctl capture allow PID`.
- **Redaction:** regex pack covers AWS keys, GCP keys, Anthropic keys (`sk-ant-...`), OpenAI keys (`sk-...`), GitHub tokens, JWTs, emails, SSNs, credit cards, IPs.
- **Hash mode:** SHA-256 of prompt for deduplication without content.
- **Differential privacy mode:** add Laplace noise to per-cgroup counters before export.
- **Egress control for tsd itself:** never make network calls except to OTLP/Prom endpoints user explicitly configured.
- **Capabilities:** drop everything except `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE` after BPF load. Never run as full root after init.
- **AppArmor / SELinux profile** ships in repo.
- **Replay attack on DuckDB file:** use SQLite WAL + checksums.

### 7.7 Performance & scale
- **Backpressure:** if userspace consumer falls behind, ringbuf drops events — emit `dropped_total` metric, throttle non-essential probes (e.g., disable payload capture before disabling counters).
- **CPU pinning:** consumer threads pinned to NUMA-local CPUs.
- **Memory cap:** `tsd` self-limits to 256MB by default; spills to DuckDB sooner under pressure.
- **Cardinality explosion:** if `model` label has > 1000 unique values, auto-bucket as `other`.
- **Clock skew:** all timestamps from kernel CLOCK_MONOTONIC + boot offset; never trust app clocks.
- **Hot loop in userspace parser:** Arrow + SIMD-accelerated JSON (simd-json crate); benchmark continuously in CI.

### 7.8 Operational
- **Probe panic in kernel:** verifier should prevent, but if a kprobe fires too hot and stalls — auto-detach after 10 lost-event windows.
- **Self-observability loop:** `tsd` itself uses LLM clients (for anomaly detection labels) → MUST exclude its own PID from probes to avoid recursion.
- **Cost data staleness:** `prices.toml` cron updates weekly; show "prices N days old" warning.
- **Time travel:** if user changes system clock backward, DuckDB queries break — use monotonic + boot UUID.
- **Disk full:** auto-rotate, refuse new writes, surface warning.
- **OOM killer targets tsd:** set `oom_score_adj = -500`.
- **Upgrade in place:** new tsd reattaches probes from old tsd's pinned BPF maps (atomic handoff).

### 7.9 Testing edge cases
- **Property-based testing** (proptest) for SSE parsers across providers.
- **Fuzzing** the TLS payload parser with cargo-fuzz.
- **Chaos:** random ringbuf drops, OOM injection, kernel module unload, network partition.
- **Recorded traces:** `tests/fixtures/` contains pcap + ringbuf dumps from real Anthropic/OpenAI/Ollama sessions; replay them in CI without network.
- **Kernel matrix:** vng + qemu running test suite on 6 kernel versions every PR.

### 7.10 Threat Model

**Assets:** prompt content (often contains PII / secrets), API keys, cost data, process command lines (may leak args), DuckDB file (aggregated history).

**Adversaries we protect against:**
| Adversary | Capability | Mitigation |
|-----------|------------|------------|
| Curious local user (non-root) | reads `~/.local/share/tokenscope/` | data_dir mode 0700; world-readable disabled |
| Malicious app on the same host | wants to feed false events | events come from kernel — apps can't forge ringbuf records; uprobes on the app's own libssl can be evaded by the app, that's the app's choice (it's their data) |
| Compromised `tsd` itself | malicious BPF program loaded | drop privileges post-load; sign release artifacts; reproducible builds; SELinux/AppArmor profile constrains tsd to its data dir + exporter sockets |
| Network attacker | sees outbound exporter traffic | TLS-only OTLP/webhook; document mTLS setup |
| Supply chain (cargo deps) | malicious crate | `cargo-vet` + `cargo-deny`; minimal dep tree; no proc-macro deps where avoidable |
| Side-channel (timing of events leaks prompt content) | exists in theory | acknowledged; differential-privacy mode for export aggregates |

**Adversaries explicitly out of scope:**
- Root-on-host attacker — game over for everything, not just TokenScope.
- Hardware attacker (cold boot, DMA) — out of scope.
- Compromised kernel — out of scope (TokenScope trusts the kernel by definition).

**Sensitive-data handling principles:**
1. Plaintext prompts never leave the host unless `capture allow` was issued AND an exporter is configured AND `redact_before_export = true` is satisfied.
2. API keys observed in HTTP headers are *immediately* hashed (SHA-256 prefix) at parse time — never written to memory after that, never to disk, never to logs.
3. Crash dumps scrub all observed-prompt strings before write.
4. Audit log records every privileged operation, with operator UID and timestamp.

### 7.11 Daemon Failure Modes

**`tsd` crashes:**
- BPF programs stay loaded (pinned in `/sys/fs/bpf/tokenscope/`); ringbuf fills.
- New `tsd` on restart picks up the pinned programs (atomic handoff) and resumes draining within 100ms.
- If pinning fails (e.g., bpffs not mounted), programs detach on crash → small data gap acceptable.
- systemd `Restart=on-failure` with exponential backoff (1s, 2s, 5s, 30s, max 5m).
- After 10 consecutive crashes, systemd stops trying and emits `tokenscope-failed.service` for monitoring.

**Watchdog:** systemd `WatchdogSec=30s`; `tsd` pings sd_notify every 10s. Missed pings → SIGABRT → restart with core dump.

**Out-of-memory:** `MemoryMax=512M` in unit; on hit, in-process pressure-stall detector starts shedding load (disable payload capture → drop sampling rate → drop non-essential probes → finally exit cleanly).

**Disk full:** `tsd` reserves 1 GB headroom check; below that, refuses new DuckDB writes, keeps emitting to exporters, surfaces `disk_full` alert.

**Probe storms:** if a single probe fires > 1M times/sec for > 30s (likely a bug), auto-detach with warning; user must `tsctl probes attach` to re-enable.

**Self-attribution loop:** `tsd` is added to a hard exclusion list; its own LLM clients (anomaly labeler) are also excluded by PID. Verified by integration test that runs `tsd` calling Anthropic and asserts no events.

**Resource confinement:** `tsd` runs in its own cgroup (`/sys/fs/cgroup/tokenscope.slice/`) with CPU quota (200% = 2 cores), memory cap, and tasks limit. Documented `systemd-cgtop` query for verification.

**Time zone:** all DB timestamps stored as UTC `BIGINT` ns since epoch. Render pass uses `chrono-tz` with `[ui.timezone]` config (default = system TZ). Round-trips preserved.

### 7.12 Compliance & Regulatory

TokenScope is the kind of tool a regulated org *needs* to use to meet their AI logging obligations — but only if it doesn't itself create new compliance burdens. The design choices that make it compliance-friendly:

**GDPR (EU 2016/679):**
- **Lawful basis:** organizations deploying TokenScope are the data controller; the tool itself is a processor. Default-off payload capture means no personal data leaves processes unless explicitly enabled per-PID.
- **Data minimization:** redaction applied *before* persistence; raw payload paths optional; prompt hashes used in lieu of content for dedup.
- **Right to erasure:** `tsctl forget --user <uid>` and `tsctl forget --request <id>` purge from DuckDB + audit log + exported sinks (where supported).
- **DPA template:** ships in `docs/compliance/gdpr-dpa-template.md`.
- **Cross-border transfer:** zero-egress default means no Schrems II issue unless user configures an exporter.

**HIPAA (US 45 CFR Part 160/164):**
- TokenScope is **BAA-ready** (no telemetry, no third-party dependencies that touch payloads).
- Documented HIPAA deployment guide: encryption at rest (LUKS or DuckDB encryption when available), TLS for all exporters, audit log retention 6 years.
- Redaction pack includes PHI patterns (MRN, ICD-10, NDC, NPI, DEA number) — opt-in via `redaction_pack = "hipaa"`.

**SOC 2 (Trust Service Criteria):**
- **Security:** capability minimization, signed binaries, reproducible builds, AppArmor/SELinux profiles.
- **Availability:** systemd watchdog, atomic restart, `/healthz` endpoint.
- **Processing integrity:** schema-validated config, audit log of every privileged action.
- **Confidentiality:** payload capture opt-in per-process, encryption-at-rest documented.
- **Privacy:** no telemetry, GDPR alignment.

**EU AI Act (Regulation 2024/1689, effective phased through 2026-2027):**
- Article 12 (record-keeping) requires automatic event logs for high-risk AI systems for the system's lifetime (min 6 months). TokenScope is *purpose-built* for this — explicit positioning in marketing materials.
- Article 13 (transparency) — TokenScope provides the "operational characteristics" data (cost, latency, error rates) regulators expect.
- Annex IV (technical documentation) — TokenScope's exports plug into the documentation template.

**Other frameworks:**
- **NIST AI RMF**: TokenScope output maps to MEASURE/MANAGE functions (cost, drift, anomaly).
- **ISO/IEC 42001 (AI management systems)**: artifact-grade audit trail.
- **PCI-DSS**: redaction pack covers PAN, CVV, track data; never persisted.
- **CCPA/CPRA**: same erasure mechanics as GDPR.

**Limitations stated honestly:**
- TokenScope sees what crosses the kernel; it cannot attest to *what the model did with the data after*.
- Compliance certifications (SOC 2 report, HIPAA attestation) cover the *organization* deploying TokenScope, not TokenScope itself; we provide the technical controls and documentation, not the audit.
- Out of scope: residency enforcement (we report; we don't block); model bias auditing (different category of tool).

---

## 8. Plugin & Extension API

Stable from v1.0. Defined as Rust traits *and* a WASM ABI so non-Rust authors can ship plugins without rebuilding `tsd`.

### 8.1 Extension points

| Trait | Purpose | Examples |
|-------|---------|----------|
| `ProviderParser` | Parse SSE/JSON for a new LLM provider | Mistral, Cohere, Together, Replicate, custom internal |
| `RedactionRule` | Custom regex/AST-based redaction | Company-specific PII, internal IDs, JWTs |
| `Exporter` | Push enriched records elsewhere | Kafka, Loki, S3, ClickHouse, Slack |
| `AlertSink` | Deliver alerts | PagerDuty, OpsGenie, Discord, ntfy.sh |
| `Tagger` | Derive `project_hint` from process metadata | k8s annotations, AWS tags, custom heuristics |
| `Anomaly` | Custom anomaly detector | per-team baselines, regression vs deploy markers |
| `CostModel` | Override cost calc per provider | reserved-capacity pricing, BYO-API discounts |

### 8.2 Loading

```toml
[plugins]
dir = "/etc/tokenscope/plugins.d"      # native .so / .wasm files

[[plugins.load]]
path = "tokenscope-mistral.wasm"
config = { api_format = "v1" }
```

Native plugins: `cdylib`, must export `ts_plugin_register` symbol returning a vtable. WASM plugins: `wasi:` ABI, run in `wasmtime` sandbox with capability-scoped host imports (no filesystem unless granted).

### 8.3 Plugin manifest

```toml
# in the plugin crate
[package.metadata.tokenscope]
name = "tokenscope-mistral"
api_version = "1.0"           # the host API version it targets
extends = ["ProviderParser"]
permissions = []              # WASM only; e.g., ["net:outbound", "fs:read:/etc"]
```

### 8.4 Versioning & isolation

- Plugin loaded against API ≠ host: refused with diff explanation.
- Plugin panic in native mode: `tsd` catches via `catch_unwind`, disables the plugin, continues.
- Plugin panic in WASM mode: trapped, plugin disabled, `tsd` unaffected.
- Plugin ABI semver from v1.0 onward.

### 8.5 Built-in plugin SDK

- `cargo new --template tokenscope/plugin` scaffolds a working ProviderParser plugin.
- `tsctl plugins test ./my-plugin.wasm < fixtures/openai.sse` runs the plugin against recorded fixtures.
- Conformance test suite that any `ProviderParser` plugin must pass before being marked stable.

---

## 9. Comparison vs Prior Art

| Capability | TokenScope | Pixie | Helicone | Langfuse | Langsmith | Datadog LLM Obs | OpenLLMetry |
|------------|:----------:|:-----:|:--------:|:--------:|:---------:|:---------------:|:-----------:|
| Zero-instrumentation (no SDK) | ✅ | ✅ | ❌ proxy | ❌ SDK | ❌ SDK | ⚠️ APM agent | ❌ SDK |
| Sees encrypted cloud LLM traffic | ✅ uprobe | ⚠️ partial | ✅ proxy | ❌ | ❌ | ⚠️ APM | ❌ |
| Local LLM (Ollama/vLLM/llama.cpp) | ✅ | ❌ | ❌ | ⚠️ if SDK wraps | ⚠️ | ❌ | ⚠️ |
| MCP / agentic tool-call tracing | ✅ | ❌ | ⚠️ | ✅ | ✅ | ⚠️ | ✅ |
| Real-time TUI | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Single-host, no cloud account | ✅ | ❌ k8s | ❌ SaaS | ⚠️ self-host | ❌ SaaS | ❌ SaaS | ⚠️ |
| Cost accounting per cgroup/pod/user | ✅ | ❌ | ⚠️ per-key | ⚠️ per-project | ⚠️ | ✅ | ⚠️ |
| Open source | ✅ | ✅ | ⚠️ partial | ✅ | ❌ | ❌ | ✅ |
| Sub-1% overhead | ✅ target | ✅ | ❌ proxy hop | n/a | n/a | ❌ APM tax | n/a |
| Privacy-first (no payload by default) | ✅ | ✅ | ❌ | ⚠️ | ⚠️ | ⚠️ | ⚠️ |
| HTTP/2 + HTTP/3 (planned) | ✅ / ⏳ | ✅ / ❌ | ✅ / ✅ | n/a | n/a | ✅ / ⚠️ | n/a |

**Legend:** ✅ first-class · ⚠️ partial / requires work · ❌ not supported · ⏳ on roadmap

**Closest competitor:** Pixie. Differences — TokenScope is LLM-specialized (provider parsers, token/cost accounting, agentic semantics), runs single-host without k8s, ships a TUI, and explicitly targets the personal/dev-machine use case in addition to production.

**Relationship to app-layer LLM obs (Langfuse/Helicone/Langsmith):** complementary. Those tools see what the app *intended*; TokenScope sees what actually crossed the network. Together they catch SDK bugs, retries the app didn't log, and "we forgot to wrap that one client" gaps.

---

## 10. Performance Targets

| Metric | v1 target | v2 target |
|--------|-----------|-----------|
| CPU overhead at idle | < 0.1% | < 0.05% |
| CPU overhead at 1k req/s | < 1% | < 0.5% |
| Memory RSS steady | < 128 MB | < 64 MB |
| Event drop rate at 10k ev/s | < 0.01% | 0% |
| Time-to-first-event after start | < 200 ms | < 100 ms |
| TUI refresh latency | < 16 ms (60fps) | same |
| DuckDB query p95 (24h window) | < 200 ms | < 100 ms |
| Binary size (stripped) | < 15 MB | < 10 MB |

Continuous benchmark in CI using `criterion` + `oha` load gen against a mock LLM server.

---

## 11. Roadmap

### Phase 0 — Foundations (Week 1)
- Repo scaffold (cargo workspace: `tsd`, `tsctl`, `tstop`, `ts-bpf`, `ts-core`).
- libbpf-rs + skeleton build pipeline (clang → BPF → embed via `build.rs`).
- vmlinux.h generation + BTFHub fetch script.
- One trivial probe (`sched_process_exec`) end-to-end through ringbuf to stdout.
- CI on GitHub Actions with vng kernel matrix.

### Phase 1 — Network MVP (Week 2-3)
- `cgroup/connect4` + `tcp_sendmsg`/`tcp_recvmsg` byte counting.
- Process enrichment via `/proc` + sched tracepoints.
- DuckDB sink with daily partitioning.
- `tsctl status` and `tsctl tail`.

### Phase 2 — TLS plaintext (Week 4-5)
- `uprobe:SSL_write` / `SSL_read` for OpenSSL.
- HTTP/1.1 + HTTP/2 demuxer in userspace.
- Anthropic + OpenAI + Ollama parsers.
- Cost calculation from `prices.toml`.
- `tstop` TUI v1.

### Phase 3 — Polyglot TLS (Week 6-7)
- Go runtime symbol resolution (goresym integration).
- BoringSSL / gnutls / Node bundled OpenSSL.
- HTTP/2 stream demux.
- 5 more provider parsers (Gemini, Bedrock, Mistral, Groq, Cohere).

### Phase 4 — Local engines deep dive (Week 8)
- Ollama Go uprobes.
- vLLM Python USDT.
- llama.cpp uprobes.
- Token-count fallback when usage field absent (BPE tokenizer in userspace).

### Phase 5 — Exporters & integrations (Week 9)
- Prometheus exporter.
- OTLP exporter (logs + metrics + traces).
- `ts-web` minimal HTMX UI.
- Grafana dashboard JSON shipped in repo.

### Phase 6 — Anomaly detection (Week 10)
- Statistical baselines per (provider, model, cgroup).
- Rate-limit prediction (linear regression on remaining tokens).
- Prompt-injection signature pack (heuristic + optional local LLM scoring).
- Runaway agent detection (tool-call loop > N).

### Phase 7 — Hardening (Week 11-12)
- Full kernel matrix CI green.
- Chaos / fuzz / property test suite.
- Security audit (cargo-audit, clippy::pedantic, capability minimization).
- Docs site (mdbook).
- v1.0.0 tag.

### Phase 8+ — Stretch (months 4-6)
- HTTP/3 / QUIC support via uprobes on quinn/msquic.
- Multi-host aggregation via OTLP collector.
- Policy enforcement (XDP) — block requests over budget.
- Web UI with flame graphs (per-request waterfall).
- Cost forecasting (Prophet / simple LSTM).
- VS Code extension showing live LLM cost in status bar.
- macOS port via DTrace + Endpoint Security framework.
- Distribution: Homebrew, AUR, deb, rpm, container image, Helm chart.

---

## 12. Risks & Mitigations

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Verifier rejects programs on some kernels | High | High | Kernel matrix in CI from day 1 |
| Static-binary apps invisible to uprobes | High | Medium | Document; offer LD_PRELOAD fallback shim |
| HTTP/3 adoption makes TCP probes obsolete | Medium | High | Phase 8 QUIC support; track adoption |
| Anthropic/OpenAI change wire format | Low | Medium | Versioned parsers; integration tests against real APIs (cheap) |
| WSL2 kernel quirks block features | Medium | Medium | Detect + degrade gracefully; document |
| Solo project bandwidth | High | High | Phase gates; ship Phase 2 as "useful" milestone — everything after is bonus |
| Privacy concern from users | Medium | High | Default-off payload capture, redaction first-class, audit log |
| Performance regression sneaks in | Medium | Medium | criterion benchmarks gate every PR |

---

## 13. Success Criteria

**v1.0 ships when all of these are true:**
- Runs on stock Ubuntu 22.04 + 24.04 + Fedora 40 + Arch + WSL2 Ubuntu without manual setup.
- Captures 99% of Anthropic + OpenAI + Ollama traffic on the dev box for one week with < 1% CPU.
- Zero panics, zero kernel oops, zero data loss in 7-day soak test.
- Test coverage > 80% lines, 100% on parsers.
- Docs cover: install, first run, every CLI command, BPF debugging, contributing.
- One blog post + HN/Lobsters launch.

**Personal success:**
- I can answer "how much did I spend on Claude this week, by project" in 1 second.
- I understand BPF, TLS internals, and CO-RE deeply enough to debug other people's eBPF code.
- The repo gets ≥ 100 GitHub stars OR I get one job inquiry citing it.

---

## 14. Day in the Life — User Scenarios

Concrete narratives that the spec must satisfy. Each is a contract for the UX promises in §6 and §3.6.

### 14.1 Solo dev — "What did Olivia cost me last night?"

**Persona:** Hoang, owner of `~/personal_proj/olivia` running local Ollama + occasional Anthropic fallback.

**Tuesday morning, 9 AM.** I open a terminal:
```
$ tstop --by project --since 'last night'
```
The TUI shows:
```
project          provider     reqs   tok/s    cost     errors
olivia           ollama       4,231  8.2k     $0       0
olivia           anthropic    18     n/a      $0.42    0
sentry-hoa       anthropic    2      n/a      $0.05    0
claude (Code)    anthropic    47     n/a      $1.89    1
```
I press `enter` on `olivia / anthropic`, see all 18 calls, sort by cost, find one runaway 30k-token retry loop. Ten minutes later I've patched the `max_tokens` cap in `start.sh`.

**What this scenario forces the spec to deliver:**
- `tstop --by project` with auto-detected `project_hint` from cwd / git_repo
- Time-range parsing of natural language ("last night")
- Drill-down navigation in TUI
- Per-call detail view including request body (gated by capture allow)

### 14.2 Team lead — "Per-customer Anthropic spend for Sentry HOA"

**Persona:** Hoang again, but as the operator of Sentry HOA SaaS (multi-tenant, each HOA = a tenant).

**Sunday morning weekly review.** Sentry HOA workers are tagged with `[tags] hoa_id = "$HOA_ID"` per request via `tsctl tag`:
```
$ tsctl query "
    SELECT
      project_hint AS hoa,
      COUNT(*) AS calls,
      SUM(prompt_tokens) AS in_tok,
      SUM(completion_tokens) AS out_tok,
      ROUND(SUM(cost_usd), 4) AS cost_usd
    FROM calls
    WHERE provider='anthropic' AND ts > now() - INTERVAL 7 DAY
    GROUP BY 1 ORDER BY 5 DESC LIMIT 20
  "
```
Output is a table I paste into the customer billing reconciliation. Two HOAs are 3× the median — opportunity to upsell or add per-tenant rate limits.

**What this scenario forces the spec to deliver:**
- `tsctl tag` accepts arbitrary key-value pairs propagated to subsequent calls from a PID/cgroup
- `tsctl query` supports interactive SQL with friendly errors
- Cost accuracy reconciles against Anthropic's invoice (`tsctl reconcile`)
- Multi-tenant attribution survives forking workers

### 14.3 Platform engineer — "There's a runaway agent in prod, page me"

**Persona:** SRE running k8s with TokenScope DaemonSet. A Claude Agent SDK service starts spinning a tool-use loop calling the same MCP `web.search` 200 times in 60 seconds.

**3 AM Tuesday.** Alert rule from §6.1:
```toml
[[alerts]]
name = "agent_loop"
match = { tool_calls_count_gte = 1 }
window = "60s"
condition = "count() > 50 AND distinct(prompt_hash) < 5"
sinks = ["webhook:pager"]
```
fires within 90 seconds of the loop starting. PagerDuty wakes the on-call SRE; the alert payload includes pod name, namespace, the offending tool name, and a deep link to `ts-web` showing the call tree. SRE kills the pod from kubectl. Postmortem the next morning uses TokenScope's `tstop --tree --pid <X>` to confirm the trigger prompt.

**What this scenario forces:**
- Sub-100s alert latency
- Webhook templating with structured payload (PagerDuty v2 schema)
- Pod/namespace enrichment from §3.6
- Persisted call tree visualization

### 14.4 Security engineer — "Did anyone exfiltrate via prompt?"

**Persona:** SecOps reviewing TokenScope's audit log after a phishing-flag-in-Slack incident.

**Question:** "Did the compromised employee's laptop send our customer database via Claude?"

**Workflow:**
1. `tsctl query "SELECT id, ts, model, prompt_tokens FROM calls WHERE uid=1042 AND provider='anthropic' AND ts BETWEEN '...' AND '...' AND prompt_tokens > 5000"`
2. For the 7 large-prompt calls, `tsctl show <id>` reveals redacted prompts (raw payloads were not captured for that user — design intent).
3. The redaction summary shows `[1247 redacted: emails]` and `[83 redacted: credit-cards]` — strong signal of customer data.
4. Audit log proves no one had `capture allow` for that user, so raw data never hit disk.
5. Incident report cites TokenScope as the detection tool; security team gets evidence without privacy violation.

**What this scenario forces:**
- Per-UID query support
- Redaction summary stored alongside the redacted text (counts by category)
- Tamper-evident audit log
- The privacy-first default *being* the security feature

---

## 15. References & Prior Art

- **libbpf-bootstrap** — https://github.com/libbpf/libbpf-bootstrap
- **libbpf-rs** — https://github.com/libbpf/libbpf-rs
- **Liz Rice, "Learning eBPF"** (O'Reilly, 2023)
- **Brendan Gregg, "BPF Performance Tools"** (Addison-Wesley, 2019)
- **bcc tools `sslsniff.py`** — proves the SSL_write uprobe technique
- **Pixie** (px.dev) — closest prior art; full APM via eBPF
- **Parca** — continuous profiling via eBPF
- **Tetragon** (Cilium) — security observability via eBPF
- **Kepler** — energy accounting via eBPF
- **Helicone / Langfuse / Langsmith** — app-layer LLM obs (what TokenScope complements)
- **BTFHub** — https://github.com/aquasecurity/btfhub
- **goresym** — https://github.com/mandiant/GoReSym
- **Anthropic streaming spec** — https://docs.anthropic.com/en/api/messages-streaming
- **OpenAI streaming spec** — https://platform.openai.com/docs/api-reference/streaming

---

## 16. Open Questions

1. **License:** Apache-2.0 vs AGPL-3.0? AGPL protects against closed forks but limits adoption.
2. **Naming collision:** check `tokenscope` against npm/PyPI/cargo/GitHub. Backup names: `lmtrace`, `pulsellm`, `ebpfllm`, `llmprobe`.
3. **Funding/sustainability:** OSS forever, or eventual hosted SaaS for multi-host? Decide before v1.
4. **Hosted demo:** can we provide a public sandbox? Probably no — it's a host agent.
5. **Telemetry on tsd itself:** opt-in usage stats? Probably no — privacy-first project shouldn't.

---

## 17. Glossary

- **BPF / eBPF:** in-kernel sandboxed VM for safe programmable extensions.
- **CO-RE:** Compile Once, Run Everywhere — using BTF to relocate field offsets at load time.
- **BTF:** BPF Type Format — kernel + program type metadata.
- **kprobe:** dynamic instrumentation of kernel function entry/exit.
- **uprobe:** same, but for userspace functions.
- **ringbuf:** lock-free MPSC queue from kernel to userspace, replaced perf buffer in 5.8.
- **CO-RE relocations:** allow BPF programs to read fields whose offsets differ across kernel versions.
- **SSE:** Server-Sent Events — `text/event-stream` format used by Anthropic/OpenAI streaming.
- **kTLS:** TLS offloaded to kernel; bypasses userspace OpenSSL after handshake.
- **cgroup BPF:** programs attached to cgroup hierarchy for per-container observability/policy.
- **TGID:** Thread Group ID — what userspace calls "PID".
- **TTFT:** Time To First Token.

---

*End of spec. Ship it.*
