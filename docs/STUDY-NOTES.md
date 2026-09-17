# EBPFCA Study Notes

These notes are for explaining the project confidently, not memorising every line. Start with the story, then trace a single signal through the code.

## 1. The core story

EBPFCA answers: **“Is this Linux host slow, and what measurements support the likely reason?”**

The agent combines two sources:

- `/proc` is the Linux virtual filesystem containing convenient host and process counters. It gives CPU totals, memory availability, disk/network byte totals, and process statistics.
- eBPF observes selected kernel events. It adds details that ordinary periodic `/proc` polling does not provide well, such as scheduler activity, page-fault counts, and request-to-completion disk latency.

The Go process converts these inputs into current state and rates. It exports Prometheus metrics and applies visible rules such as “CPU is high and context switches are high.” Grafana then charts the stored values.

## 2. Linux foundations

### Process, thread, PID, and command name

A **process** is a running program with a PID. A process can own multiple threads. Linux schedules threads; many kernel tracepoints use the word `pid` even when the value is the task/thread identifier. `comm` is a short task name, limited to 16 bytes. It is useful for display but not a secure or unique application identity.

### CPU usage

CPU usage is calculated from the change in CPU time, not a single value. In `/proc/stat`, Linux reports cumulative jiffies spent in user, system, idle, I/O wait, interrupt, soft interrupt, and steal states. The agent compares two readings:

```text
CPU% = (1 - idle_delta / total_delta) × 100
```

A host can show 100% even with several cores; that means all available aggregate CPU time was busy in the interval. Per-process percentages are normalized by CPU count in this project, so they express a share of whole-host capacity.

### Scheduler and context switch

A **context switch** is the scheduler stopping one runnable task and selecting another. Some switching is normal. A very high rate can mean many competing tasks, lock contention, short CPU bursts, or a load generator such as `stress-ng --switch`. It is not automatically a bug; EBPFCA only treats it as evidence combined with other signals.

### Memory and page faults

Virtual memory lets a process use addresses that are not currently resident in RAM. A **page fault** happens when the CPU accesses a page that needs resolution. Minor faults may be cheap; major faults can require disk I/O. High page-fault volume with low available memory can suggest pressure or thrashing. High faults alone are not proof of an out-of-memory condition.

`MemAvailable` is more useful than “free memory”: Linux intentionally uses spare RAM as cache. EBPFCA computes memory used from `MemTotal - MemAvailable`.

### Disk I/O latency

The block layer receives I/O requests. EBPFCA stores an issue timestamp in `disk_start`, then subtracts it when the completion tracepoint arrives. The result is block request latency in nanoseconds, converted to milliseconds in Go. The implementation uses a request pointer as the map key. This is a practical correlation key for the tracepoints but should be reviewed if adapting the project across unusual kernel/storage stacks.

### TCP and network

TCP is connection-oriented. The `inet_sock_set_state` tracepoint reports state changes; EBPFCA records connects and closes. Packet-path tracepoints count receive/transmit events. `/proc/net/dev` provides byte totals. Event counts are not byte throughput, so the project reports them as activity rates; byte counters remain the source for actual transferred data.

## 3. eBPF from scratch

eBPF is a constrained virtual machine inside the Linux kernel. A small program attaches to an approved hook and can read safe context, use helper functions, and communicate through maps. Before it runs, the kernel verifier checks that the program terminates, accesses memory safely, and follows the allowed instruction rules.

### Why tracepoints?

Tracepoints are named kernel events intended for instrumentation. They are generally more stable than kprobes, which depend on internal kernel function names and signatures. This project attaches tracepoints using `github.com/cilium/ebpf/link.Tracepoint`.

### Maps used here

- **Ring buffer `events`**: sends lower-volume, detailed process, disk, and TCP events to Go.
- **Hash map `disk_start`**: remembers an I/O start time until matching completion.
- **Per-CPU array `counters`**: counts extremely frequent events without the overhead of emitting every event. Each CPU updates its own counter, and Go sums them.

### BTF and `vmlinux.h`

BTF (BPF Type Format) exposes kernel type metadata. `bpftool btf dump ...` generates `vmlinux.h`, which lets the eBPF C code use the precise tracepoint context types for the running kernel. Regenerate it after a kernel change. The repository contains a minimal fallback header so source control and basic builds remain usable; the generated header is preferred on the target host.

### Important eBPF rule of thumb

Do as little work as possible in the kernel. Filtering, formatting, reports, and HTTP belong in Go. Kernel work should be bounded: increment, timestamp, copy a small fixed-size payload, or update a map.

## 4. Go architecture

The Go packages follow a simple pipeline:

1. `cmd/ebpfca/main.go` reads configuration and starts goroutines.
2. `internal/ebpf` loads the BPF object, attaches tracepoints, decodes ring-buffer records, and sums per-CPU counters.
3. `internal/collector` polls `/proc`, consumes detailed events, and pushes values into state.
4. `internal/state` protects shared data with `sync.RWMutex`, snapshots it, sorts processes, and calculates rates using deltas over elapsed time.
5. `internal/detector` emits threshold signals.
6. `internal/rca` correlates signals and builds evidence strings.
7. `internal/reporter` stores reports in memory and JSON files, with a cooldown to avoid report spam.
8. `internal/metrics` exposes Prometheus gauges/counters.
9. `internal/api` provides JSON endpoints and a small live status page.

### Why a mutex?

The host sampler, event reader, metrics synchronizer, RCA ticker, and HTTP handler run concurrently. Without synchronization, one goroutine could read a map while another changes it, causing data races or crashes. `RWMutex` permits many readers while retaining safe exclusive writes.

### Why `context.Context`?

The main program creates a context cancelled by SIGINT/SIGTERM. Long-running goroutines watch it and stop cleanly. This prevents abandoned background work during shutdown.

## 5. Prometheus and Grafana

Prometheus uses a pull model: it asks the agent for `/metrics` every five seconds. A **gauge** can rise or fall (CPU %, memory %, current connection count). A **counter** only increases during a process lifetime (incident count). Labels add dimensions, such as `pid` and `comm` for process metrics.

Grafana queries Prometheus; it does not receive data directly from the agent. Its dashboard definitions are JSON files provisioned at startup. `topk(10, ebpfca_process_cpu_percent)` is PromQL meaning “show the ten highest process CPU series.”

## 6. Detection and RCA

An anomaly detector answers **what is unusual**. Root cause analysis answers **what combination best explains it**. These are not the same.

Example high-CPU rule:

```text
CPU ≥ threshold + high context switches + dominant process
  → High CPU Usage
  → root cause: Excessive context switching
  → evidence: CPU %, switch rate, top PID CPU
```

The output says **suspected** root cause. It does not claim mathematical certainty. The evidence list makes the conclusion reviewable.

## 7. Docker and Fedora SELinux

Docker Compose starts Prometheus and Grafana. They use host networking so Prometheus can reach the native agent at `127.0.0.1:9090`. The eBPF agent service is optional (`profiles: ["agent"]`) because a native agent is easier to develop and debug.

Fedora SELinux labels file access. The `:z` suffix on bind mounts tells Docker to label shared project files for container use. Without it, a service may start and then fail to read its configuration.

## 8. Interview questions to practise

### Why eBPF instead of only `/proc`?

`/proc` gives excellent periodic aggregate counters, but it cannot directly correlate a specific block I/O issue and completion or observe every scheduler transition. eBPF supplements it with kernel event visibility. It does not replace `/proc`; the project uses both where each is strongest.

### Why use a ring buffer and counters together?

A ring buffer gives details but can become expensive at very high event rates. A per-CPU counter is cheap for frequent signals. EBPFCA emits only selected details and aggregates scheduler/page-fault/network activity with counters.

### How would you make it production-grade?

Add endpoint authentication/TLS, alert delivery/Alertmanager, durable incident storage, better process identity (cgroup/container metadata), cardinality controls, versioned configuration, integration tests on target kernels, observability for the agent itself, and a stronger privilege model than a blanket privileged container.

### What happens when `stress-ng --cpu` runs?

CPU time increases in `/proc/stat`; the host collector calculates a larger CPU delta. The process collector sees `stress-ng` use more jiffies. Scheduler counters may rise. Prometheus stores the exported values. If thresholds are exceeded, detector signals flow into RCA, which creates an incident containing the actual observed numbers.

## 9. Study drill

Follow one scheduler signal end-to-end:

```text
tp_sched_switch in bpf/ebpfca.bpf.c
→ counters map
→ Loader.ReadCounters
→ HostSampler
→ Store.RecordEBPF / Store.RecalcRates
→ Exporter.Sync
→ ebpfca_context_switches_per_sec
→ Grafana System Overview panel
```

If you can explain this path aloud, describe the technology choices, and run the live demo, you can confidently defend the project in an interview.
