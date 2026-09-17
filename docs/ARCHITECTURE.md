# Architecture

## Data flow

```text
Linux tracepoints             /proc files
      │                           │
      ▼                           ▼
eBPF programs ─ Ring Buffer ─ Event collector    Host collector
                       │                 │            │
                       └─────────────────┴────────────┘
                                         ▼
                              thread-safe State Store
                                 │             │
                                 ▼             ▼
                          RCA / incident     Prometheus exporter
                                 │             │
                                 ▼             ▼
                           JSON + files    Prometheus → Grafana
```

The BPF side does only small, safe kernel operations: increment a counter, record an I/O start time, or emit a compact event. The Go process does the heavier aggregation and presentation work in user space.

## Why this shape

- **Tracepoints** provide stable named kernel instrumentation points.
- **Ring buffer** carries occasional detailed events efficiently to user space.
- **Per-CPU counter map** avoids emitting an event for every scheduler switch/page fault, which would create unnecessary overhead.
- **`/proc`** supplies established host-wide counters and process metadata inexpensively.
- **Prometheus pull model** keeps metrics storage separate from the host agent.
- **Rules** are inspectable: every incident links directly to measurements.
