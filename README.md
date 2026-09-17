# EBPFCA — Linux eBPF Root Cause Analysis Platform

EBPFCA is a single-host Linux observability platform. It combines a Go agent, eBPF tracepoints, Prometheus, and Grafana to show real-time host health and produce evidence-backed, rule-based incident reports.

It is deliberately scoped for one Fedora/Linux host: no cloud service, Kubernetes cluster, external database, or machine-learning dependency is required.

## What it collects

- Host CPU, memory, load, disk byte counters, network byte counters, TCP connections, and per-process CPU/RSS from `/proc`.
- Kernel-level process lifecycle, scheduler, page-fault, block-I/O, TCP-state, and network events via eBPF tracepoints.
- Prometheus metrics at `/metrics`, structured state at `/api/v1/state`, and incident reports at `/api/v1/incidents`.

## Architecture

```text
Linux tracepoints ──> eBPF maps/ring buffer ──> Go agent ──> Prometheus ──> Grafana
       /proc ────────────────────────────────────┘
                                                    └──> rule-based RCA ──> JSON incidents
```

## Quick start on Fedora

Requirements: Fedora Linux with BTF enabled (`/sys/kernel/btf/vmlinux`), root access for eBPF, Go 1.22+, clang/LLVM, libbpf headers, Docker, and Docker Compose.

```bash
sudo dnf install -y clang llvm make libbpf-devel kernel-devel bpftool golang docker docker-compose-plugin
./scripts/generate-vmlinux.sh
make
sudo ./bin/ebpfca -config configs/ebpfca.yml
```

In a second terminal, configure the optional visual stack:

```bash
cp .env.example .env
# Edit .env and replace the Grafana password placeholder.
sudo docker compose up -d prometheus grafana
```

Open:

- Agent status: `http://127.0.0.1:9090/`
- Metrics: `http://127.0.0.1:9090/metrics`
- Grafana: `http://127.0.0.1:3000`
- Prometheus: `http://127.0.0.1:9091`

## Validation

```bash
go test ./...
curl http://127.0.0.1:9090/healthz
curl -s http://127.0.0.1:9090/api/v1/state | jq '.host, .rates'
```

To create a controlled CPU test, install `stress-ng` and run:

```bash
stress-ng --cpu 4 --timeout 60s
```

## Project layout

```text
bpf/                    eBPF C source, build rules, generated kernel type header
cmd/ebpfca/             application entry point
internal/               Go application packages
configs/                agent and Prometheus configuration
grafana/                provisioned datasource and dashboards
docs/                   architecture and study material
scripts/                host setup helpers
examples/               representative incident reports and test scenarios
```

## Security and operational notes

- The native agent must run as root (or with the required BPF capabilities).
- The optional eBPF Docker service is privileged; do not expose it on an untrusted host.
- Grafana credentials are configured in a local `.env`, which is excluded from Git.
- Fedora SELinux users should keep the `:z` volume suffixes in `docker-compose.yml`.

## Documentation

- [HOWTO.md](HOWTO.md): plain-language complete operating guide.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): component and data-flow details.
- [docs/STUDY-NOTES.md](docs/STUDY-NOTES.md): project interview preparation.

## Current limitations

This is a single-host educational/portfolio platform, not an HA monitoring product. It has no authentication on the agent HTTP endpoints, no alert delivery service, no long-term incident store, and uses intentionally transparent threshold rules rather than statistical or ML detection.
