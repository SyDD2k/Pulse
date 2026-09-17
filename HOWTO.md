# EBPFCA HOWTO

## In simple words

Think of your computer as a factory. CPU is the workforce, memory is the workspace, disk is the warehouse, and the network is the delivery road. EBPFCA watches those parts. When one looks unhealthy, it creates a short report saying what it saw and why it suspects a particular problem.

The project has three running pieces:

1. **EBPFCA agent** — runs on the Linux host and collects readings every second.
2. **Prometheus** — saves a time series of those readings every five seconds.
3. **Grafana** — draws the charts in the browser.

## What each major folder does

- `bpf/`: the small C programs that attach safely to Linux kernel tracepoints.
- `cmd/ebpfca/`: starts the Go application.
- `internal/collector/`: reads `/proc` and accepts eBPF event data.
- `internal/state/`: safely keeps the latest values and calculates rates.
- `internal/detector/`: checks simple thresholds such as CPU above 85%.
- `internal/rca/`: turns threshold signals into human-readable incident evidence.
- `internal/metrics/`: presents values in Prometheus format.
- `internal/api/`: provides the status page and JSON endpoints.
- `configs/`: tuning values and Prometheus scraping setup.
- `grafana/`: dashboards that are loaded automatically at startup.

## First-time setup

Install packages:

```bash
sudo dnf install -y clang llvm make libbpf-devel kernel-devel bpftool golang docker docker-compose-plugin jq stress-ng
```

Generate the type information matching your current kernel and compile:

```bash
./scripts/generate-vmlinux.sh
make
go test ./...
```

Run the agent in terminal one:

```bash
sudo ./bin/ebpfca -config configs/ebpfca.yml
```

Prepare the dashboard credentials, then start the visual stack in terminal two:

```bash
cp .env.example .env
nano .env
sudo docker compose up -d prometheus grafana
```

## Seeing live readings

The agent samples host/process data once per second. Prometheus and Grafana refresh every five seconds, so charts naturally lag by roughly 5–10 seconds.

```bash
# Overall CPU now
curl -s http://127.0.0.1:9090/api/v1/state | jq '.host.cpu_percent'

# Top processes now
curl -s http://127.0.0.1:9090/api/v1/state | jq '.processes[:10] | .[] | {pid, comm, cpu_percent}'

# Human-facing local status page
xdg-open http://127.0.0.1:9090/
```

Open Grafana at `http://127.0.0.1:3000`, sign in using the values in `.env`, and select **Dashboards → EBPFCA**.

## Testing an incident

```bash
stress-ng --cpu 4 --timeout 60s
curl -s http://127.0.0.1:9090/api/v1/incidents | jq .
```

Incidents are written to `data/incidents/`. A cooldown prevents the same incident from being saved every 10 seconds.

## Common problems

### Port 9090 is already in use

Only one EBPFCA agent should run. Find the listener with `sudo ss -tlnp | grep 9090`, stop the old process/container, then start the one you intend to use.

### `vmlinux.h` build errors after a kernel update

Regenerate it and rebuild:

```bash
./scripts/generate-vmlinux.sh
make clean && make
```

Warnings from generated `vmlinux.h` are common; compilation errors are not.

### Prometheus or Grafana cannot read mounted files on Fedora

The Compose mounts include `:z`, which lets Docker apply a container-safe SELinux label. If labels were previously wrong:

```bash
sudo chcon -Rt container_file_t configs grafana
sudo docker compose restart prometheus grafana
```

### Grafana says “No data”

First verify the agent and Prometheus independently:

```bash
curl http://127.0.0.1:9090/healthz
curl -s 'http://127.0.0.1:9091/api/v1/query?query=ebpfca_host_cpu_percent' | jq .
```

Then open `http://127.0.0.1:9091/targets`; the `ebpfca` target must be **UP**.

## Tuning detection

Edit `configs/ebpfca.yml`. For example, lower `cpu_percent_high` temporarily to make a test incident easier to trigger. Restart the agent after changing the file. Use normal thresholds again after the demo.

## Stopping

Press `Ctrl+C` in the native agent terminal. Stop dashboards with:

```bash
sudo docker compose down
```
