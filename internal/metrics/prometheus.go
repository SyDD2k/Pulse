package metrics

import (
	"net/http"
	"strconv"

	"github.com/ebpfca/ebpfca/internal/state"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Exporter struct {
	store *state.Store
	reg   *prometheus.Registry

	cpuUsage       prometheus.Gauge
	memUsage       prometheus.Gauge
	memAvailable   prometheus.Gauge
	load1          prometheus.Gauge
	ctxSwitchRate  prometheus.Gauge
	pageFaultRate  prometheus.Gauge
	diskReadBytes  prometheus.Gauge
	diskWriteBytes prometheus.Gauge
	diskLatencyMs  prometheus.Gauge
	netRXBytes     prometheus.Gauge
	netTXBytes     prometheus.Gauge
	tcpConnections prometheus.Gauge
	ebpfEvents     *prometheus.GaugeVec
	processCPU     *prometheus.GaugeVec
	processMemory  *prometheus.GaugeVec
	incidentTotal  *prometheus.CounterVec
}

func NewExporter(store *state.Store) *Exporter {
	reg := prometheus.NewRegistry()
	e := &Exporter{
		store: store,
		reg:   reg,
		cpuUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpfca_host_cpu_percent",
			Help: "Host CPU utilization percent",
		}),
		memUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpfca_host_memory_used_percent",
			Help: "Host memory used percent",
		}),
		memAvailable: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpfca_host_memory_available_kb",
			Help: "Host memory available in KB",
		}),
		load1: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpfca_host_load1",
			Help: "1-minute load average",
		}),
		ctxSwitchRate: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpfca_context_switches_per_sec",
			Help: "Context switch rate from eBPF",
		}),
		pageFaultRate: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpfca_page_faults_per_sec",
			Help: "Page fault rate from eBPF",
		}),
		diskReadBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpfca_disk_read_bytes_total",
			Help: "Cumulative disk read bytes",
		}),
		diskWriteBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpfca_disk_write_bytes_total",
			Help: "Cumulative disk write bytes",
		}),
		diskLatencyMs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpfca_disk_latency_ms",
			Help: "Average block I/O latency in milliseconds",
		}),
		netRXBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpfca_network_rx_bytes_total",
			Help: "Cumulative network RX bytes",
		}),
		netTXBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpfca_network_tx_bytes_total",
			Help: "Cumulative network TX bytes",
		}),
		tcpConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpfca_tcp_connections",
			Help: "Established TCP connections",
		}),
		ebpfEvents: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpfca_ebpf_events_total",
			Help: "Total eBPF events observed by type",
		}, []string{"type"}),
		processCPU: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpfca_process_cpu_percent",
			Help: "Process CPU utilization percent",
		}, []string{"pid", "comm"}),
		processMemory: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpfca_process_memory_rss_bytes",
			Help: "Process resident memory in bytes",
		}, []string{"pid", "comm"}),
		incidentTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpfca_incidents_total",
			Help: "Detected incidents by type",
		}, []string{"incident", "confidence"}),
	}

	reg.MustRegister(
		e.cpuUsage, e.memUsage, e.memAvailable, e.load1,
		e.ctxSwitchRate, e.pageFaultRate,
		e.diskReadBytes, e.diskWriteBytes, e.diskLatencyMs,
		e.netRXBytes, e.netTXBytes, e.tcpConnections,
		e.ebpfEvents, e.processCPU, e.processMemory, e.incidentTotal,
	)
	return e
}

func (e *Exporter) Handler() http.Handler {
	return promhttp.HandlerFor(e.reg, promhttp.HandlerOpts{})
}

func (e *Exporter) Sync() {
	host, rates, procs, ebpfCnt := e.store.Snapshot()

	e.cpuUsage.Set(host.CPUPercent)
	e.memUsage.Set(host.MemoryUsedPercent)
	e.memAvailable.Set(float64(host.MemoryAvailableKB))
	e.load1.Set(host.Load1)
	e.ctxSwitchRate.Set(rates.ContextSwitchPerSec)
	e.pageFaultRate.Set(rates.PageFaultPerSec)
	e.diskReadBytes.Set(float64(host.DiskReadBytes))
	e.diskWriteBytes.Set(float64(host.DiskWriteBytes))
	if rates.DiskLatencyMs > 0 {
		e.diskLatencyMs.Set(rates.DiskLatencyMs)
	} else {
		e.diskLatencyMs.Set(host.DiskAvgLatencyMs)
	}
	e.netRXBytes.Set(float64(host.NetRXBytes))
	e.netTXBytes.Set(float64(host.NetTXBytes))
	e.tcpConnections.Set(float64(host.TCPConnections))

	e.ebpfEvents.WithLabelValues("context_switch").Set(float64(ebpfCnt.ContextSwitches))
	e.ebpfEvents.WithLabelValues("page_fault").Set(float64(ebpfCnt.PageFaults))
	e.ebpfEvents.WithLabelValues("disk_complete").Set(float64(ebpfCnt.DiskCompletes))
	e.ebpfEvents.WithLabelValues("tcp_connect").Set(float64(ebpfCnt.TCPConnects))
	e.ebpfEvents.WithLabelValues("net_rx").Set(float64(ebpfCnt.NetRXEvents))
	e.ebpfEvents.WithLabelValues("net_tx").Set(float64(ebpfCnt.NetTXEvents))

	e.processCPU.Reset()
	e.processMemory.Reset()
	for _, p := range procs {
		if p.CPUPercent < 0.1 && p.MemoryRSS < 1<<20 {
			continue
		}
		labels := prometheus.Labels{
			"pid":  strconv.FormatUint(uint64(p.PID), 10),
			"comm": p.Comm,
		}
		e.processCPU.With(labels).Set(p.CPUPercent)
		e.processMemory.With(labels).Set(float64(p.MemoryRSS))
	}
}

func (e *Exporter) RecordIncident(incident, confidence string) {
	e.incidentTotal.WithLabelValues(incident, confidence).Inc()
}
