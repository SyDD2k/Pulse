package detector

import (
	"github.com/ebpfca/ebpfca/internal/config"
	"github.com/ebpfca/ebpfca/internal/state"
)

type Signal string

const (
	SignalHighCPU           Signal = "high_cpu"
	SignalHighMemory        Signal = "high_memory"
	SignalHighContextSwitch Signal = "high_context_switch"
	SignalHighPageFault     Signal = "high_page_fault"
	SignalHighDiskLatency   Signal = "high_disk_latency"
	SignalRunawayProcess    Signal = "runaway_process"
	SignalNetworkPressure   Signal = "network_pressure"
	SignalOOMRisk           Signal = "oom_risk"
)

type Anomaly struct {
	Signal   Signal
	Severity string
	Message  string
	Value    float64
}

type Detector struct {
	thresholds config.Thresholds
}

func NewDetector(thresholds config.Thresholds) *Detector {
	return &Detector{thresholds: thresholds}
}

func (d *Detector) Detect(host state.HostSnapshot, rates state.Rates, procs []state.ProcessInfo) []Anomaly {
	var anomalies []Anomaly

	if host.CPUPercent >= d.thresholds.CPUPercentHigh {
		anomalies = append(anomalies, Anomaly{
			Signal:   SignalHighCPU,
			Severity: "critical",
			Message:  "Host CPU utilization exceeds threshold",
			Value:    host.CPUPercent,
		})
	}

	if host.MemoryUsedPercent >= d.thresholds.MemoryPercentHigh {
		anomalies = append(anomalies, Anomaly{
			Signal:   SignalHighMemory,
			Severity: "critical",
			Message:  "Host memory utilization exceeds threshold",
			Value:    host.MemoryUsedPercent,
		})
	}

	if host.MemoryAvailableKB < 256*1024 {
		anomalies = append(anomalies, Anomaly{
			Signal:   SignalOOMRisk,
			Severity: "critical",
			Message:  "Available memory below OOM risk threshold",
			Value:    float64(host.MemoryAvailableKB),
		})
	}

	if rates.ContextSwitchPerSec >= d.thresholds.ContextSwitchRateHigh {
		anomalies = append(anomalies, Anomaly{
			Signal:   SignalHighContextSwitch,
			Severity: "warning",
			Message:  "Context switch rate exceeds threshold",
			Value:    rates.ContextSwitchPerSec,
		})
	}

	if rates.PageFaultPerSec >= d.thresholds.PageFaultRateHigh {
		anomalies = append(anomalies, Anomaly{
			Signal:   SignalHighPageFault,
			Severity: "warning",
			Message:  "Page fault rate exceeds threshold",
			Value:    rates.PageFaultPerSec,
		})
	}

	latency := rates.DiskLatencyMs
	if latency == 0 {
		latency = host.DiskAvgLatencyMs
	}
	if latency >= d.thresholds.DiskLatencyMsHigh {
		anomalies = append(anomalies, Anomaly{
			Signal:   SignalHighDiskLatency,
			Severity: "warning",
			Message:  "Disk I/O latency exceeds threshold",
			Value:    latency,
		})
	}

	for _, p := range procs {
		if p.Comm == "ebpfca" {
			continue
		}
		if p.CPUPercent >= d.thresholds.ProcessCPUPercentHigh {
			anomalies = append(anomalies, Anomaly{
				Signal:   SignalRunawayProcess,
				Severity: "critical",
				Message:  "Process CPU utilization exceeds threshold",
				Value:    p.CPUPercent,
			})
			break
		}
	}

	rxMbps := rates.NetRXPerSec * 8 / 1e6
	txMbps := rates.NetTXPerSec * 8 / 1e6
	if rxMbps+txMbps >= d.thresholds.NetworkThroughputHigh {
		anomalies = append(anomalies, Anomaly{
			Signal:   SignalNetworkPressure,
			Severity: "warning",
			Message:  "Network event throughput exceeds threshold",
			Value:    rxMbps + txMbps,
		})
	}

	return anomalies
}
