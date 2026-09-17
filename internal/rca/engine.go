package rca

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ebpfca/ebpfca/internal/detector"
	"github.com/ebpfca/ebpfca/internal/state"
)

type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

type IncidentReport struct {
	Incident         string     `json:"incident"`
	SuspectedProcess string     `json:"suspected_process,omitempty"`
	RootCause        string     `json:"root_cause"`
	Confidence       Confidence `json:"confidence"`
	Evidence         []string   `json:"evidence"`
	Timestamp        time.Time  `json:"timestamp"`
	Severity         string     `json:"severity"`
}

type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) Analyze(host state.HostSnapshot, rates state.Rates, procs []state.ProcessInfo, anomalies []detector.Anomaly) []IncidentReport {
	if len(anomalies) == 0 {
		return nil
	}

	top, hasTop := topProcess(procs)
	signals := indexSignals(anomalies)
	var reports []IncidentReport

	if signals[detector.SignalHighCPU] || signals[detector.SignalRunawayProcess] {
		reports = append(reports, e.cpuContention(host, rates, top, hasTop, signals))
	}
	if signals[detector.SignalHighMemory] || signals[detector.SignalOOMRisk] || signals[detector.SignalHighPageFault] {
		reports = append(reports, e.memoryPressure(host, rates, top, hasTop, signals))
	}
	if signals[detector.SignalHighDiskLatency] {
		reports = append(reports, e.diskBottleneck(host, rates, top, hasTop))
	}
	if signals[detector.SignalNetworkPressure] {
		reports = append(reports, e.networkBottleneck(host, rates, top, hasTop))
	}
	if signals[detector.SignalHighContextSwitch] && !signals[detector.SignalHighCPU] {
		reports = append(reports, e.schedulingContention(host, rates, top, hasTop))
	}

	return dedupeReports(reports)
}

func (e *Engine) cpuContention(host state.HostSnapshot, rates state.Rates, top state.ProcessInfo, hasTop bool, signals map[detector.Signal]bool) IncidentReport {
	report := IncidentReport{
		Incident:   "High CPU Usage",
		RootCause:  "CPU saturation on host",
		Confidence: ConfidenceMedium,
		Timestamp:  time.Now(),
		Severity:   "critical",
		Evidence: []string{
			fmt.Sprintf("CPU %.1f%%", host.CPUPercent),
			fmt.Sprintf("Load average %.2f", host.Load1),
		},
	}

	if rates.ContextSwitchPerSec > 10000 {
		report.RootCause = "Excessive context switching"
		report.Confidence = ConfidenceHigh
		report.Evidence = append(report.Evidence, fmt.Sprintf("Context switches %.0f/sec", rates.ContextSwitchPerSec))
	}

	if signals[detector.SignalRunawayProcess] && hasTop {
		report.SuspectedProcess = top.Comm
		report.Confidence = ConfidenceHigh
		report.Evidence = append(report.Evidence, fmt.Sprintf("PID %d consuming %.1f%% CPU", top.PID, top.CPUPercent))
	}

	return report
}

func (e *Engine) memoryPressure(host state.HostSnapshot, rates state.Rates, top state.ProcessInfo, hasTop bool, signals map[detector.Signal]bool) IncidentReport {
	report := IncidentReport{
		Incident:   "Memory Pressure",
		RootCause:  "Elevated memory utilization",
		Confidence: ConfidenceMedium,
		Timestamp:  time.Now(),
		Severity:   "critical",
		Evidence: []string{
			fmt.Sprintf("Memory used %.1f%%", host.MemoryUsedPercent),
			fmt.Sprintf("Memory available %d KB", host.MemoryAvailableKB),
		},
	}

	if signals[detector.SignalOOMRisk] {
		report.Incident = "OOM Risk"
		report.RootCause = "Critically low available memory"
		report.Confidence = ConfidenceHigh
	}

	if rates.PageFaultPerSec > 1000 {
		report.Evidence = append(report.Evidence, fmt.Sprintf("Page faults %.0f/sec", rates.PageFaultPerSec))
		if rates.PageFaultPerSec > 5000 {
			report.RootCause = "Sustained page fault storm indicating memory thrashing"
			report.Confidence = ConfidenceHigh
		}
	}

	if hasTop && top.MemoryRSS > 512*1024*1024 {
		report.SuspectedProcess = top.Comm
		report.Evidence = append(report.Evidence, fmt.Sprintf("Top process %s RSS %.1f MB", top.Comm, float64(top.MemoryRSS)/(1024*1024)))
	}

	return report
}

func (e *Engine) diskBottleneck(host state.HostSnapshot, rates state.Rates, top state.ProcessInfo, hasTop bool) IncidentReport {
	latency := rates.DiskLatencyMs
	if latency == 0 {
		latency = host.DiskAvgLatencyMs
	}
	report := IncidentReport{
		Incident:   "Disk Bottleneck",
		RootCause:  "Elevated block I/O latency",
		Confidence: ConfidenceHigh,
		Timestamp:  time.Now(),
		Severity:   "warning",
		Evidence: []string{
			fmt.Sprintf("Disk latency %.2f ms", latency),
			fmt.Sprintf("Disk read bytes %d", host.DiskReadBytes),
			fmt.Sprintf("Disk write bytes %d", host.DiskWriteBytes),
		},
	}
	if hasTop {
		report.SuspectedProcess = top.Comm
	}
	if host.CPUPercent > 50 && rates.ContextSwitchPerSec > 15000 {
		report.RootCause = "I/O wait causing scheduler churn"
		report.Evidence = append(report.Evidence, "High CPU with elevated context switches suggests iowait")
	}
	return report
}

func (e *Engine) networkBottleneck(host state.HostSnapshot, rates state.Rates, top state.ProcessInfo, hasTop bool) IncidentReport {
	report := IncidentReport{
		Incident:   "Network Bottleneck",
		RootCause:  "High network activity detected",
		Confidence: ConfidenceMedium,
		Timestamp:  time.Now(),
		Severity:   "warning",
		Evidence: []string{
			fmt.Sprintf("Network RX events %.0f/sec", rates.NetRXPerSec),
			fmt.Sprintf("Network TX events %.0f/sec", rates.NetTXPerSec),
			fmt.Sprintf("TCP connections %d", host.TCPConnections),
			fmt.Sprintf("RX bytes %d", host.NetRXBytes),
			fmt.Sprintf("TX bytes %d", host.NetTXBytes),
		},
	}
	if hasTop {
		report.SuspectedProcess = top.Comm
	}
	if host.TCPConnections > 1000 {
		report.RootCause = "Connection churn or high connection count"
		report.Confidence = ConfidenceHigh
	}
	return report
}

func (e *Engine) schedulingContention(host state.HostSnapshot, rates state.Rates, top state.ProcessInfo, hasTop bool) IncidentReport {
	report := IncidentReport{
		Incident:   "Scheduler Contention",
		RootCause:  "Excessive context switching without CPU saturation",
		Confidence: ConfidenceMedium,
		Timestamp:  time.Now(),
		Severity:   "warning",
		Evidence: []string{
			fmt.Sprintf("Context switches %.0f/sec", rates.ContextSwitchPerSec),
			fmt.Sprintf("CPU %.1f%%", host.CPUPercent),
		},
	}
	if hasTop {
		report.SuspectedProcess = top.Comm
		report.Evidence = append(report.Evidence, fmt.Sprintf("Top runnable process %s at %.1f%% CPU", top.Comm, top.CPUPercent))
	}
	return report
}

func topProcess(procs []state.ProcessInfo) (state.ProcessInfo, bool) {
	filtered := make([]state.ProcessInfo, 0, len(procs))
	for _, p := range procs {
		if p.Comm == "ebpfca" {
			continue
		}
		filtered = append(filtered, p)
	}
	if len(filtered) == 0 {
		return state.ProcessInfo{}, false
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].CPUPercent == filtered[j].CPUPercent {
			return filtered[i].MemoryRSS > filtered[j].MemoryRSS
		}
		return filtered[i].CPUPercent > filtered[j].CPUPercent
	})
	return filtered[0], true
}

func indexSignals(anomalies []detector.Anomaly) map[detector.Signal]bool {
	m := make(map[detector.Signal]bool, len(anomalies))
	for _, a := range anomalies {
		m[a.Signal] = true
	}
	return m
}

func dedupeReports(reports []IncidentReport) []IncidentReport {
	seen := make(map[string]struct{})
	out := make([]IncidentReport, 0, len(reports))
	for _, r := range reports {
		key := strings.ToLower(r.Incident + "|" + r.RootCause)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, r)
	}
	return out
}
