package rca

import (
	"testing"

	"github.com/ebpfca/ebpfca/internal/detector"
	"github.com/ebpfca/ebpfca/internal/state"
)

func TestAnalyzeCPUIncident(t *testing.T) {
	engine := NewEngine()
	host := state.HostSnapshot{CPUPercent: 96, Load1: 8.4}
	rates := state.Rates{ContextSwitchPerSec: 30000}
	procs := []state.ProcessInfo{{PID: 1234, Comm: "nginx", CPUPercent: 82}}
	anomalies := []detector.Anomaly{
		{Signal: detector.SignalHighCPU},
		{Signal: detector.SignalHighContextSwitch},
		{Signal: detector.SignalRunawayProcess},
	}

	reports := engine.Analyze(host, rates, procs, anomalies)
	if len(reports) == 0 {
		t.Fatal("expected incident report")
	}
	if reports[0].Incident != "High CPU Usage" {
		t.Fatalf("unexpected incident: %s", reports[0].Incident)
	}
	if reports[0].SuspectedProcess != "nginx" {
		t.Fatalf("unexpected process: %s", reports[0].SuspectedProcess)
	}
}

func TestSkipAgentAsSuspect(t *testing.T) {
	engine := NewEngine()
	host := state.HostSnapshot{CPUPercent: 20}
	rates := state.Rates{ContextSwitchPerSec: 40000}
	procs := []state.ProcessInfo{
		{PID: 1, Comm: "ebpfca", CPUPercent: 6},
		{PID: 2, Comm: "stress-ng-cpu", CPUPercent: 5},
	}
	anomalies := []detector.Anomaly{{Signal: detector.SignalHighContextSwitch}}
	reports := engine.Analyze(host, rates, procs, anomalies)
	if len(reports) == 0 {
		t.Fatal("expected scheduler incident")
	}
	if reports[0].SuspectedProcess != "stress-ng-cpu" {
		t.Fatalf("got %s", reports[0].SuspectedProcess)
	}
}
