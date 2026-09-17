package detector

import (
	"testing"

	"github.com/ebpfca/ebpfca/internal/config"
	"github.com/ebpfca/ebpfca/internal/state"
)

func TestDetectHighCPU(t *testing.T) {
	d := NewDetector(config.Default().Thresholds)
	host := state.HostSnapshot{CPUPercent: 95, Load1: 4.2}
	anomalies := d.Detect(host, state.Rates{}, nil)
	if len(anomalies) == 0 {
		t.Fatal("expected anomalies")
	}
	if anomalies[0].Signal != SignalHighCPU {
		t.Fatalf("got %s", anomalies[0].Signal)
	}
}

func TestDetectRunawayProcess(t *testing.T) {
	d := NewDetector(config.Default().Thresholds)
	procs := []state.ProcessInfo{{PID: 1234, Comm: "nginx", CPUPercent: 82}}
	anomalies := d.Detect(state.HostSnapshot{}, state.Rates{}, procs)
	found := false
	for _, a := range anomalies {
		if a.Signal == SignalRunawayProcess {
			found = true
		}
	}
	if !found {
		t.Fatal("expected runaway process signal")
	}
}

func TestIgnoreAgentAsRunaway(t *testing.T) {
	d := NewDetector(config.Default().Thresholds)
	procs := []state.ProcessInfo{{PID: 1, Comm: "ebpfca", CPUPercent: 90}}
	anomalies := d.Detect(state.HostSnapshot{}, state.Rates{}, procs)
	for _, a := range anomalies {
		if a.Signal == SignalRunawayProcess {
			t.Fatal("agent should not be treated as runaway")
		}
	}
}
