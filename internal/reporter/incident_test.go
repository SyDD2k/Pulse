package reporter

import (
	"testing"
	"time"

	"github.com/ebpfca/ebpfca/internal/rca"
)

func TestCooldownSuppressesDuplicate(t *testing.T) {
	s := NewStore(10, "", time.Minute)
	rep := rca.IncidentReport{Incident: "High CPU Usage", RootCause: "CPU saturation on host"}
	ok, err := s.Add(rep)
	if err != nil || !ok {
		t.Fatalf("first add should succeed: %v", err)
	}
	ok, err = s.Add(rep)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("duplicate within cooldown should be suppressed")
	}
	if len(s.List()) != 1 {
		t.Fatal("store should keep a single incident")
	}
}
