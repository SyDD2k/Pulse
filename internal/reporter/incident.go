package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ebpfca/ebpfca/internal/rca"
)

type Store struct {
	mu        sync.RWMutex
	reports   []rca.IncidentReport
	lastSeen  map[string]time.Time
	maxItems  int
	outputDir string
	cooldown  time.Duration
}

func NewStore(maxItems int, outputDir string, cooldown time.Duration) *Store {
	return &Store{
		maxItems:  maxItems,
		outputDir: outputDir,
		cooldown:  cooldown,
		lastSeen:  make(map[string]time.Time),
	}
}

func (s *Store) Add(report rca.IncidentReport) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := report.Incident + "|" + report.RootCause
	if last, ok := s.lastSeen[key]; ok && s.cooldown > 0 && time.Since(last) < s.cooldown {
		return false, nil
	}
	s.lastSeen[key] = time.Now()

	s.reports = append([]rca.IncidentReport{report}, s.reports...)
	if len(s.reports) > s.maxItems {
		s.reports = s.reports[:s.maxItems]
	}

	if s.outputDir == "" {
		return true, nil
	}
	if err := os.MkdirAll(s.outputDir, 0o755); err != nil {
		return true, err
	}

	filename := filepath.Join(s.outputDir, time.Now().Format("20060102-150405")+".json")
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return true, err
	}
	return true, os.WriteFile(filename, data, 0o644)
}

func (s *Store) List() []rca.IncidentReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]rca.IncidentReport, len(s.reports))
	copy(out, s.reports)
	return out
}
