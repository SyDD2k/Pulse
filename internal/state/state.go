package state

import (
	"sort"
	"sync"
	"time"
)

type ProcessInfo struct {
	PID        uint32    `json:"pid"`
	PPID       uint32    `json:"ppid"`
	Comm       string    `json:"comm"`
	CPUPercent float64   `json:"cpu_percent"`
	MemoryRSS  uint64    `json:"memory_rss"`
	LastSeen   time.Time `json:"last_seen"`
}

type HostSnapshot struct {
	Timestamp         time.Time `json:"timestamp"`
	CPUPercent        float64   `json:"cpu_percent"`
	MemoryUsedPercent float64   `json:"memory_used_percent"`
	MemoryAvailableKB uint64    `json:"memory_available_kb"`
	Load1             float64   `json:"load1"`
	ContextSwitches   uint64    `json:"context_switches"`
	PageFaults        uint64    `json:"page_faults"`
	DiskReadBytes     uint64    `json:"disk_read_bytes"`
	DiskWriteBytes    uint64    `json:"disk_write_bytes"`
	DiskAvgLatencyMs  float64   `json:"disk_avg_latency_ms"`
	NetRXBytes        uint64    `json:"net_rx_bytes"`
	NetTXBytes        uint64    `json:"net_tx_bytes"`
	TCPConnections    uint64    `json:"tcp_connections"`
}

type EBPFCounters struct {
	ContextSwitches uint64 `json:"context_switches"`
	PageFaults      uint64 `json:"page_faults"`
	DiskIssues      uint64 `json:"disk_issues"`
	DiskCompletes   uint64 `json:"disk_completes"`
	DiskLatencySum  uint64 `json:"disk_latency_sum"`
	DiskLatencyCnt  uint64 `json:"disk_latency_cnt"`
	TCPConnects     uint64 `json:"tcp_connects"`
	TCPClose        uint64 `json:"tcp_close"`
	NetRXEvents     uint64 `json:"net_rx_events"`
	NetTXEvents     uint64 `json:"net_tx_events"`
	ProcessForks    uint64 `json:"process_forks"`
	ProcessExecs    uint64 `json:"process_execs"`
	ProcessExits    uint64 `json:"process_exits"`
	SchedWakeups    uint64 `json:"sched_wakeups"`
}

type Rates struct {
	ContextSwitchPerSec float64 `json:"context_switch_per_sec"`
	PageFaultPerSec     float64 `json:"page_fault_per_sec"`
	DiskLatencyMs       float64 `json:"disk_latency_ms"`
	NetRXPerSec         float64 `json:"net_rx_per_sec"`
	NetTXPerSec         float64 `json:"net_tx_per_sec"`
}

type Store struct {
	mu sync.RWMutex

	host         HostSnapshot
	processes    map[uint32]*ProcessInfo
	ebpf         EBPFCounters
	prevEBPF     EBPFCounters
	lastRateCalc time.Time
	rates        Rates
}

func NewStore() *Store {
	return &Store{
		processes:    make(map[uint32]*ProcessInfo),
		lastRateCalc: time.Now(),
	}
}

func (s *Store) UpdateHost(h HostSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.host = h
}

func (s *Store) UpdateProcesses(procs []ProcessInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	active := make(map[uint32]struct{}, len(procs))
	now := time.Now()
	for i := range procs {
		p := procs[i]
		active[p.PID] = struct{}{}
		if existing, ok := s.processes[p.PID]; ok {
			existing.Comm = p.Comm
			existing.PPID = p.PPID
			existing.CPUPercent = p.CPUPercent
			existing.MemoryRSS = p.MemoryRSS
			existing.LastSeen = p.LastSeen
		} else {
			cp := p
			s.processes[p.PID] = &cp
		}
	}
	for pid, p := range s.processes {
		if _, ok := active[pid]; !ok && now.Sub(p.LastSeen) > 30*time.Second {
			delete(s.processes, pid)
		}
	}
}

func (s *Store) RecordEBPF(mutator func(*EBPFCounters)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mutator(&s.ebpf)
}

func (s *Store) RecalcRates() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(s.lastRateCalc).Seconds()
	if elapsed <= 0 {
		return
	}
	s.rates = Rates{
		ContextSwitchPerSec: perSec(s.ebpf.ContextSwitches, s.prevEBPF.ContextSwitches, elapsed),
		PageFaultPerSec:     perSec(s.ebpf.PageFaults, s.prevEBPF.PageFaults, elapsed),
		NetRXPerSec:         perSec(s.ebpf.NetRXEvents, s.prevEBPF.NetRXEvents, elapsed),
		NetTXPerSec:         perSec(s.ebpf.NetTXEvents, s.prevEBPF.NetTXEvents, elapsed),
	}
	if delta := s.ebpf.DiskLatencyCnt - s.prevEBPF.DiskLatencyCnt; delta > 0 {
		sum := s.ebpf.DiskLatencySum - s.prevEBPF.DiskLatencySum
		s.rates.DiskLatencyMs = float64(sum) / float64(delta) / 1e6
	}
	s.prevEBPF = s.ebpf
	s.lastRateCalc = now
}

func perSec(now, prev uint64, elapsed float64) float64 {
	if now < prev {
		return 0
	}
	return float64(now-prev) / elapsed
}

func (s *Store) Snapshot() (HostSnapshot, Rates, []ProcessInfo, EBPFCounters) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	procs := make([]ProcessInfo, 0, len(s.processes))
	for _, p := range s.processes {
		procs = append(procs, *p)
	}
	sort.Slice(procs, func(i, j int) bool {
		return procs[i].CPUPercent > procs[j].CPUPercent
	})
	return s.host, s.rates, procs, s.ebpf
}

func (s *Store) TopCPUProcess() (ProcessInfo, bool) {
	_, _, procs, _ := s.Snapshot()
	for _, p := range procs {
		if p.Comm == "ebpfca" {
			continue
		}
		return p, true
	}
	if len(procs) == 0 {
		return ProcessInfo{}, false
	}
	return procs[0], true
}
