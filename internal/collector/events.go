package collector

import (
	"context"
	"errors"
	"log"
	"os"
	"time"

	"github.com/ebpfca/ebpfca/internal/ebpf"
	"github.com/ebpfca/ebpfca/internal/state"
)

type EventCollector struct {
	loader *ebpf.Loader
	store  *state.Store
}

func NewEventCollector(loader *ebpf.Loader, store *state.Store) *EventCollector {
	return &EventCollector{loader: loader, store: store}
}

func (c *EventCollector) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		evt, err := c.loader.ReadEvent()
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		c.handleEvent(evt)
	}
}

func (c *EventCollector) handleEvent(evt ebpf.Event) {
	c.store.RecordEBPF(func(counters *state.EBPFCounters) {
		switch evt.Type {
		case ebpf.EVTDiskIssue:
			counters.DiskIssues++
		case ebpf.EVTDiskComplete:
			counters.DiskCompletes++
			if evt.Value > 0 {
				counters.DiskLatencySum += evt.Value
				counters.DiskLatencyCnt++
			}
		case ebpf.EVTTCPConnect:
			counters.TCPConnects++
		case ebpf.EVTTCPClose:
			counters.TCPClose++
		case ebpf.EVTProcessFork:
			counters.ProcessForks++
		case ebpf.EVTProcessExec:
			counters.ProcessExecs++
		case ebpf.EVTProcessExit:
			counters.ProcessExits++
		}
	})

	if evt.Type == ebpf.EVTProcessFork || evt.Type == ebpf.EVTProcessExec {
		c.store.UpdateProcesses([]state.ProcessInfo{{
			PID:      evt.PID,
			PPID:     evt.PPID,
			Comm:     evt.Comm,
			LastSeen: evt.Timestamp,
		}})
	}
}

type HostSampler struct {
	collector *HostCollector
	loader    *ebpf.Loader
	store     *state.Store
	interval  time.Duration
}

func NewHostSampler(collector *HostCollector, loader *ebpf.Loader, store *state.Store, interval time.Duration) *HostSampler {
	return &HostSampler{collector: collector, loader: loader, store: store, interval: interval}
}

func (s *HostSampler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sample()
		}
	}
}

func (s *HostSampler) sample() {
	if ctrs, err := s.loader.ReadCounters(); err == nil {
		s.store.RecordEBPF(func(c *state.EBPFCounters) {
			c.ContextSwitches = ctrs[ebpf.CTRSchedSwitch]
			c.SchedWakeups = ctrs[ebpf.CTRSchedWakeup]
			c.PageFaults = ctrs[ebpf.CTRPageFault]
			c.NetRXEvents = ctrs[ebpf.CTRNetRX]
			c.NetTXEvents = ctrs[ebpf.CTRNetTX]
		})
	}

	s.store.RecalcRates()

	snap, err := s.collector.Sample()
	if err != nil {
		log.Printf("host sample error: %v", err)
		return
	}
	_, rates, _, _ := s.store.Snapshot()
	snap.DiskAvgLatencyMs = rates.DiskLatencyMs
	s.store.UpdateHost(snap)

	procs, err := s.collector.SampleProcesses()
	if err != nil {
		log.Printf("process sample error: %v", err)
		return
	}
	s.store.UpdateProcesses(procs)
}
