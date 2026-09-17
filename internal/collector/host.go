package collector

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ebpfca/ebpfca/internal/state"
)

type HostCollector struct {
	prevCPU      cpuTimes
	prevProcCPU  map[uint32]uint64
	prevSampleAt time.Time
}

type cpuTimes struct {
	user, nice, system, idle, iowait, irq, softirq, steal uint64
}

func NewHostCollector() *HostCollector {
	return &HostCollector{prevProcCPU: make(map[uint32]uint64)}
}

func (c *HostCollector) Sample() (state.HostSnapshot, error) {
	snap := state.HostSnapshot{Timestamp: time.Now()}

	cpu, err := c.readCPU()
	if err != nil {
		return snap, err
	}
	snap.CPUPercent = cpu

	memUsed, memAvail, err := c.readMemory()
	if err != nil {
		return snap, err
	}
	snap.MemoryUsedPercent = memUsed
	snap.MemoryAvailableKB = memAvail

	if load1, err := c.readLoad(); err == nil {
		snap.Load1 = load1
	}
	if ctxSw, pgFault, err := c.readProcStat(); err == nil {
		snap.ContextSwitches = ctxSw
		snap.PageFaults = pgFault
	}
	if rb, wb, err := c.readDisk(); err == nil {
		snap.DiskReadBytes = rb
		snap.DiskWriteBytes = wb
	}
	if rx, tx, err := c.readNet(); err == nil {
		snap.NetRXBytes = rx
		snap.NetTXBytes = tx
	}
	if tcp, err := c.countTCPConnections(); err == nil {
		snap.TCPConnections = tcp
	}
	return snap, nil
}

func (c *HostCollector) SampleProcesses() ([]state.ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	now := time.Now()
	elapsed := now.Sub(c.prevSampleAt).Seconds()
	if c.prevSampleAt.IsZero() {
		elapsed = 0
	}

	var procs []state.ProcessInfo
	nextTicks := make(map[uint32]uint64, len(entries))
	nCPU := float64(runtimeNumCPU())
	ticksPerSec := 100.0

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)
		stat, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		fields := strings.Fields(string(stat))
		if len(fields) < 24 {
			continue
		}
		comm := strings.Trim(fields[1], "()")
		ppid, _ := strconv.ParseUint(fields[3], 10, 32)
		utime, _ := strconv.ParseUint(fields[13], 10, 64)
		stime, _ := strconv.ParseUint(fields[14], 10, 64)
		rss, _ := strconv.ParseUint(fields[23], 10, 64)
		totalTicks := utime + stime
		nextTicks[pid] = totalTicks

		cpuPct := 0.0
		if elapsed > 0 {
			if prev, ok := c.prevProcCPU[pid]; ok && totalTicks >= prev {
				delta := float64(totalTicks - prev)
				cpuPct = (delta / (elapsed * ticksPerSec * nCPU)) * 100.0
			}
		}

		procs = append(procs, state.ProcessInfo{
			PID:        pid,
			PPID:       uint32(ppid),
			Comm:       comm,
			CPUPercent: cpuPct,
			MemoryRSS:  rss * 4096,
			LastSeen:   now,
		})
	}

	c.prevProcCPU = nextTicks
	c.prevSampleAt = now
	return procs, nil
}

func runtimeNumCPU() int {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return 1
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "processor") {
			count++
		}
	}
	if count == 0 {
		return 1
	}
	return count
}

func (c *HostCollector) readCPU() (float64, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			return 0, fmt.Errorf("unexpected /proc/stat cpu line")
		}
		cur := cpuTimes{}
		cur.user, _ = strconv.ParseUint(fields[1], 10, 64)
		cur.nice, _ = strconv.ParseUint(fields[2], 10, 64)
		cur.system, _ = strconv.ParseUint(fields[3], 10, 64)
		cur.idle, _ = strconv.ParseUint(fields[4], 10, 64)
		cur.iowait, _ = strconv.ParseUint(fields[5], 10, 64)
		cur.irq, _ = strconv.ParseUint(fields[6], 10, 64)
		cur.softirq, _ = strconv.ParseUint(fields[7], 10, 64)
		if len(fields) > 8 {
			cur.steal, _ = strconv.ParseUint(fields[8], 10, 64)
		}

		if c.prevCPU.idle == 0 && c.prevCPU.user == 0 {
			c.prevCPU = cur
			return 0, nil
		}

		prevIdle := c.prevCPU.idle + c.prevCPU.iowait
		idle := cur.idle + cur.iowait
		prevTotal := c.prevCPU.user + c.prevCPU.nice + c.prevCPU.system + prevIdle + c.prevCPU.irq + c.prevCPU.softirq + c.prevCPU.steal
		total := cur.user + cur.nice + cur.system + idle + cur.irq + cur.softirq + cur.steal
		deltaTotal := total - prevTotal
		deltaIdle := idle - prevIdle
		c.prevCPU = cur
		if deltaTotal == 0 {
			return 0, nil
		}
		return (1.0 - float64(deltaIdle)/float64(deltaTotal)) * 100.0, nil
	}
	return 0, scanner.Err()
}

func (c *HostCollector) readMemory() (usedPct float64, availKB uint64, err error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	var total, available uint64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			total = val
		case "MemAvailable:":
			available = val
		}
	}
	if total == 0 {
		return 0, 0, fmt.Errorf("meminfo missing MemTotal")
	}
	usedPct = (1.0 - float64(available)/float64(total)) * 100.0
	return usedPct, available, nil
}

func (c *HostCollector) readLoad() (float64, error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, fmt.Errorf("invalid loadavg")
	}
	return strconv.ParseFloat(fields[0], 64)
}

func (c *HostCollector) readProcStat() (ctxSw, pgFault uint64, err error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "ctxt":
			ctxSw, _ = strconv.ParseUint(fields[1], 10, 64)
		case "page":
			pgFault, _ = strconv.ParseUint(fields[1], 10, 64)
		}
	}
	return ctxSw, pgFault, nil
}

func (c *HostCollector) readDisk() (readBytes, writeBytes uint64, err error) {
	data, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return 0, 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 14 {
			continue
		}
		name := fields[2]
		if strings.Contains(name, "loop") || strings.Contains(name, "ram") {
			continue
		}
		rb, _ := strconv.ParseUint(fields[5], 10, 64)
		wb, _ := strconv.ParseUint(fields[9], 10, 64)
		readBytes += rb * 512
		writeBytes += wb * 512
	}
	return readBytes, writeBytes, nil
}

func (c *HostCollector) readNet() (rx, tx uint64, err error) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[2:] {
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}
		rxb, _ := strconv.ParseUint(fields[0], 10, 64)
		txb, _ := strconv.ParseUint(fields[8], 10, 64)
		rx += rxb
		tx += txb
	}
	return rx, tx, nil
}

func (c *HostCollector) countTCPConnections() (uint64, error) {
	data, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return 0, err
	}
	var count uint64
	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[3] == "01" {
			count++
		}
	}
	return count, nil
}
