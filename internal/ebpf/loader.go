package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type rawEvent struct {
	TsNs   uint64
	Type   uint32
	PID    uint32
	PPID   uint32
	CPU    uint32
	Value  uint64
	Value2 uint64
	Comm   [TaskCommLen]byte
	Detail [32]byte
}

type Loader struct {
	collection *cilium.Collection
	links      []link.Link
	reader     *ringbuf.Reader
	counters   *cilium.Map
}

func NewLoader(objectPath string) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	data, err := os.ReadFile(objectPath)
	if err != nil {
		return nil, fmt.Errorf("read bpf object %s: %w", objectPath, err)
	}

	spec, err := cilium.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("load bpf spec: %w", err)
	}

	coll, err := cilium.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create bpf collection: %w", err)
	}

	l := &Loader{collection: coll}
	if err := l.attachPrograms(); err != nil {
		l.Close()
		return nil, err
	}

	eventsMap := coll.Maps["events"]
	if eventsMap == nil {
		l.Close()
		return nil, errors.New("events ring buffer map not found")
	}

	l.counters = coll.Maps["counters"]
	if l.counters == nil {
		l.Close()
		return nil, errors.New("counters map not found")
	}

	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	l.reader = reader
	return l, nil
}

func (l *Loader) attachPrograms() error {
	attach := func(section, group, name string) error {
		prog := l.collection.Programs[section]
		if prog == nil {
			return fmt.Errorf("program %s missing", section)
		}
		lnk, err := link.Tracepoint(group, name, prog, nil)
		if err != nil {
			return fmt.Errorf("attach %s: %w", section, err)
		}
		l.links = append(l.links, lnk)
		return nil
	}

	tracepoints := [][3]string{
		{"tp_sched_process_fork", "sched", "sched_process_fork"},
		{"tp_sched_process_exec", "sched", "sched_process_exec"},
		{"tp_sched_process_exit", "sched", "sched_process_exit"},
		{"tp_sched_switch", "sched", "sched_switch"},
		{"tp_sched_wakeup", "sched", "sched_wakeup"},
		{"tp_page_fault_user", "exceptions", "page_fault_user"},
		{"tp_page_fault_kernel", "exceptions", "page_fault_kernel"},
		{"tp_block_rq_issue", "block", "block_rq_issue"},
		{"tp_block_rq_complete", "block", "block_rq_complete"},
		{"tp_inet_sock_set_state", "sock", "inet_sock_set_state"},
		{"tp_netif_receive_skb", "net", "netif_receive_skb"},
		{"tp_net_dev_xmit", "net", "net_dev_xmit"},
	}

	for _, tp := range tracepoints {
		if err := attach(tp[0], tp[1], tp[2]); err != nil {
			return err
		}
	}
	return nil
}

func (l *Loader) ReadEvent() (Event, error) {
	l.reader.SetDeadline(time.Now().Add(250 * time.Millisecond))
	record, err := l.reader.Read()
	if err != nil {
		return Event{}, err
	}
	if len(record.RawSample) < int(unsafe.Sizeof(rawEvent{})) {
		return Event{}, fmt.Errorf("short bpf sample: %d bytes", len(record.RawSample))
	}

	var raw rawEvent
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
		return Event{}, err
	}

	return Event{
		// bpf_ktime_get_ns is monotonic time since boot, not Unix wall-clock
		// time. Use arrival time for an API/report timestamp; raw.TsNs remains
		// available to calculate in-kernel durations such as disk latency.
		Timestamp: time.Now(),
		Type:      EventType(raw.Type),
		PID:       raw.PID,
		PPID:      raw.PPID,
		CPU:       raw.CPU,
		Value:     raw.Value,
		Value2:    raw.Value2,
		Comm:      strings.TrimRight(string(raw.Comm[:]), "\x00"),
		Detail:    strings.TrimRight(string(raw.Detail[:]), "\x00"),
	}, nil
}

func (l *Loader) ReadCounters() ([CTRMax]uint64, error) {
	var out [CTRMax]uint64
	nCPU, err := cilium.PossibleCPU()
	if err != nil {
		nCPU = 1
	}
	for i := uint32(0); i < CTRMax; i++ {
		values := make([]uint64, nCPU)
		if err := l.counters.Lookup(i, &values); err != nil {
			perCPU := make([]uint64, 128)
			if err2 := l.counters.Lookup(i, &perCPU); err2 != nil {
				continue
			}
			values = perCPU
		}
		var sum uint64
		for _, v := range values {
			sum += v
		}
		out[i] = sum
	}
	return out, nil
}

func (l *Loader) Close() error {
	if l.reader != nil {
		_ = l.reader.Close()
	}
	for _, lnk := range l.links {
		_ = lnk.Close()
	}
	if l.collection != nil {
		l.collection.Close()
	}
	return nil
}
