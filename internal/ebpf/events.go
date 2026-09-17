package ebpf

import "time"

const TaskCommLen = 16

type EventType uint32

const (
	EVTProcessFork EventType = iota + 1
	EVTProcessExec
	EVTProcessExit
	EVTDiskIssue
	EVTDiskComplete
	EVTTCPConnect
	EVTTCPClose
)

type Event struct {
	Timestamp time.Time
	Type      EventType
	PID       uint32
	PPID      uint32
	CPU       uint32
	Value     uint64
	Value2    uint64
	Comm      string
	Detail    string
}

func (t EventType) String() string {
	switch t {
	case EVTProcessFork:
		return "process_fork"
	case EVTProcessExec:
		return "process_exec"
	case EVTProcessExit:
		return "process_exit"
	case EVTDiskIssue:
		return "disk_issue"
	case EVTDiskComplete:
		return "disk_complete"
	case EVTTCPConnect:
		return "tcp_connect"
	case EVTTCPClose:
		return "tcp_close"
	default:
		return "unknown"
	}
}

const (
	CTRSchedSwitch = 0
	CTRSchedWakeup = 1
	CTRPageFault   = 2
	CTRNetRX       = 3
	CTRNetTX       = 4
	CTRMax         = 5
)
