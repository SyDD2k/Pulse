package rca

type Rule struct {
	ID          string
	Incident    string
	Signals     []string
	RootCause   string
	Confidence  Confidence
	Description string
}

var Rules = []Rule{
	{
		ID:          "cpu-runaway-ctx",
		Incident:    "High CPU Usage",
		Signals:     []string{"high_cpu", "high_context_switch", "runaway_process"},
		RootCause:   "Excessive context switching",
		Confidence:  ConfidenceHigh,
		Description: "CPU saturation with scheduler churn and a dominant process",
	},
	{
		ID:          "memory-oom",
		Incident:    "OOM Risk",
		Signals:     []string{"high_memory", "oom_risk", "high_page_fault"},
		RootCause:   "Critically low available memory",
		Confidence:  ConfidenceHigh,
		Description: "Memory pressure leading to page fault storms",
	},
	{
		ID:          "disk-latency",
		Incident:    "Disk Bottleneck",
		Signals:     []string{"high_disk_latency"},
		RootCause:   "Elevated block I/O latency",
		Confidence:  ConfidenceHigh,
		Description: "Block layer latency from eBPF block_rq tracepoints",
	},
	{
		ID:          "network-pressure",
		Incident:    "Network Bottleneck",
		Signals:     []string{"network_pressure"},
		RootCause:   "High network activity detected",
		Confidence:  ConfidenceMedium,
		Description: "Sustained RX/TX and TCP connection activity",
	},
	{
		ID:          "scheduler-contention",
		Incident:    "Scheduler Contention",
		Signals:     []string{"high_context_switch"},
		RootCause:   "Excessive context switching without CPU saturation",
		Confidence:  ConfidenceMedium,
		Description: "Scheduler overhead without full CPU utilization",
	},
}
