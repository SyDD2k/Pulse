package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr         string        `yaml:"listen_addr"`
	MetricsPath        string        `yaml:"metrics_path"`
	BPFObjectPath      string        `yaml:"bpf_object_path"`
	IncidentDir        string        `yaml:"incident_dir"`
	HostSampleInterval time.Duration `yaml:"host_sample_interval"`
	RCAInterval        time.Duration `yaml:"rca_interval"`
	IncidentCooldown   time.Duration `yaml:"incident_cooldown"`
	Thresholds         Thresholds    `yaml:"thresholds"`
}

type Thresholds struct {
	CPUPercentHigh        float64 `yaml:"cpu_percent_high"`
	MemoryPercentHigh     float64 `yaml:"memory_percent_high"`
	ContextSwitchRateHigh float64 `yaml:"context_switch_rate_high"`
	PageFaultRateHigh     float64 `yaml:"page_fault_rate_high"`
	DiskLatencyMsHigh     float64 `yaml:"disk_latency_ms_high"`
	ProcessCPUPercentHigh float64 `yaml:"process_cpu_percent_high"`
	NetworkThroughputHigh float64 `yaml:"network_throughput_mbps_high"`
}

func Default() Config {
	return Config{
		ListenAddr:         ":9090",
		MetricsPath:        "/metrics",
		BPFObjectPath:      "bpf/ebpfca.bpf.o",
		IncidentDir:        "data/incidents",
		HostSampleInterval: time.Second,
		RCAInterval:        10 * time.Second,
		IncidentCooldown:   2 * time.Minute,
		Thresholds: Thresholds{
			CPUPercentHigh:        85.0,
			MemoryPercentHigh:     90.0,
			ContextSwitchRateHigh: 20000.0,
			PageFaultRateHigh:     5000.0,
			DiskLatencyMsHigh:     50.0,
			ProcessCPUPercentHigh: 70.0,
			NetworkThroughputHigh: 800.0,
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}
