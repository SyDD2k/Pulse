package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/ebpfca/ebpfca/internal/api"
	"github.com/ebpfca/ebpfca/internal/collector"
	"github.com/ebpfca/ebpfca/internal/config"
	"github.com/ebpfca/ebpfca/internal/detector"
	ebpfloader "github.com/ebpfca/ebpfca/internal/ebpf"
	"github.com/ebpfca/ebpfca/internal/metrics"
	"github.com/ebpfca/ebpfca/internal/rca"
	"github.com/ebpfca/ebpfca/internal/reporter"
	"github.com/ebpfca/ebpfca/internal/state"
)

func main() {
	configPath := flag.String("config", "configs/ebpfca.yml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	store := state.NewStore()
	exporter := metrics.NewExporter(store)
	reportStore := reporter.NewStore(100, cfg.IncidentDir, cfg.IncidentCooldown)

	loader, err := ebpfloader.NewLoader(cfg.BPFObjectPath)
	if err != nil {
		log.Fatalf("ebpf loader: %v", err)
	}
	defer loader.Close()

	hostCollector := collector.NewHostCollector()
	eventCollector := collector.NewEventCollector(loader, store)
	hostSampler := collector.NewHostSampler(hostCollector, loader, store, cfg.HostSampleInterval)

	go eventCollector.Run(ctx)
	go hostSampler.Run(ctx)

	det := detector.NewDetector(cfg.Thresholds)
	engine := rca.NewEngine()

	go runRCA(ctx, cfg, store, det, engine, reportStore, exporter)
	go runMetricsSync(ctx, exporter)

	srv := api.NewServer(store, reportStore, exporter.Handler())
	httpSrv := &http.Server{Addr: cfg.ListenAddr, Handler: srv.Handler()}

	go func() {
		log.Printf("ebpfca listening on %s", cfg.ListenAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}

func runRCA(ctx context.Context, cfg config.Config, store *state.Store, det *detector.Detector, engine *rca.Engine, reports *reporter.Store, exporter *metrics.Exporter) {
	ticker := time.NewTicker(cfg.RCAInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			host, rates, procs, _ := store.Snapshot()
			anomalies := det.Detect(host, rates, procs)
			incidents := engine.Analyze(host, rates, procs, anomalies)
			for _, inc := range incidents {
				added, err := reports.Add(inc)
				if err != nil {
					log.Printf("incident persist error: %v", err)
				}
				if !added {
					continue
				}
				exporter.RecordIncident(inc.Incident, string(inc.Confidence))
				log.Printf("incident detected: %s (%s) — %s", inc.Incident, inc.Confidence, inc.RootCause)
			}
		}
	}
}

func runMetricsSync(ctx context.Context, exporter *metrics.Exporter) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			exporter.Sync()
		}
	}
}
