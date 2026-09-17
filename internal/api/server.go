package api

import (
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/ebpfca/ebpfca/internal/reporter"
	"github.com/ebpfca/ebpfca/internal/state"
)

const statusHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="5">
  <title>EBPFCA</title>
  <style>
    :root { color-scheme: dark; --bg:#0f1419; --card:#1a2332; --text:#e8eef7; --muted:#8aa0b8; --accent:#3d9cf0; --ok:#3ecf8e; --warn:#f0b429; }
    * { box-sizing: border-box; }
    body { margin:0; font-family: ui-sans-serif, system-ui, sans-serif; background:var(--bg); color:var(--text); }
    header { padding:1.25rem 1.5rem; border-bottom:1px solid #2a3548; display:flex; justify-content:space-between; align-items:center; }
    h1 { font-size:1.15rem; margin:0; letter-spacing:.04em; }
    .status { color:var(--ok); font-size:.85rem; }
    main { max-width:960px; margin:0 auto; padding:1.5rem; display:grid; gap:1rem; }
    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:1rem; }
    .card { background:var(--card); border-radius:12px; padding:1rem 1.1rem; }
    .label { color:var(--muted); font-size:.75rem; text-transform:uppercase; letter-spacing:.08em; }
    .value { font-size:1.6rem; margin-top:.35rem; font-variant-numeric:tabular-nums; }
    a { color:var(--accent); }
    nav { display:flex; gap:1rem; flex-wrap:wrap; font-size:.9rem; }
    table { width:100%; border-collapse:collapse; font-size:.9rem; }
    th, td { text-align:left; padding:.55rem .4rem; border-bottom:1px solid #2a3548; }
    th { color:var(--muted); font-weight:600; }
    .empty { color:var(--muted); padding:.5rem 0; }
  </style>
</head>
<body>
  <header>
    <h1>EBPFCA Host Observability</h1>
    <span class="status">agent healthy · refreshes every 5 seconds</span>
  </header>
  <main>
    <div class="grid">
      <div class="card"><div class="label">CPU</div><div class="value">{{printf "%.1f" .Host.CPUPercent}}%</div></div>
      <div class="card"><div class="label">Memory</div><div class="value">{{printf "%.1f" .Host.MemoryUsedPercent}}%</div></div>
      <div class="card"><div class="label">Load 1m</div><div class="value">{{printf "%.2f" .Host.Load1}}</div></div>
      <div class="card"><div class="label">TCP</div><div class="value">{{.Host.TCPConnections}}</div></div>
    </div>
    <nav class="card">
      <a href="/metrics">Prometheus metrics</a>
      <a href="/api/v1/state">Live state JSON</a>
      <a href="/api/v1/incidents">Incidents JSON</a>
      <a href="http://127.0.0.1:3000">Grafana</a>
    </nav>
    <div class="card">
      <div class="label">Recent incidents</div>
      {{if .Incidents}}
      <table>
        <thead><tr><th>Incident</th><th>Cause</th><th>Process</th><th>Confidence</th></tr></thead>
        <tbody>
        {{range .Incidents}}
          <tr>
            <td>{{.Incident}}</td>
            <td>{{.RootCause}}</td>
            <td>{{if .SuspectedProcess}}{{.SuspectedProcess}}{{else}}—{{end}}</td>
            <td>{{.Confidence}}</td>
          </tr>
        {{end}}
        </tbody>
      </table>
      {{else}}
      <p class="empty">No incidents yet. Thresholds are evaluated every 10 seconds.</p>
      {{end}}
    </div>
  </main>
</body>
</html>`

type Server struct {
	store   *state.Store
	reports *reporter.Store
	metrics http.Handler
	page    *template.Template
}

func NewServer(store *state.Store, reports *reporter.Store, metrics http.Handler) *Server {
	return &Server{
		store:   store,
		reports: reports,
		metrics: metrics,
		page:    template.Must(template.New("status").Parse(statusHTML)),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", s.metrics)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/api/v1/state", s.handleState)
	mux.HandleFunc("/api/v1/incidents", s.handleIncidents)
	mux.HandleFunc("/", s.handleHome)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	host, _, _, _ := s.store.Snapshot()
	incidents := s.reports.List()
	if len(incidents) > 8 {
		incidents = incidents[:8]
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.page.Execute(w, map[string]any{
		"Host":      host,
		"Incidents": incidents,
	})
}

func (s *Server) handleState(w http.ResponseWriter, _ *http.Request) {
	host, rates, procs, ebpf := s.store.Snapshot()
	writeJSON(w, map[string]any{
		"host":      host,
		"rates":     rates,
		"processes": procs,
		"ebpf":      ebpf,
	})
}

func (s *Server) handleIncidents(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.reports.List())
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
