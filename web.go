package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"tailscale.com/tsnet"
)

// WebPanel provides a control panel accessible via the tailnet.
// Mobile users can open this in their browser to see status and switch proxies.
type WebPanel struct {
	cfg       *Config
	forwarder *ProxyForwarder
	srv       *tsnet.Server
}

func NewWebPanel(cfg *Config, forwarder *ProxyForwarder, srv *tsnet.Server) *WebPanel {
	return &WebPanel{cfg: cfg, forwarder: forwarder, srv: srv}
}

func (wp *WebPanel) Serve(ln net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", wp.handleIndex)
	mux.HandleFunc("/api/status", wp.handleStatus)
	return http.Serve(ln, mux)
}

func (wp *WebPanel) handleIndex(w http.ResponseWriter, r *http.Request) {
	active, total := wp.forwarder.Stats()
	ip4, ip6 := wp.srv.TailscaleIPs()

	var backendsHTML strings.Builder
	for i, b := range wp.forwarder.Backends() {
		status := "UP"
		if !b.healthy.Load() {
			status = "DOWN"
		}
		fmt.Fprintf(&backendsHTML, "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			i, b.alias, b.addr, status)
	}

	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>mobile-exit-proxy</title></head>
<body>
<h2>mobile-exit-proxy</h2>
<p>Active: %d | Total: %d</p>
<h3>Node</h3>
<table border="1" cellpadding="4">
<tr><td>Hostname</td><td>%s</td></tr>
<tr><td>IPv4</td><td>%s</td></tr>
<tr><td>IPv6</td><td>%s</td></tr>
</table>
<h3>Backends</h3>
<table border="1" cellpadding="4">
<tr><th>#</th><th>Alias</th><th>Address</th><th>Status</th></tr>
%s
</table>
<p><small>Mobile -> Tailscale WireGuard -> exit node -> Burp Suite -> Internet</small></p>
<script>setTimeout(()=>location.reload(), 5000)</script>
</body>
</html>`,
		active, total,
		wp.cfg.Hostname, ip4, ip6,
		backendsHTML.String())
}

func (wp *WebPanel) handleStatus(w http.ResponseWriter, r *http.Request) {
	active, total := wp.forwarder.Stats()

	var backends []string
	for _, b := range wp.forwarder.Backends() {
		backends = append(backends, fmt.Sprintf(
			`{"alias":%q,"addr":%q,"healthy":%v}`,
			b.alias, b.addr, b.healthy.Load()))
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"active":%d,"total":%d,"backends":[%s]}`,
		active, total, strings.Join(backends, ","))
}
