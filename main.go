package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

func main() {
	configFile := flag.String("config", "", "Config file (JSONC)")
	hostname := flag.String("hostname", "", "Tailscale hostname (overrides config)")
	authkey := flag.String("authkey", "", "Tailscale auth key (overrides config, or set TS_AUTHKEY)")
	proxyAddr := flag.String("proxy", "", "Upstream proxy address (overrides config)")
	verbose := flag.Bool("verbose", false, "Verbose logging (overrides config)")
	flag.Parse()

	// Load config: file first, then CLI overrides.
	var cfg *Config
	if *configFile != "" {
		var err error
		cfg, err = ParseConfig(*configFile)
		if err != nil {
			log.Fatalf("Failed to parse config %s: %v", *configFile, err)
		}
	} else {
		cfg = DefaultConfig()
	}

	// CLI overrides.
	if *hostname != "" {
		cfg.Hostname = *hostname
	}
	if *authkey != "" {
		cfg.AuthKey = *authkey
	}
	if cfg.AuthKey == "" {
		cfg.AuthKey = os.Getenv("TS_AUTHKEY")
	}
	if *proxyAddr != "" {
		cfg.Proxies = []*ProxyBackend{{Addr: *proxyAddr, Alias: "cli-proxy"}}
	}
	if *verbose {
		cfg.Verbose = true
	}
	if cfg.StateDir == "" {
		home, _ := os.UserHomeDir()
		cfg.StateDir = filepath.Join(home, ".mobile-exit-proxy")
	}

	log.SetFlags(log.LstdFlags)
	log.Printf("Starting mobile-exit-proxy")
	log.Printf("  Hostname:    %s", cfg.Hostname)
	log.Printf("  Proxies:     %d backend(s)", len(cfg.Proxies))
	for i, p := range cfg.Proxies {
		log.Printf("    [%d] %s (%s)", i, p.Addr, p.Alias)
	}
	log.Printf("  State dir:   %s", cfg.StateDir)
	log.Printf("  Buffer size: %d KB", cfg.BufferSize/1024)

	if err := run(cfg); err != nil {
		log.Fatalf("Fatal: %v", err)
	}
}

func run(cfg *Config) error {
	if err := os.MkdirAll(cfg.StateDir, 0700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	// Create tsnet server.
	srv := &tsnet.Server{
		Hostname: cfg.Hostname,
		AuthKey:  cfg.AuthKey,
		Dir:      cfg.StateDir,
	}
	if cfg.Verbose {
		srv.Logf = log.Printf
	}

	// Start and wait for tailnet connection.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	status, err := srv.Up(ctx)
	cancel()
	if err != nil {
		return fmt.Errorf("tsnet up: %w", err)
	}

	log.Printf("Connected to tailnet as %s", status.Self.DNSName)
	ip4, ip6 := srv.TailscaleIPs()
	log.Printf("  IPv4: %s", ip4)
	log.Printf("  IPv6: %s", ip6)

	// Advertise as exit node.
	lc, err := srv.LocalClient()
	if err != nil {
		return fmt.Errorf("local client: %w", err)
	}

	prefs := &ipn.MaskedPrefs{
		AdvertiseRoutesSet: true,
	}
	prefs.AdvertiseRoutes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}
	prefs.Prefs.SetAdvertiseExitNode(true)

	updatedPrefs, err := lc.EditPrefs(context.Background(), prefs)
	if err != nil {
		return fmt.Errorf("edit prefs (advertise exit node): %w", err)
	}
	log.Printf("Exit node advertised: %v", updatedPrefs.AdvertisesExitNode())

	// Apply performance tuning to the gVisor TCP stack and WireGuard layer.
	TuneNetstack(srv, cfg)
	TuneMagicsock(srv)

	// Create proxy forwarder with pooling and rotation.
	forwarder := NewProxyForwarder(cfg)

	// Start health checker for proxy backends.
	go forwarder.HealthCheckLoop(cfg.HealthInterval.Duration())

	// Register fallback TCP handler — intercepts all forwarded TCP.
	deregister := srv.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (handler func(net.Conn), intercept bool) {
		dstStr := dst.String()
		return func(conn net.Conn) {
			forwarder.HandleConn(conn, dstStr)
		}, true
	})
	defer deregister()

	// DNS forwarder.
	udpLn, err := srv.ListenPacket("udp", ":53")
	if err != nil {
		log.Printf("Warning: could not start DNS forwarder: %v", err)
	} else {
		dnsForwarder := NewDNSForwarder(cfg)
		go dnsForwarder.ServeDNS(udpLn)
		log.Printf("DNS forwarder started on :53 -> %v", cfg.DNS)
	}

	// Web control panel on tsnet.
	if cfg.WebListen != "" {
		webLn, err := srv.Listen("tcp", cfg.WebListen)
		if err != nil {
			log.Printf("Warning: could not start web panel: %v", err)
		} else {
			panel := NewWebPanel(cfg, forwarder, srv)
			go func() {
				if err := panel.Serve(webLn); err != nil {
					log.Printf("Web panel error: %v", err)
				}
			}()
		}
	}

	log.Printf("Open web panel at http://%s%s to monitor/switch proxies\n", cfg.Hostname, cfg.WebListen)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Printf("Shutting down...")
	srv.Close()
	return nil
}
