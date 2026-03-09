package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ProxyForwarder struct {
	backends    []*proxyBackend
	bufferSize  int
	dialTimeout time.Duration
	maxIdleTime time.Duration
	verbose     bool

	// Passthrough: domains that bypass Burp and connect directly.
	passthrough   []string
	interceptOnly []string

	bufPool sync.Pool

	activeConns atomic.Int64
	totalConns  atomic.Int64
}

type proxyBackend struct {
	addr      string
	alias     string
	proxyAuth string
	healthy   atomic.Bool
}

func NewProxyForwarder(cfg *Config) *ProxyForwarder {
	pf := &ProxyForwarder{
		bufferSize:    cfg.BufferSize,
		dialTimeout:   cfg.DialTimeout.Duration(),
		maxIdleTime:   cfg.MaxIdleTime.Duration(),
		verbose:       cfg.Verbose,
		passthrough:   cfg.Passthrough,
		interceptOnly: cfg.InterceptOnly,
		bufPool: sync.Pool{
			New: func() any {
				b := make([]byte, cfg.BufferSize)
				return &b
			},
		},
	}

	for _, p := range cfg.Proxies {
		b := &proxyBackend{addr: p.Addr, alias: p.Alias}
		b.healthy.Store(true)
		if p.Username != "" {
			b.proxyAuth = base64.StdEncoding.EncodeToString(
				[]byte(p.Username + ":" + p.Password))
		}
		pf.backends = append(pf.backends, b)
	}

	if len(pf.passthrough) > 0 {
		log.Printf("[passthrough] %d domain(s) will bypass Burp:", len(pf.passthrough))
		for _, d := range pf.passthrough {
			log.Printf("[passthrough]   %s", d)
		}
	}
	if len(pf.interceptOnly) > 0 {
		log.Printf("[intercept] only %d domain(s) go through Burp:", len(pf.interceptOnly))
		for _, d := range pf.interceptOnly {
			log.Printf("[intercept]   %s", d)
		}
	}

	return pf
}

// shouldPassthrough checks if a hostname should bypass Burp.
func (pf *ProxyForwarder) shouldPassthrough(hostname string) bool {
	if hostname == "" {
		return false
	}
	h := strings.ToLower(hostname)

	// intercept_only mode: only listed domains go through Burp, everything else is passthrough.
	if len(pf.interceptOnly) > 0 {
		for _, pattern := range pf.interceptOnly {
			if matchDomain(h, strings.ToLower(pattern)) {
				return false // intercept this one
			}
		}
		return true // not in intercept list → passthrough
	}

	// passthrough mode: listed domains bypass Burp.
	for _, pattern := range pf.passthrough {
		if matchDomain(h, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// matchDomain checks if hostname matches a pattern.
// Pattern "example.com" matches exactly.
// Pattern ".example.com" matches "foo.example.com", "bar.example.com", etc.
// Pattern "*" matches everything.
func matchDomain(hostname, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, ".") {
		// Suffix match: ".example.com" matches "sub.example.com" and "example.com"
		return strings.HasSuffix(hostname, pattern) || hostname == pattern[1:]
	}
	return hostname == pattern
}

func (pf *ProxyForwarder) pickBackend() *proxyBackend {
	for _, b := range pf.backends {
		if b.healthy.Load() {
			return b
		}
	}
	if len(pf.backends) > 0 {
		return pf.backends[0]
	}
	return nil
}

func (pf *ProxyForwarder) HealthCheckLoop(interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		for _, b := range pf.backends {
			conn, err := net.DialTimeout("tcp", b.addr, 5*time.Second)
			if err != nil {
				if b.healthy.Load() {
					log.Printf("[health] %s (%s) DOWN: %v", b.alias, b.addr, err)
					b.healthy.Store(false)
				}
			} else {
				conn.Close()
				if !b.healthy.Load() {
					log.Printf("[health] %s (%s) UP", b.alias, b.addr)
					b.healthy.Store(true)
				}
			}
		}
	}
}

func (pf *ProxyForwarder) Stats() (active, total int64) {
	return pf.activeConns.Load(), pf.totalConns.Load()
}

func (pf *ProxyForwarder) Backends() []*proxyBackend {
	return pf.backends
}

// HandleConn forwards a single TCP connection.
// It sniffs the protocol, extracts SNI for TLS, and decides whether to
// forward through Burp or connect directly (passthrough).
func (pf *ProxyForwarder) HandleConn(clientConn net.Conn, dstAddr string) {
	defer clientConn.Close()

	pf.activeConns.Add(1)
	connNum := pf.totalConns.Add(1)
	defer pf.activeConns.Add(-1)

	dstHost, dstPort, err := net.SplitHostPort(dstAddr)
	if err != nil {
		log.Printf("[#%d] bad dst %s: %v", connNum, dstAddr, err)
		return
	}

	// Peek the first bytes to detect protocol and extract SNI.
	peekBuf := bufio.NewReaderSize(clientConn, 4096)
	first, peekErr := peekBuf.Peek(3)
	wrappedConn := &peekedConn{Conn: clientConn, reader: peekBuf}

	if peekErr != nil {
		log.Printf("[#%d] -> %s:%s (peek failed: %v)", connNum, dstHost, dstPort, peekErr)
		pf.routeConnection(wrappedConn, dstHost, dstPort, "", false, false, connNum)
		return
	}

	isTLS := first[0] == 0x16 && first[1] == 0x03
	isH2 := string(first) == "PRI"
	isHTTP := isLikelyHTTP(first)

	// Extract SNI hostname from TLS ClientHello.
	var sni string
	if isTLS {
		// Peek only what's already buffered — do NOT try to read more from
		// the client. The first Peek(3) already triggered a Read that pulled
		// the full ClientHello into the buffer. Requesting more bytes would
		// block because the client is waiting for a server response.
		buffered := peekBuf.Buffered()
		if buffered > 0 {
			peeked, _ := peekBuf.Peek(buffered)
			sni = ParseTLSClientHelloSNI(peeked)
		}
	}

	// Determine display name: SNI > reverse DNS > raw IP.
	displayHost := dstHost
	if sni != "" {
		displayHost = sni
	}

	if isTLS || isH2 {
		proto := "TLS"
		if isH2 {
			proto = "H2"
		}
		log.Printf("[#%d] -> %s:%s [%s] sni=%s", connNum, dstHost, dstPort, proto, sni)
	} else if isHTTP {
		log.Printf("[#%d] -> %s:%s [HTTP]", connNum, dstHost, dstPort)
	} else {
		log.Printf("[#%d] -> %s:%s [TCP]", connNum, dstHost, dstPort)
	}

	// Check passthrough: should this domain bypass Burp?
	if pf.shouldPassthrough(sni) || pf.shouldPassthrough(displayHost) {
		log.Printf("[#%d] PASSTHROUGH %s:%s (bypassing Burp)", connNum, displayHost, dstPort)
		pf.handlePassthrough(wrappedConn, dstHost, dstPort, connNum)
		return
	}

	pf.routeConnection(wrappedConn, dstHost, dstPort, sni, isTLS || isH2, isHTTP, connNum)
}

// routeConnection decides how to forward the connection.
func (pf *ProxyForwarder) routeConnection(clientConn net.Conn, dstHost, dstPort, sni string, isTLSOrH2, isHTTP bool, connNum int64) {
	backend := pf.pickBackend()
	if backend == nil {
		log.Printf("[#%d] no proxy backend", connNum)
		return
	}

	// For CONNECT target, prefer SNI hostname over raw IP.
	// This gives Burp the real hostname for TLS interception.
	connectHost := dstHost
	if sni != "" {
		connectHost = sni
	}

	if isTLSOrH2 {
		pf.handleCONNECT(clientConn, connectHost, dstPort, backend, connNum)
	} else if dstPort == "80" && isHTTP {
		pf.handleHTTP(clientConn, dstHost, dstPort, backend, connNum)
	} else {
		pf.handleCONNECT(clientConn, connectHost, dstPort, backend, connNum)
	}
}

// handlePassthrough connects directly to the destination, bypassing Burp.
// Used for domains with SSL pinning that break through Burp.
func (pf *ProxyForwarder) handlePassthrough(clientConn net.Conn, host, port string, connNum int64) {
	target := net.JoinHostPort(host, port)

	// Use a dialer that tries both IPv4 and IPv6 with fallback.
	dialer := &net.Dialer{Timeout: pf.dialTimeout}
	dstConn, err := dialer.Dial("tcp", target)
	if err != nil {
		// If IPv6 fails, try forcing IPv4.
		if isIPv6(host) {
			log.Printf("[#%d] passthrough IPv6 unreachable %s, dropping", connNum, target)
		} else {
			log.Printf("[#%d] passthrough dial %s: %v", connNum, target, err)
		}
		return
	}
	defer dstConn.Close()
	tuneProxyConn(dstConn)

	pf.pipe(clientConn, dstConn, connNum)
}

func isIPv6(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil
}

func (pf *ProxyForwarder) handleCONNECT(clientConn net.Conn, host, port string, backend *proxyBackend, connNum int64) {
	proxyConn, err := net.DialTimeout("tcp", backend.addr, pf.dialTimeout)
	if err != nil {
		log.Printf("[#%d] dial proxy %s: %v", connNum, backend.addr, err)
		backend.healthy.Store(false)
		return
	}
	defer proxyConn.Close()
	tuneProxyConn(proxyConn)

	if pf.maxIdleTime > 0 {
		deadline := time.Now().Add(pf.maxIdleTime)
		proxyConn.SetDeadline(deadline)
		clientConn.SetDeadline(deadline)
	}

	// Use hostname (from SNI) in CONNECT — Burp needs this for TLS interception.
	target := net.JoinHostPort(host, port)
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if backend.proxyAuth != "" {
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", backend.proxyAuth)
	}
	connectReq += "\r\n"

	log.Printf("[#%d] CONNECT %s via %s", connNum, target, backend.alias)

	if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
		log.Printf("[#%d] send CONNECT: %v", connNum, err)
		return
	}

	br := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		log.Printf("[#%d] read CONNECT resp: %v", connNum, err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[#%d] CONNECT %s: %s", connNum, target, resp.Status)
		return
	}

	log.Printf("[#%d] CONNECT %s OK", connNum, target)

	proxyConn.SetDeadline(time.Time{})
	clientConn.SetDeadline(time.Time{})

	bufferedProxy := &bufferedConn{Conn: proxyConn, reader: br}
	pf.pipe(clientConn, bufferedProxy, connNum)
}

func (pf *ProxyForwarder) handleHTTP(clientConn net.Conn, host, port string, backend *proxyBackend, connNum int64) {
	proxyConn, err := net.DialTimeout("tcp", backend.addr, pf.dialTimeout)
	if err != nil {
		log.Printf("[#%d] dial proxy %s: %v", connNum, backend.addr, err)
		backend.healthy.Store(false)
		return
	}
	defer proxyConn.Close()
	tuneProxyConn(proxyConn)

	var clientBuf *bufio.Reader
	if pc, ok := clientConn.(*peekedConn); ok {
		clientBuf = pc.reader
	} else {
		clientBuf = bufio.NewReader(clientConn)
	}

	for {
		req, err := http.ReadRequest(clientBuf)
		if err != nil {
			if err != io.EOF {
				log.Printf("[#%d] read HTTP req: %v", connNum, err)
			}
			return
		}

		if !req.URL.IsAbs() {
			req.URL.Scheme = "http"
			if port == "80" {
				req.URL.Host = host
			} else {
				req.URL.Host = net.JoinHostPort(host, port)
			}
		}

		if backend.proxyAuth != "" {
			req.Header.Set("Proxy-Authorization", "Basic "+backend.proxyAuth)
		}
		if req.Host == "" {
			req.Host = host
		}

		log.Printf("[#%d] HTTP %s %s", connNum, req.Method, req.URL)

		if err := req.WriteProxy(proxyConn); err != nil {
			log.Printf("[#%d] forward HTTP req: %v", connNum, err)
			return
		}

		proxyBuf := bufio.NewReader(proxyConn)
		resp, err := http.ReadResponse(proxyBuf, req)
		if err != nil {
			log.Printf("[#%d] read HTTP resp: %v", connNum, err)
			return
		}

		if err := resp.Write(clientConn); err != nil {
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		if resp.Close || req.Close {
			return
		}
	}
}

func (pf *ProxyForwarder) pipe(a, b net.Conn, connNum int64) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyFn := func(dst, src net.Conn, direction string) {
		defer wg.Done()
		bufPtr := pf.bufPool.Get().(*[]byte)
		defer pf.bufPool.Put(bufPtr)

		n, err := io.CopyBuffer(dst, src, *bufPtr)
		if err != nil && !isClosedErr(err) {
			log.Printf("[#%d] %s: %d bytes, err: %v", connNum, direction, n, err)
		} else if pf.verbose {
			log.Printf("[#%d] %s: %d bytes", connNum, direction, n)
		}
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		if tc, ok := src.(*net.TCPConn); ok {
			tc.CloseRead()
		}
	}

	go copyFn(b, a, "client->proxy")
	go copyFn(a, b, "proxy->client")
	wg.Wait()
}

type peekedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (pc *peekedConn) Read(b []byte) (int, error) {
	return pc.reader.Read(b)
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (bc *bufferedConn) Read(b []byte) (int, error) {
	return bc.reader.Read(b)
}

func isLikelyHTTP(first []byte) bool {
	if len(first) < 3 {
		return false
	}
	s := string(first)
	return s == "GET" || s == "POS" || s == "PUT" || s == "DEL" ||
		s == "HEA" || s == "OPT" || s == "PAT" || s == "CON"
}

func tuneProxyConn(conn net.Conn) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	tc.SetNoDelay(true)
	tc.SetKeepAlive(true)
	tc.SetReadBuffer(256 << 10)
	tc.SetWriteBuffer(256 << 10)
}

func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "closed") ||
		strings.Contains(s, "reset") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "EOF")
}
