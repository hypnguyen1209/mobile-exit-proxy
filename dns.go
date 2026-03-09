package main

import (
	"log"
	"net"
	"sync"
	"time"
)

// DNSForwarder forwards DNS queries to upstream servers with buffer pooling.
type DNSForwarder struct {
	upstreamDNS []string
	verbose     bool
	bufPool     sync.Pool
}

func NewDNSForwarder(cfg *Config) *DNSForwarder {
	dns := cfg.DNS
	if len(dns) == 0 {
		dns = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}
	return &DNSForwarder{
		upstreamDNS: dns,
		verbose:     cfg.Verbose,
		bufPool: sync.Pool{
			New: func() any {
				b := make([]byte, 4096)
				return &b
			},
		},
	}
}

func (df *DNSForwarder) ServeDNS(pc net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := pc.ReadFrom(buf)
		if err != nil {
			if isClosedErr(err) {
				return
			}
			log.Printf("[dns] read: %v", err)
			continue
		}
		if n < 12 {
			continue
		}

		query := make([]byte, n)
		copy(query, buf[:n])
		go df.handleQuery(pc, clientAddr, query)
	}
}

func (df *DNSForwarder) handleQuery(pc net.PacketConn, clientAddr net.Addr, query []byte) {
	if df.verbose {
		log.Printf("[dns] query from %s (%d bytes)", clientAddr, len(query))
	}

	for _, upstream := range df.upstreamDNS {
		resp, err := df.forwardToUpstream(upstream, query)
		if err != nil {
			if df.verbose {
				log.Printf("[dns] %s error: %v", upstream, err)
			}
			continue
		}
		if _, err := pc.WriteTo(resp, clientAddr); err != nil && df.verbose {
			log.Printf("[dns] write resp: %v", err)
		}
		return
	}
	log.Printf("[dns] all upstream DNS failed for %s", clientAddr)
}

func (df *DNSForwarder) forwardToUpstream(upstream string, query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", upstream, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	bufPtr := df.bufPool.Get().(*[]byte)
	defer df.bufPool.Put(bufPtr)

	n, err := conn.Read(*bufPtr)
	if err != nil {
		return nil, err
	}

	resp := make([]byte, n)
	copy(resp, (*bufPtr)[:n])
	return resp, nil
}
