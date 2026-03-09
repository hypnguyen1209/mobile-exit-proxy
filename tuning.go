package main

import (
	"log"

	"gvisor.dev/gvisor/pkg/tcpip"
	"tailscale.com/tsnet"
	"tailscale.com/wgengine/netstack"
)

// netstackTuner is the subset of netstack.Impl we need for tuning.
type netstackTuner interface {
	SetTransportProtocolOption(tcpip.TransportProtocolNumber, tcpip.SettableTransportProtocolOption) tcpip.Error
}

// TuneNetstack applies performance tuning to the gVisor TCP/IP stack
// that powers tsnet's userspace networking.
func TuneNetstack(srv *tsnet.Server, cfg *Config) {
	sys := srv.Sys()

	nsIface, ok := sys.Netstack.GetOK()
	if !ok {
		log.Printf("[tuning] netstack not available, skipping")
		return
	}

	// Type-assert to *netstack.Impl to access SetTransportProtocolOption.
	ns, ok := nsIface.(*netstack.Impl)
	if !ok {
		// Try the interface fallback.
		tuner, ok2 := nsIface.(netstackTuner)
		if !ok2 {
			log.Printf("[tuning] netstack does not support SetTransportProtocolOption, skipping")
			return
		}
		applyTCPTuning(tuner)
		return
	}

	applyTCPTuning(ns)
}

func applyTCPTuning(ns netstackTuner) {
	tcp := tcpip.TransportProtocolNumber(6) // TCP protocol number

	// --- TCP Send Buffer: increase default to 2MB for proxy throughput ---
	sendBuf := tcpip.TCPSendBufferSizeRangeOption{
		Min:     4 << 10, // 4KB
		Default: 2 << 20, // 2MB (up from 1MB default)
		Max:     4 << 20, // 4MB
	}
	if err := ns.SetTransportProtocolOption(tcp, &sendBuf); err != nil {
		log.Printf("[tuning] TCP send buffer: %v", err)
	} else {
		log.Printf("[tuning] TCP send buffer: default=%dMB max=%dMB", sendBuf.Default>>20, sendBuf.Max>>20)
	}

	// --- TCP Receive Buffer: increase for high-bandwidth mobile traffic ---
	recvBuf := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     4 << 10, // 4KB
		Default: 2 << 20, // 2MB
		Max:     4 << 20, // 4MB
	}
	if err := ns.SetTransportProtocolOption(tcp, &recvBuf); err != nil {
		log.Printf("[tuning] TCP recv buffer: %v", err)
	} else {
		log.Printf("[tuning] TCP recv buffer: default=%dMB max=%dMB", recvBuf.Default>>20, recvBuf.Max>>20)
	}

	// --- SACK: selective retransmission for lossy mobile networks ---
	sack := tcpip.TCPSACKEnabled(true)
	if err := ns.SetTransportProtocolOption(tcp, &sack); err != nil {
		log.Printf("[tuning] SACK: %v", err)
	} else {
		log.Printf("[tuning] TCP SACK enabled")
	}

	// --- Auto-tune receive buffer based on RTT/throughput ---
	moderate := tcpip.TCPModerateReceiveBufferOption(true)
	if err := ns.SetTransportProtocolOption(tcp, &moderate); err != nil {
		log.Printf("[tuning] recv buffer moderation: %v", err)
	} else {
		log.Printf("[tuning] TCP recv buffer auto-tuning enabled")
	}

	// --- CUBIC congestion control: better for high-BDP mobile paths ---
	cubic := tcpip.CongestionControlOption("cubic")
	if err := ns.SetTransportProtocolOption(tcp, &cubic); err != nil {
		log.Printf("[tuning] CUBIC: %v (using default)", err)
	} else {
		log.Printf("[tuning] TCP congestion control: CUBIC")
	}

	// --- RACK loss detection: faster recovery on lossy networks ---
	rack := tcpip.TCPRecovery(tcpip.TCPRACKLossDetection)
	if err := ns.SetTransportProtocolOption(tcp, &rack); err != nil {
		log.Printf("[tuning] RACK: %v", err)
	} else {
		log.Printf("[tuning] TCP RACK loss detection enabled")
	}

	log.Printf("[tuning] gVisor TCP stack tuning complete")
}

// TuneMagicsock optimizes the WireGuard magic socket layer.
func TuneMagicsock(srv *tsnet.Server) {
	sys := srv.Sys()

	mc, ok := sys.MagicSock.GetOK()
	if !ok {
		log.Printf("[tuning] magicsock not available")
		return
	}

	// Path MTU Discovery: discover largest unfragmented packet size.
	mc.UpdatePMTUD()
	log.Printf("[tuning] PMTUD update triggered")

	// Probe UDP path lifetime for NAT timeout adaptation.
	mc.SetProbeUDPLifetime(true)
	log.Printf("[tuning] UDP lifetime probing enabled")

	log.Printf("[tuning] magicsock tuning complete")
}
