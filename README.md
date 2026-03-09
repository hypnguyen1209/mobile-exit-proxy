# mobile-exit-proxy

A Tailscale exit node built with [tsnet](https://pkg.go.dev/tailscale.com/tsnet) that forwards all mobile device traffic through Burp Suite for penetration testing.

## Architecture

```
┌──────────┐     WireGuard      ┌─────────────────────┐    HTTP CONNECT     ┌────────────┐        ┌──────────┐
│  Mobile   │ ───────────────── │  mobile-exit-proxy   │ ────────────────── │ Burp Suite │ ────── │ Internet │
│  Device   │    (Tailscale)    │  (tsnet exit node)   │  (127.0.0.1:8083) │   Proxy    │        │          │
└──────────┘                    └─────────────────────┘                     └────────────┘        └──────────┘
                                         │
                                    Web Panel :8080
                                  (status & control)
```

**Traffic flow:**
1. Mobile device connects to Tailscale and selects this node as exit node
2. All mobile internet traffic is routed through the WireGuard tunnel
3. TCP traffic is intercepted and forwarded through Burp Suite:
   - **HTTP (port 80)**: Forwarded as HTTP forward proxy requests (plaintext)
   - **HTTPS/TLS (port 443+)**: Tunneled via HTTP CONNECT (Burp can MITM with its CA cert)
4. DNS queries (UDP :53) are forwarded to configurable upstream servers

## Features

- **JSONC config file** — comments supported, easy to customize
- **Multiple proxy backends** — failover & health checking
- **Buffer pooling** — `sync.Pool` for reduced GC pressure on high-throughput
- **Web control panel** — accessible via tailnet, shows live stats
- **DNS forwarding** — configurable upstream DNS servers
- **No system Tailscale needed** — runs entirely in userspace via tsnet

## Prerequisites

- Go 1.21+
- A [Tailscale account](https://login.tailscale.com)
- Burp Suite with proxy listener on `127.0.0.1:8083`
- Tailscale installed on your mobile device (Android/iOS)

## Build

```bash
go build -o mobile-exit-proxy .
```

## Usage

### Quick Start (CLI flags)

```bash
export TS_AUTHKEY="tskey-auth-xxxxx"
./mobile-exit-proxy -proxy 127.0.0.1:8083 -verbose
```

### With Config File

```bash
cp config.example.jsonc config.jsonc
# Edit config.jsonc with your settings
./mobile-exit-proxy -config config.jsonc
```

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | _(none)_ | JSONC config file path |
| `-hostname` | `mobile-exit-proxy` | Tailscale hostname (overrides config) |
| `-authkey` | `$TS_AUTHKEY` | Tailscale auth key (overrides config) |
| `-proxy` | `127.0.0.1:8083` | Burp proxy address (overrides config) |
| `-verbose` | `false` | Verbose logging (overrides config) |

### Config File (JSONC)

See [config.example.jsonc](config.example.jsonc) for all options:

```jsonc
{
  "hostname": "mobile-exit-proxy",
  "proxies": [
    { "addr": "127.0.0.1:8083", "alias": "burpsuite", "health_check": true },
    { "addr": "127.0.0.1:8084", "alias": "backup", "health_check": true }
  ],
  "dns": ["8.8.8.8:53", "1.1.1.1:53"],
  "buffer_size": 32768,
  "web_listen": ":8080",
  "verbose": false
}
```

## Setup Steps

### 1. Generate a Tailscale Auth Key

Go to [Tailscale Admin > Keys](https://login.tailscale.com/admin/settings/keys) and generate a **reusable** auth key.

### 2. Start Burp Suite

Ensure Burp's proxy listener is running on `127.0.0.1:8083` (or your configured address).

### 3. Start the Proxy

```bash
export TS_AUTHKEY="tskey-auth-xxxxx"
./mobile-exit-proxy -config config.jsonc
```

### 4. Approve Exit Node

1. Go to [Tailscale Admin > Machines](https://login.tailscale.com/admin/machines)
2. Find `mobile-exit-proxy` > `...` > **Edit route settings**
3. Enable **"Use as exit node"**

### 5. Configure Mobile Device

**Android:** Tailscale app > Exit node > Select `mobile-exit-proxy`

**iOS:** Tailscale app > Exit node selector (top) > Select `mobile-exit-proxy`

### 6. Install Burp CA Certificate (for HTTPS interception)

**Android:**
1. Export Burp CA cert (Proxy > Options > Export CA certificate)
2. Transfer `.der` to device
3. Settings > Security > Install certificates > CA certificate

**iOS:**
1. Export and transfer Burp CA cert
2. Settings > General > Profile > Install
3. Settings > General > About > Certificate Trust Settings > Enable full trust

### 7. Web Panel

Open `http://mobile-exit-proxy:8080` from any device on your tailnet to see live connection stats and proxy backend health.

## SSL Pinning Bypass

For apps with certificate pinning, use alongside:
- **Android**: [Frida](https://frida.re/) with ssl-pinning bypass scripts, or [objection](https://github.com/sensepost/objection)
- **iOS**: Frida/objection, or [SSL Kill Switch 2](https://github.com/nicklockwood/ssl-kill-switch2) (jailbroken)

## Performance Tuning

- Increase `buffer_size` to `65536` (64KB) for high-throughput testing
- Add multiple proxy backends for failover
- Health checks run every `health_interval` to detect proxy failures
- Buffer pooling via `sync.Pool` minimizes GC overhead
