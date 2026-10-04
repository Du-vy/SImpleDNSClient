# SimpleDNS

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20%7C%20Server-0078D6?style=flat&logo=windows)](https://microsoft.com/windows)
[![Transports](https://img.shields.io/badge/Transports-DoH%20%7C%20DoT%20%7C%20DoQ%20%7C%20DoH3%20%7C%20UDP%20%7C%20TCP-blueviolet)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A high-performance, transparent DNS client for Microsoft Windows designed to provide seamless, encrypted DNS resolution on Windows versions that lack native DNS-over-HTTPS (especially Windows 10 and Windows Server), as well as Windows 11 where alternative transports such as DNS-over-TLS (DoT), DNS-over-QUIC (DoQ), or DNS-over-HTTPS over HTTP/3 (DoH3) are desired.

Unlike standard DNS proxies, **SimpleDNS does NOT require configuring Windows network adapters to point to `127.0.0.1:53`**. Operating similarly to tools such as YogaDNS, SimpleDNS transparently diverts outbound DNS traffic at the Windows Filtering Platform (WFP) network layer, resolves queries securely across your configured encrypted upstreams, and injects answers directly back into the requesting application socket.

---

## Key Features

* **True System-Wide Transparency**: No manual adapter configuration required. No `127.0.0.1:53` loopback listeners required. All desktop apps, background services, Win32 software, command line tools, and browsers resolve securely without disruption.
* **First-Class Transport Support**:
  * **DNS-over-HTTPS (DoH)**: RFC 8484 over HTTP/2 with persistent connection pooling and HTTP POST privacy.
  * **DNS-over-TLS (DoT)**: RFC 7858 over TLS 1.2/1.3 with session reuse and SNI certificate verification.
  * **DNS-over-QUIC (DoQ)**: RFC 9250 multiplexed over dedicated QUIC streams with zero head-of-line blocking.
  * **DNS-over-HTTPS over HTTP/3 (DoH3)**: RFC 9114 / RFC 8484 over QUIC datagrams.
  * **Classic DNS over UDP & TCP**: RFC 1035 / RFC 7766 with automatic TCP truncation fallback (`TC=1`).
* **Circular-Dependency-Free Bootstrap DNS**: Resolves encrypted endpoint hostnames (e.g. `cloudflare-dns.com`) via configurable bootstrap IPs (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, IPv6) with strict anti-recursion safeguards and singleflight deduplication.
* **Dual Operation Modes**: Runs interactively as a console application or as a native Windows Service (`NT AUTHORITY\SYSTEM`) with automatic boot recovery.
* **High Performance & Low Footprint**: Sub-35ns packet parsing, zero busy loops, sub-15 MB RAM idle usage, and an in-memory LRU cache with dynamic TTL decrementing.
* **Strict Privacy by Default**: Zero telemetry, zero analytics, query logging disabled by default, and **zero silent plaintext fallback** (prevents local downgrade attacks).
* **Guaranteed Clean Cleanup**: Stopping SimpleDNS immediately unregisters kernel filters, leaving the machine in a clean, default network state.

---

## Supported Windows Versions & Compatibility

SimpleDNS is optimized for 64-bit Windows architectures (`windows/amd64`):

| Operating System | Compatibility Status | Interception Method | Notes |
|---|---|---|---|
| **Windows 11** | Fully Supported | WinDivert (Transparent WFP) / Listener | Alternative to native DoH; supports DoT, DoQ, DoH3 |
| **Windows 10** (1607+) | Fully Supported | WinDivert (Transparent WFP) / Listener | Provides full encrypted DNS lacking in native OS |
| **Windows Server 2016-2025** | Fully Supported | WinDivert (Transparent WFP) / Listener | Recommended as Windows Service |
| **Windows 7 / 8.1** | Supported (Legacy Driver) | WinDivert (Transparent WFP) / Listener | Requires Go runtime compatible with legacy Windows |

---

## Quick Start

### 1. Download Dependencies (WinDivert)
SimpleDNS uses the Microsoft-signed WinDivert driver for transparent packet interception. Download the official binaries:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\download-windivert.ps1
```

### 2. Build the Application
```powershell
go build -v -o bin\simpledns.exe .\cmd\simpledns
```

### 3. Validate Configuration
Verify syntax, test bootstrap connectivity, and validate upstream handshakes:
```powershell
bin\simpledns.exe check
```

### 4. Run Transparently (Console Mode)
Open PowerShell as **Administrator** and run:
```powershell
bin\simpledns.exe run
```
*All applications on Windows will immediately resolve DNS through the configured encrypted upstreams without changing adapter settings.* Press `Ctrl+C` to terminate.

---

## CLI Usage

```
Usage:
  simpledns <command> [options]

Commands:
  run                  Run the DNS client in console mode
  check                Validate configuration and test upstream resolvers
  status               Inspect operational and Windows Service status
  service <action>     Manage the Windows Service (install, uninstall, start, stop, status)
  version              Display version and supported capabilities
  help                 Show this help message

Options for 'run':
  -c, --config <file>  Path to YAML configuration file (default: simpledns.yaml)
  --mode <mode>        Override interceptor mode: windivert, listener, or auto
  -v, --verbose        Enable verbose debug logging
```

---

## Windows Service Mode

SimpleDNS can be installed as an auto-starting background Windows Service:

```powershell
# Install service (auto-starts with Windows)
bin\simpledns.exe service install -c C:\Path\To\simpledns.yaml

# Start the service
bin\simpledns.exe service start

# Check running status
bin\simpledns.exe service status

# Stop the service
bin\simpledns.exe service stop

# Uninstall the service
bin\simpledns.exe service uninstall
```

---

## Configuration Overview

Configuration is defined via YAML. A documented example is available at [`configs/simpledns.example.yaml`](configs/simpledns.example.yaml).

```yaml
logging:
  level: "info"
  format: "text"
  log_queries: false     # Set to true only for temporary debugging (protects privacy)

interceptor:
  mode: "windivert"      # Transparent kernel interception (no 127.0.0.1 required)
  windivert:
    tcp_interception: true
    workers: 4

bootstrap:
  servers:
    - "1.1.1.1:53"
    - "8.8.8.8:53"
    - "9.9.9.9:53"
  timeout: "2s"
  retries: 2
  ip_preference: "prefer_ipv4"

routing:
  strategy: "priority"   # "priority", "round_robin", "fastest", "parallel"
  allow_plaintext_fallback: false # Do NOT leak queries if upstreams fail
  probe_interval: "30s"

cache:
  enabled: true
  max_entries: 4096
  min_ttl: "10s"
  max_ttl: "86400s"

upstreams:
  - name: "Cloudflare DoH"
    transport: "doh"
    endpoint: "https://cloudflare-dns.com/dns-query"
    hostname: "cloudflare-dns.com"
    priority: 1

  - name: "Cloudflare DoT"
    transport: "dot"
    endpoint: "1.1.1.1"
    hostname: "cloudflare-dns.com"
    port: 853
    priority: 1

  - name: "Cloudflare DoH3"
    transport: "doh3"
    endpoint: "https://cloudflare-dns.com/dns-query"
    hostname: "cloudflare-dns.com"
    priority: 2

  - name: "Quad9 DoQ"
    transport: "doq"
    endpoint: "dns.quad9.net"
    hostname: "dns.quad9.net"
    port: 853
    priority: 3
```

---

## Benchmarks

Microbenchmarks measured on an AMD Ryzen 7 5700X:

| Operation | Throughput | Latency | Memory Allocs |
|---|---|---|---|
| **Packet Dissection (`ParsePacket`)** | **35,999,968 ops/sec** | **33.3 ns/op** | 128 B/op (1 alloc) |
| **Response Builder (`BuildUDPResponsePacket`)** | **31,529,080 ops/sec** | **36.9 ns/op** | 64 B/op (1 alloc) |
| **Wire Packing (`PackWire`)** | **9,103,308 ops/sec** | **131.2 ns/op** | 64 B/op (1 alloc) |
| **Wire Parsing (`ParseWire`)** | **4,764,494 ops/sec** | **252.6 ns/op** | 304 B/op (6 allocs) |
| **Cache Lookup (`CacheGet`)** | **3,877,327 ops/sec** | **309.3 ns/op** | 288 B/op (7 allocs) |

---

## Detailed Documentation

Comprehensive guides are available in the [`docs/`](docs/) directory:

* [Architecture & Design Decisions](docs/architecture.md): Subsystem breakdown, concurrency model, and component diagrams.
* [Windows Transparency & Interception](docs/windows-transparency.md): Deep dive into WFP callouts, WinDivert, and what can/cannot be intercepted.
* [DNS Transports](docs/transports.md): Protocol specifications for UDP, TCP, DoT, DoH, DoH3, and DoQ.
* [Bootstrap DNS & Anti-Recursion](docs/bootstrap.md): Handling upstream endpoint resolution without circular loops.
* [Security & Privacy Model](docs/security-and-privacy.md): Cryptographic guarantees, TLS certificate validation, and telemetry policy.
* [Installation & Deployment Guide](docs/installation.md): Step-by-step setup and Windows Service deployment.
* [Troubleshooting & Diagnostics](docs/troubleshooting.md): Common error codes, diagnostics, and firewall configurations.

---

## Testing

Run all unit and integration test suites:
```powershell
go test -v ./...
```

Run benchmarks:
```powershell
go test "-bench=." -benchmem .\pkg\dnsmsg .\pkg\cache .\pkg\interceptor\windivert
```

---

## License

This project is licensed under the MIT License. WinDivert is licensed under the GNU Lesser General Public License (LGPL) v3.
