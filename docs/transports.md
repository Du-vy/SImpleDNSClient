# Supported DNS Transports

SimpleDNS treats encrypted transports as first-class citizens. All transports are implemented via a common, extensible `Transport` interface defined in `pkg/transport`.

---

## 1. Summary of Supported Transports

| Transport | Standard / RFC | Default Port | Underlying Protocol | Multiplexing / Concurrency | Encryption / Security |
|---|---|---|---|---|---|
| **Classic UDP** | RFC 1035 | 53 | UDP | Datagram / per-query ID | None (Plaintext) |
| **Classic TCP** | RFC 7766 | 53 | TCP | Stream with 2-byte prefix | None (Plaintext) |
| **DoT** | RFC 7858 | 853 | TLS over TCP | Persistent connection pool | TLS 1.2+ / SNI verification |
| **DoH** | RFC 8484 | 443 | HTTP/2 over TLS | HTTP/2 Stream multiplexing | TLS 1.2+ / SNI verification |
| **DoH3** | RFC 9114 / RFC 8484 | 443 | HTTP/3 over QUIC | QUIC Streams (no HoL blocking) | TLS 1.3 / QUIC Crypto |
| **DoQ** | RFC 9250 | 853 | Dedicated QUIC | Bi-directional QUIC Streams | TLS 1.3 / QUIC Crypto |

---

## 2. Transport Details

### 2.1 Classic DNS over UDP & TCP
* **UDP**: Traditional DNS datagram exchange. If the upstream response sets the `TC` (Truncated) bit and `allow_tcp_fallback: true` is configured, SimpleDNS automatically redials the upstream over TCP to retrieve the complete answer.
* **TCP**: Length-prefixed wire format (2-byte big-endian prefix).

### 2.2 DNS-over-TLS (DoT, RFC 7858)
* Operates on TCP port 853.
* Establishes a TLS session with the configured server name (`hostname`).
* **Connection Reuse**: SimpleDNS maintains an active TLS connection with an idle timeout (10 seconds), preventing repeated 2-RTT TLS handshakes for sequential queries.
* **Resilience**: If a reused TLS connection is closed by the server or encounters an EOF, SimpleDNS reconnects transparently.

### 2.3 DNS-over-HTTPS (DoH, RFC 8484)
* Operates on HTTPS port 443 using HTTP/2.
* Uses **HTTP POST** with `Content-Type: application/dns-message` and `Accept: application/dns-message`.
  * *Why POST instead of GET?* HTTP GET encodes the query in the URL query string (`?dns=...`), which leaks domain names in intermediate web proxies, server access logs, and HTTP caches. HTTP POST sends the query in the encrypted request body.
* **Anti-Circular Dialing**: SimpleDNS uses a custom `DialContext` that resolves the DoH server's endpoint hostname using the local **Bootstrap Resolver** rather than the OS resolver, preventing recursion loops.

### 2.4 DNS-over-HTTPS over HTTP/3 (DoH3, RFC 9114)
* Operates on UDP port 443 using HTTP/3 and QUIC.
* Eliminates TCP head-of-line (HoL) blocking across multiplexed DNS queries: packet loss on one query stream does not stall unrelated DNS queries.
* Uses `github.com/quic-go/quic-go/http3` with custom QUIC dialer resolving via the Bootstrap Resolver.

### 2.5 DNS-over-QUIC (DoQ, RFC 9250)
* Dedicated DNS transport running directly over QUIC on port 853 (ALPN `doq`).
* **Framing**: Each DNS query is sent on a new bi-directional QUIC stream:
  1. 2-byte big-endian length prefix.
  2. DNS message wire format.
  3. Half-close of the send stream (`stream.Close()`), signaling end of query per RFC 9250 Section 5.2.
  4. Server sends 2-byte length prefix + DNS response wire format.
* **Connection Pooling**: SimpleDNS keeps an active QUIC connection alive with keep-alive packets and multiplexes queries across concurrent QUIC streams.

---

## 3. Extensibility: Adding New Transports

The transport subsystem is cleanly decoupled. To add a new transport (e.g. ODoH - Oblivious DoH, or DNSCrypt):
1. Implement the `transport.Transport` interface in `pkg/transport`:
   ```go
   type Transport interface {
       Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error)
       Close() error
       Protocol() string
       Endpoint() string
   }
   ```
2. Register the protocol string in `pkg/transport/transport.go` (`NewTransport`).
3. Add configuration schema support in `pkg/config/config.go`.
No changes to the routing pool, cache, interceptor, or CLI are required.
