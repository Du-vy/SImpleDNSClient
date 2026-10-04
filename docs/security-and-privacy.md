# Security & Privacy Model

Security and privacy are primary design requirements for SimpleDNS. This document describes the security guarantees, threat model, certificate verification rules, and telemetry policies of SimpleDNS.

---

## 1. Cryptographic Trust & Certificate Validation

### Strict Certificate Validation (No Insecure Shortcuts)
SimpleDNS enforces strict TLS and QUIC certificate verification across all encrypted transports (DoH, DoT, DoH3, and DoQ):
* **`InsecureSkipVerify: false`** is hardcoded across the entire codebase. There are no options, flags, or configuration settings to disable certificate validation.
* **Server Name Indication (SNI)**: The target hostname is transmitted during the TLS handshake and verified against the SAN (Subject Alternative Name) of the server's X.509 certificate.
* **Root Certificate Authorities**: Certificates are verified against the host Windows Trusted Root Certification Authorities store.
* **Minimum TLS Version**: TLS 1.2 is enforced as the absolute minimum; TLS 1.3 is negotiated automatically whenever supported by the upstream resolver.

---

## 2. Privacy Guarantees

### Zero Telemetry & Zero Analytics
* SimpleDNS contains **zero telemetry**, **zero crash reporting to third parties**, **zero analytics**, and **zero advertising**.
* The application makes **zero network connections** other than:
  1. Outbound DNS queries to your configured upstreams.
  2. Outbound bootstrap queries to your configured bootstrap servers.

### Sensitive DNS Query Logging
* In SimpleDNS, **query logging is disabled by default** (`log_queries: false`).
* Even when verbose debug logging is enabled (`--verbose` or `level: "debug"`), the domain names being resolved are **NOT** printed unless `log_queries: true` is explicitly enabled in the configuration file.
* This ensures that console logs, service logs, and terminal transcripts do not leak your browsing history.

### No Silent Downgrade Attacks
* Traditional network attacks (or rogue Wi-Fi portals) attempt to break encrypted DNS by blocking port 443 / 853 to force clients into plaintext DNS over UDP port 53.
* SimpleDNS sets `allow_plaintext_fallback: false` by default. If an attacker blocks encrypted ports, SimpleDNS refuses to transmit unencrypted queries and returns `SERVFAIL` instead of silently leaking user traffic in plaintext.

---

## 3. Threat Model & Boundaries

| Threat | Protected by SimpleDNS? | Explanation |
|---|---|---|
| **Local Wi-Fi / LAN Eavesdropping** | **YES** | DNS queries leave your machine encrypted via TLS 1.3 or QUIC. Local network observers see only encrypted packets to the resolver IP. |
| **ISP DNS Snooping / Hijacking** | **YES** | Outbound port 53 packets are captured before reaching your network card and forwarded over port 443 / 853. ISP port 53 redirection or injection has no effect. |
| **DNS Spoofing / Cache Poisoning** | **YES** | Authenticated TLS/QUIC channels prevent MITM packet injection. Responses carry upstream cryptographic integrity. |
| **SNI Eavesdropping during HTTPS** | **NO** | When your browser connects to a web server after resolving its IP, the HTTPS SNI header may reveal the domain unless ECH (Encrypted Client Hello) is enabled in your browser. SimpleDNS encrypts DNS, not downstream HTTP connections. |
| **Browser-Internal DoH** | **N/A** | If a browser is configured to use its own DoH directly to port 443, it bypasses the system resolver and connects directly via HTTPS. |
