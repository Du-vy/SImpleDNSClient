# Windows Transparency & Interception Architecture

A core requirement of SimpleDNS is providing **transparent DNS interception without requiring the user to change Windows network adapter DNS settings to `127.0.0.1`**.

This document explains the technical mechanisms behind this design, compares alternative approaches on Windows, outlines operational behavior during network transitions, and explicitly documents what can and cannot be intercepted.

---

## 1. Why `127.0.0.1:53` Is Unacceptable for a Transparent Client

Traditional DNS proxies require the user to open Windows Network Connections and manually set the primary DNS server of every network adapter (Wi-Fi, Ethernet, VPN) to `127.0.0.1` or `::1`.

This approach suffers from critical engineering drawbacks:
1. **Broken Network on Exit**: If the proxy process terminates unexpectedly or crashes, all DNS resolution on the machine stops completely because Windows continues querying `127.0.0.1:53`.
2. **Adapter Churn**: Whenever a laptop connects to a new Wi-Fi network, switches to an Ethernet dock, or receives a new DHCP lease, Windows frequently overwrites or adds DHCP-provided DNS servers, causing DNS leaks.
3. **VPN Conflicts**: Many VPN clients override or lock adapter DNS settings, conflicting with local loopback configurations.
4. **Poor User Experience**: Requiring users to configure adapter settings undermines simplicity and security.

---

## 2. Technical Comparison of Windows Interception Mechanisms

| Mechanism | Kernel Driver Required? | Transparent (No 127.0.0.1)? | Signed Driver Available? | Evaluated Decision |
|---|---|---|---|---|
| **Adapter DNS -> 127.0.0.1** | No | No (breaks on crash) | N/A | **Rejected** (Violates transparency requirement) |
| **User-Mode WFP API (`FwpmFilterAdd0`)** | No | No (Only blocks/permits; cannot redirect without callout) | N/A | **Rejected** (Cannot redirect or modify packets without a kernel callout) |
| **NRPT (Name Resolution Policy Table)** | No | Partial (Only applies to specific namespaces; does not intercept raw sockets) | N/A | **Rejected** (Incomplete interception; ignored by apps using direct sockets) |
| **Custom WFP Kernel Driver** | Yes | Yes | Requires expensive EV certificate & WHQL attestation | **Impractical** for open source distribution without enterprise signing |
| **WinDivert (WFP Kernel Callout)** | Yes | **Yes** | **Yes (Microsoft Attestation Signed)** | **Selected as Primary Architecture** |

### The WFP User-Mode Redirection Reality
While the Windows Filtering Platform (WFP) exposes user-mode management APIs (`fwpuclnt.dll`), Microsoft's architecture requires a kernel-mode driver callback (`FwpsCalloutRegister`) to perform packet redirection (`FWPM_LAYER_ALE_CONNECT_REDIRECT_V4`) or packet modification. User-mode applications alone can only issue `FWP_ACTION_PERMIT` or `FWP_ACTION_BLOCK`.

To perform packet diversion without writing, maintaining, and signing a proprietary kernel driver, SimpleDNS utilizes **WinDivert** (`WinDivert64.sys` / `WinDivert.dll`). WinDivert is an established, open-source WFP callout driver that carries an official Microsoft digital signature, enabling elevated processes on Windows 10, Windows 11, and earlier versions to inspect and divert network traffic safely.

---

## 3. How Transparent Interception Works in SimpleDNS

### Step 1: Kernel Filter Registration
When SimpleDNS starts with administrative privileges, it opens a WinDivert network handle with a dynamic, hardened filter:
```
outbound and !impostor and !loopback and (udp.DstPort == 53 or tcp.DstPort == 53) and (!ip or (ip.DstAddr != ...)) and (!ipv6 or (ipv6.DstAddr != ...))
```
* `outbound`: Intercepts packets originating from local applications before they leave the network card.
* `!impostor`: Excludes packets injected by SimpleDNS itself, preventing infinite loops.
* `!loopback`: Excludes local loopback traffic.
* `udp.DstPort == 53 or tcp.DstPort == 53`: Captures all standard DNS traffic over both IPv4 and IPv6 regardless of the destination IP address.
* `(!ip or (...))` and `(!ipv6 or (...))`: **Dual-Stack Bootstrap Exemption Guards**. Automatically exempts bootstrap DNS server IPs from interception so SimpleDNS's own queries to resolve upstream hostnames travel directly to the network without creating a circular interception deadlock. In WinDivert's filter language, evaluating an `ip.*` predicate on an IPv6 packet fails if not guarded by `!ip`; the dual-stack guards guarantee that IPv6 queries are NEVER dropped or bypassed by IPv4 exclusion rules.

### Step 2: Packet Capture & Dissection
When an application (e.g. Chrome, `svchost.exe`, `ping`, `nslookup`) queries DNS (say, to `192.168.1.1:53`):
1. The kernel diverts the outbound IP packet to SimpleDNS's user-mode worker pool.
2. SimpleDNS extracts the source IP, destination IP, source port, and destination port.
3. The UDP payload is parsed into a DNS message structure (`*dns.Msg`).

### Step 3: Resolution via Encrypted Transports
SimpleDNS processes the query through its in-memory cache and forwards cache misses to the configured upstream encrypted resolvers (DoH, DoT, DoQ, DoH3) using HTTP/2, HTTP/3, or TLS.

### Step 4: Spoofed Inbound Packet Injection
Upon receiving the response from the upstream encrypted resolver:
1. SimpleDNS constructs a new IP/UDP packet.
2. **Reversed Addresses**:
   * Packet Source IP = Original Destination IP (e.g. `192.168.1.1`)
   * Packet Destination IP = Original Source IP (e.g. client local IP)
   * Packet Source Port = `53`
   * Packet Destination Port = Original Client Port (e.g. `54321`)
3. **Checksum Recalculation**: Computes the 16-bit one's complement checksums for the IPv4 header and UDP pseudo-header per RFC 768 / 1071 / 2460.
4. **Direction Inversion**: Sets `addr.Outbound = false` (inbound) and `addr.Impostor = true`.
5. Injects the packet into the Windows network stack via `WinDivertSend`.

### Step 5: Transparent Delivery
The Windows network stack receives the inbound packet as if it arrived directly from `192.168.1.1:53`. The querying application's socket unblocks and receives the response. **No configuration was changed on any network adapter.**

---

## 4. What CAN and CANNOT Be Intercepted

Honest engineering requires clearly defining the capabilities and boundaries of packet diversion:

### What CAN Be Intercepted:
* **Windows DNS Client Resolver**: All queries issued by `svchost.exe` (`Dnscache` service) on behalf of Win32 applications calling `getaddrinfo()`, `GetHostByName()`, or WinRT name resolution APIs.
* **Direct Socket Applications**: Applications that bypass the Windows DNS client and construct raw UDP or TCP sockets to port 53 (e.g. `nslookup`, `dig`, game engines, diagnostic tools).
* **IPv4 and IPv6 Traffic**: Outbound port 53 traffic over both IPv4 and IPv6.
* **Third-Party Browsers**: Browsers running with default system DNS configurations.

### What CANNOT Be Intercepted:
* **Application-Level Encrypted DNS**: If a browser or application (e.g. Firefox or Chrome with "Secure DNS" enabled) connects directly to an HTTPS DoH server over port 443 (e.g. `https://cloudflare-dns.com/dns-query`), that traffic is encrypted HTTPS over port 443. A port 53 filter cannot inspect or divert port 443 traffic without performing a TLS man-in-the-middle proxy with root certificate installation.
* **Full-Tunnel VPNs**: VPN clients that use proprietary virtual network adapters (or NDIS filter drivers located lower in the network stack than WFP) may route packets through an encrypted tunnel before WFP inspects them.
* **Local Hosts File**: Entries defined in `C:\Windows\System32\drivers\etc\hosts` are resolved locally by the Windows resolver without generating network packets.
* **Local Multicast / Link-Local Resolution**: mDNS (port 5353), LLMNR (port 5355), and NetBIOS-NS (port 137) use distinct ports and multicast addresses.

---

## 5. Network Transitions & Reliability

### Network Adapter Changes (Wi-Fi <-> Ethernet)
WinDivert operates at the IP packet layer using the interface index (`IfIdx`) supplied by the kernel. When a machine switches from Wi-Fi to Ethernet or receives a new DHCP address, outbound packets on the new interface match the filter automatically. SimpleDNS does not need to rebind sockets or monitor network interface list changes.

### Sleep, Resume & Hibernation
When Windows suspends and resumes:
* The WinDivert handle remains valid.
* The upstream connection pools automatically reconnect with backoff when network connectivity is re-established.
* If a WinDivert handle error occurs during system resume, the worker pool detects the failure and gracefully re-establishes the capture handle.

### Clean Shutdown Guarantee
SimpleDNS attaches a process signal handler (handling `SIGINT`, `SIGTERM`, and Windows Service `SERVICE_CONTROL_STOP` / `SERVICE_CONTROL_SHUTDOWN`).
When stopped:
1. The WinDivert handle is closed (`WinDivertClose`).
2. The Windows kernel immediately detaches the WFP callout filter.
3. System DNS traffic immediately flows normally to the default DNS servers.
4. **Under no circumstances is the operating system left in a broken DNS state.**
