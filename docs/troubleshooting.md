# Troubleshooting & Diagnostics Guide

This document lists common issues, diagnostic procedures, error codes, and solutions when running SimpleDNS.

---

## 1. Quick Diagnostic Checklist

If you encounter unexpected behavior:
1. Run `simpledns check`:
   ```powershell
   bin\simpledns.exe check
   ```
   This validates syntax, verifies all bootstrap DNS servers, and executes a live resolution test against your encrypted upstreams.
2. Run with verbose debug logging:
   ```powershell
   bin\simpledns.exe run -v
   ```
3. Verify that `WinDivert.dll` and `WinDivert64.sys` exist in the same directory as `simpledns.exe`.

---

## 2. Common Errors and Resolutions

### Error: `administrative privileges required for transparent DNS interception`
* **Cause**: Transparent packet interception requires the ability to register and control kernel WFP callouts via the Windows Service Control Manager.
* **Solution**:
  * Right-click PowerShell / Command Prompt and select **Run as Administrator**.
  * Or install SimpleDNS as a background Windows Service (`simpledns service install`), which executes automatically under `NT AUTHORITY\SYSTEM`.
  * If running in a development or unprivileged environment, run in listener mode: `simpledns run --mode listener`.

### Error: `could not load WinDivert.dll`
* **Cause**: `WinDivert.dll` is missing from the search path.
* **Solution**:
  * Place `WinDivert.dll` and `WinDivert64.sys` in the same directory as `simpledns.exe` or run:
    ```powershell
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts\download-windivert.ps1
    ```

### Error: `WinDivertOpen failed: The system cannot find the file specified (code 2 / 3)`
* **Cause**: `WinDivert.dll` was loaded, but the companion kernel driver `WinDivert64.sys` was not found in the same folder.
* **Solution**: Ensure `WinDivert64.sys` is copied into the same directory as `WinDivert.dll`.

### Error: `WinDivertOpen failed: Access is denied (code 5)`
* **Cause**: The process lacks `SeLoadDriverPrivilege` (standard user attempting to open WinDivert handle).
* **Solution**: Elevate the command prompt to Administrator.

### Error: `all upstream resolvers failed to answer` / Client receives `SERVFAIL`
* **Cause**: SimpleDNS successfully intercepted the query, but none of the configured encrypted upstreams responded within their configured timeouts.
* **Troubleshooting**:
  1. Test upstream connectivity:
     ```powershell
     bin\simpledns.exe check
     ```
  2. Inspect whether a corporate firewall or antivirus is blocking outbound port 853 (used by DoT and DoQ).
  3. If your network blocks port 853, configure DoH (`https://cloudflare-dns.com/dns-query`) on port 443, which blends with normal HTTPS traffic.
  4. Check whether your network has dropped Internet connectivity.

### Error: `bootstrap resolution failed on all servers` / Circular Bootstrap Loop
* **Cause**: SimpleDNS was unable to reach any of the configured bootstrap DNS servers (default: `1.1.1.1:53`, `8.8.8.8:53`).
  * If running in WinDivert mode, this typically occurs if WinDivert intercepts SimpleDNS's own queries to port 53.
* **Solution**:
  * SimpleDNS automatically excludes bootstrap servers via dual-stack guards (`(!ip or (...))` and `(!ipv6 or (...))`). Ensure `interceptor.windivert.exempt_ips` contains your bootstrap servers if you customized them manually.
  * Alternatively, configure your upstream `endpoint` using a direct raw IP (e.g. `https://[2606:4700:4700::1111]/dns-query` or `https://1.1.1.1/dns-query`) with `hostname: "cloudflare-dns.com"`. This eliminates bootstrap queries entirely.

### Issue: Queries Appear as Plaintext ("DNS simple") on Upstream / SimpleDNS Shows `Captured: 0`
* **Cause**: WinDivert is not matching or intercepting outbound port 53 traffic.
  1. **Primary DNS IP in `exempt_ips`**: If your local network adapter or router has `192.168.1.1` or your private server IP configured as its primary DNS, and that IP was added to `interceptor.windivert.exempt_ips`, WinDivert deliberately ignores it, letting Windows send plain UDP 53 directly.
  2. **IPv4 Exclusions Breaking IPv6**: In WinDivert, un-guarded `ip.*` expressions evaluate to false on IPv6 packets. SimpleDNS enforces dual-stack guards (`(!ip or (...))`) to prevent this.
* **Solution**:
  * Verify `simpledns.yaml`: do **NOT** list your network adapter's primary DNS server in `exempt_ips`. Only public fallback bootstrap servers (like `1.1.1.1`) should be in `exempt_ips`.

---

## 3. Firewall & Antivirus Notes

* **Windows Defender Firewall**: Standard outbound traffic is permitted by default. No special firewall rules are required for outbound DoH (port 443), DoT (port 853), or DoQ (port 853).
* **Third-Party Antivirus / "Web Protection" Suites**:
  Some antivirus suites (e.g. Avast, Bitdefender, Kaspersky) attempt to intercept port 53 traffic using their own WFP callouts.
  * WinDivert operates at standard filter priority (0).
  * If a conflict occurs, adjust `interceptor.windivert.priority` in `simpledns.yaml` (values can range from -1000 to 1000). A higher priority ensures SimpleDNS classifies packets first.

---

## 4. Exit Codes

| Exit Code | Meaning |
|---|---|
| `0` | Success (normal shutdown, check passed, or service action succeeded) |
| `1` | General error (configuration validation failure, startup error, or privilege check failed) |
| `2` | Service startup failure |
