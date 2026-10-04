# Installation & Deployment Guide

This guide covers system requirements, downloading dependencies, running SimpleDNS in console mode, and managing SimpleDNS as a background Windows Service.

---

## 1. System Requirements & Compatibility

* **Supported Operating Systems**:
  * Windows 11 (all builds, 64-bit)
  * Windows 10 (Build 1607 and later, 64-bit)
  * Windows Server 2016, 2019, 2022, 2025 (64-bit)
* **Architectures**:
  * `windows/amd64` (x64)
* **Privilege Requirements**:
  * **Transparent Mode (`windivert`)**: Requires **Administrator privileges** to register and open the signed kernel callout driver.
  * **Listener Mode (`listener`)**: Can run under a standard, non-elevated user account on any port >= 1024 (or port 53 if administrator).

---

## 2. Installing WinDivert Binaries

SimpleDNS relies on the official, Microsoft-attested **WinDivert 2.2** driver (`WinDivert.dll` and `WinDivert64.sys`) for transparent packet interception without changing adapter settings.

You can automatically download and verify the official signed binaries using the included PowerShell script:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\download-windivert.ps1
```

The script extracts:
* `bin\WinDivert.dll` (User-mode C library)
* `bin\WinDivert64.sys` (Microsoft-signed kernel WFP driver)

Verify the digital signature of the driver:
```powershell
Get-AuthenticodeSignature bin\WinDivert64.sys
```
*Expected status*: `Valid` (signed by Basil00 / Microsoft Windows Hardware Compatibility Publisher).

---

## 3. Building from Source

SimpleDNS is written in 100% pure Go with zero CGO dependencies (`CGO_ENABLED=0`).

```powershell
# Clone the repository
git clone https://github.com/Du-vy/SImpleDNSClient.git
cd SImpleDNSClient

# Download dependencies
go mod download

# Build the executable
go build -v -o bin\simpledns.exe .\cmd\simpledns
```

---

## 4. Configuration

Ensure a configuration file exists in the current directory or `configs/`:
```powershell
# Copy the documented example configuration
Copy-Item configs\simpledns.example.yaml simpledns.yaml
```

Validate your configuration before starting:
```powershell
bin\simpledns.exe check -c simpledns.yaml
```

---

## 5. Running in Console Mode (Default)

Right-click PowerShell or Windows Terminal and select **Run as Administrator**, then execute:

```powershell
# Run transparently with default or simpledns.yaml configuration
bin\simpledns.exe run

# Run with verbose debug output
bin\simpledns.exe run -v

# Run with a custom configuration file
bin\simpledns.exe run -c C:\Path\To\myconfig.yaml

# Run in non-elevated local listener testing mode
bin\simpledns.exe run --mode listener
```

Press `Ctrl+C` to terminate. SimpleDNS shuts down gracefully and unregisters all kernel filters immediately.

---

## 6. Running as a Windows Service (Optional)

SimpleDNS can be installed as an auto-starting background Windows Service (`NT AUTHORITY\SYSTEM`), ensuring continuous protection across user logins and system reboots.

### 6.1 Install the Service
From an elevated (Administrator) command prompt:
```powershell
bin\simpledns.exe service install -c C:\full\path\to\simpledns.yaml
```
* Note: The configuration path should be an absolute path so the background service can locate it upon boot.
* The installer configures:
  * Startup Type: **Automatic** (starts with Windows boot)
  * Recovery Action: **Restart on failure** (restarts after 5s and 15s)

### 6.2 Manage the Service
```powershell
# Start the service
bin\simpledns.exe service start

# Check operational status
bin\simpledns.exe service status

# Stop the service
bin\simpledns.exe service stop

# Completely remove the service
bin\simpledns.exe service uninstall
```

### 6.3 Standard Windows Service Commands
SimpleDNS integrates with Windows Service Control Manager (`sc.exe` and `services.msc`):
```powershell
sc.exe query SimpleDNS
sc.exe stop SimpleDNS
sc.exe start SimpleDNS
```
