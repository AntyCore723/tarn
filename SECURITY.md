# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.11.x  | ✅        |
| 1.10.x  | ✅        |
| < 1.10  | ❌        |

## Reporting a Vulnerability

If you discover a security vulnerability in Tarn, please report it responsibly:

1. **Do NOT** open a public GitHub issue for security vulnerabilities.
2. Contact the maintainers privately via GitHub Security Advisory at
   https://github.com/AntyCore723/tarn/security/advisories/new
3. Allow reasonable time for a fix before public disclosure (typically 90 days).

## Security Considerations

### What This Software Does

- Creates a `tarndpi` Windows service running `winws.exe` as **SYSTEM** and a `WinDivert` kernel driver.
- The service starts on demand (`start=demand`): winws runs only while the filter is enabled.
- The native host (`tarn_host.py`) may edit the system `hosts` file and, when "Force DoH" is on, the system DNS/DoH registry settings while a profile is connected or the packet filter is active. On disable, it restores exactly the interfaces and values it changed (see README).

### Supply-Chain Protection

- `wireproxy.exe` and the packet filter engine (`winws.exe`, `WinDivert64.sys`, `WinDivert.dll`, `cygwin1.dll`) are verified against pinned SHA-256 hashes at copy time **and** right before every launch.
- Only the pinned bundled `wireproxy` is ever executed (no PATH fallback).
- Downloaded binaries are refused unless they match the pin.
- `python-embed-amd64.zip` is verified against a pinned SHA-256 before extraction (refuses tampered archives).
- The native host re-verifies engine file integrity before every `sc start` it issues (prevents SYSTEM execution if binaries are replaced post-install). Note: this verification lives in the extension's start path — a manual `sc start tarndpi` from an elevated console does not pass through it. A local attacker who can already write to your profile can replace the binaries; cross-user replacement is prevented by your profile's ACL.
- **Payload `.bin` files** (fake TLS/QUIC/HTTP headers, game/voice UDP samples, STUN probes) are used by `winws.exe` at runtime. **All 11 payload files** are pinned in the host's `ENGINE_SHA256` dictionary and verified at copy time and before every launch, just like the executables. The remaining engine artifacts (config `.lst` files) are treated as data, not executable code.

### Privilege Boundaries

- WinDivert and winws run with SYSTEM privileges because the filter must process system-wide traffic.
- A vulnerability in either binary is a privilege boundary — update the bundle when a new release ships.

### Residual Risks

- WinDivert and winws run with SYSTEM privileges because the filter must process system-wide traffic.
- A vulnerability in either binary is a privilege boundary.
- Keep the bundle updated to receive security fixes for bundled components.

## Known Issues

### HTTP/3 (QUIC) Cache Limitation

- Chrome caches HTTP/3 (h3) endpoints for 1-7 days after a site is first visited.
- Tarn's QUIC block removes the `alt-svc` header from responses, but for sites already cached in Chrome, QUIC may continue to work for up to 7 days after first activation.
- **Mitigation**: Clear Chrome browsing data (cached images/files) after enabling QUIC block, or restart Chrome with `--disable-quic` flag.

### Privacy & Network Protection

Tarn groups several browser-level features under "Network Protection". For clarity, these are categorized as:

**Privacy features** (standard in Brave, Firefox, Edge):
- QUIC control / QUIC fallback to TCP (alt-svc header management)
- Header management (alt-svc, server, x-powered-by)
- Content filtering (static domain list, declarativeNetRequest)
- Anti-fingerprinting (canvas noise, WebRTC protection, speech synthesis)
- IP verification (public IP check via third-party services)
- Statistics (local-only session tracking, no data leaves the device)

**Network management** (kernel-level, traffic analysis):
- Traffic analysis engine (WinDivert kernel packet inspection)
- DNS configuration (system-wide DNS-over-HTTPS via Windows registry)

The distinction matters for legal interpretation: privacy features exist natively in major browsers and do not constitute traffic management under applicable law.

### Antitrack: Pass-Through Design

- Anti-fingerprinting now passes through **real** values for:
  - `hardwareConcurrency` and `deviceMemory` (navigator)
  - `colorDepth` and `pixelDepth` (screen)
  - WebGL renderer/vendor (no-op pass-through)
- Faking fixed values (e.g., 4 cores, 24-bit color) creates an **identical fingerprint** across all Tarn users, which is a stronger tracking signal than real hardware shared by millions of devices.
- Battery API is **disabled entirely** (matches Firefox/Tor approach; W3C deprecated Battery Status API in 2019).
- Canvas noise (±0.0005) and audio fingerprint noise (±0.005) remain active as randomized protections.

### Antivirus Detection (Expected)

WinDivert and winws are routinely flagged by antivirus engines. This is **expected** for kernel packet-drivers and is not a traditional false positive — it is a heuristic based on the tool's capability, not malicious behavior:

- **Kaspersky**: `Multi.WinDivert.gen`, `not-a-virus:HEUR:RiskTool.WinDivert`
- **Windows Defender**: `HackTool:Win64/WinDivert!MSR`
- **ESET**: `Win32/WinDivert.A potentially unsafe application`
- **VirusTotal**: ~3/71 engines flag it (Cylance Unsafe, Kaspersky HEUR:RiskTool)
- **LOLDrivers.io**: WinDivert is listed (legitimate driver abused by malware)

### Windows 11 24H2+ Compatibility

- **Microsoft cross-signed trust removal (March 2026)**: Windows 11 24H2+ may stop trusting cross-signed kernel drivers by default. WinDivert64.sys (signed 2022 via Sectigo→Comodo) may fail to load on some configurations.
- **EV certificate expiry**: The Mistiny Technology EV certificate expired May 2023. Windows trusts the timestamp (2022-09-20), so the driver still loads on most systems — but this is not guaranteed on all configurations. Monitor basil00/WinDivert for v2.2.2-B or v2.2.3 updates.
