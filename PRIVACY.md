# Privacy Policy

## Data Collection

**Tarn does not collect, transmit, or store any personal data.**

The extension operates entirely locally on your machine. There is:
- No telemetry
- No analytics
- No update-checking mechanism
- No remote code loading

## Network Requests

### Browser-Level Requests (Extension)

Tarn makes the following network requests **only** through the tunnel/IP-check functionality:

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `api.ipify.org` | Public IP verification | None (GET request) |
| `ifconfig.me` | Public IP verification (fallback) | None (GET request) |
| `api.myip.com` | Public IP verification (fallback) | None (GET request) |
| `browserleaks.com/dns` | "Leak test" button (popup) | Opens DNS-leak test page in a new tab, triggered by you |

These requests are made solely to determine your public IP address for the "My IP" feature and health checks. No personal information is transmitted. The "Leak test" button in the popup opens `browserleaks.com/dns` only when you click it — Tarn does not call it otherwise.

## Runtime Transparency

Tarn performs the following operations that are visible to web pages you visit and to the operating system. All of them are described here so there are no hidden behaviors:

### Content Scripts ("AntiTrack")

When the tunnel is active, Tarn injects a small content script into web pages to reduce browser fingerprinting and block anti-bot detection. Concretely, when you enable this protection the extension may:

- Inject JavaScript into **all pages** (`<all_urls>`) while anti-fingerprinting is enabled, matching the `content_scripts` declaration in `manifest.json`.
- Add **randomized noise** to `canvas` and `AudioContext` fingerprint sources, so drawn shapes/audio signals differ between sessions.
- Disable the `navigator.battery` API.
- Patch `Function.prototype.toString` so that function-name checks performed by anti-bot scripts cannot reveal patched internals.
- Skip sensitive domains automatically (banking, payment, webstore — see the `exclude_matches` list in `manifest.json`).

These patches run entirely in your browser and send nothing to the network. They are disabled the moment you turn off the AntiTrack feature or the tunnel.

### Kernel Driver and System Service

- Tarn installs **WinDivert** (a signed network-filter kernel driver, `WinDivert64.sys`) and runs the packet filter engine (`winws.exe`) as a **SYSTEM-level Windows service** named `tarndpi`. This is required because the DPI-mitigation filter must process system-wide traffic.
- The kernel driver is from the upstream WinDivert project (see `THIRD_PARTY_NOTICES.md`); Tarn does not modify it.
- Removing the driver and stopping the service is done on uninstall and when you disable the feature.

### Browsing Traffic

The packet filter operates on your traffic at the network layer (it inspects packet headers to apply DPI-mitigation strategies). Tarn's own components do not log, store, or transmit the packet payloads they inspect.

### Native Host Requests (Python)

The native host (`tarn_host.py`) makes additional network requests for the
packet filter strategy testing:

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `www.cloudflare.com` | Strategy probe target | HTTP HEAD (diagnostic) |
| `www.wikipedia.org` | Strategy probe target | HTTP HEAD (diagnostic) |
| `example.com` | Strategy probe target | HTTP HEAD (diagnostic) |
| `www.example.org` | Strategy probe target | HTTP HEAD (diagnostic) |

These requests are made **only** during the "Full strategy test" operation,
only to user-configured or default probe targets, and only to verify
connectivity. No personal data is transmitted. Probe targets are fully
user-configurable in the extension settings.

The native host may also download `wireproxy` binary from GitHub Releases
(`github.com/windtf/wireproxy`) on first use if the bundled binary is missing.

### DNS-over-HTTPS (DoH) Resolvers

When "Force DoH" is enabled, the native host configures system DNS to use:
| Resolver | Endpoint | Purpose |
|----------|----------|---------|
| AdGuard DNS | `https://dns.adguard-dns.com/dns-query` | Default (when dpiAdguardDns enabled) |
| Cloudflare DNS | `https://cloudflare-dns.com/dns-query` | Fallback option |

These are system-level settings configured via Windows registry. No DNS queries
are sent through the extension itself — the OS resolver handles all DNS traffic.

## Data Storage

All data is stored locally in your browser's `chrome.storage.local`:
- WG configuration profiles (your `.conf` files)
- Extension settings
- Connection state

This data never leaves your machine.

> **Security notice:** tunnel private keys (WG protocol) are stored in plaintext in
> `chrome.storage.local`. This is the standard storage mechanism for Chrome
> extensions; the data is isolated per extension and never leaves the
> browser, but it is stored unencrypted in your browser profile on disk.
> On a shared or compromised system, anything running under your user
> account (or malware with access to your profile) could read it. For
> high-security environments, consider using a dedicated browser profile.

## Third-Party Components

Tarn bundles third-party components (see `THIRD_PARTY_NOTICES.md`). These components operate locally and do not make independent network calls except as described above.

## System Access

With your permission, Tarn may:
- Edit the system `hosts` file (for packet filter host entries)
- Modify system DNS/DoH registry settings (when "Force DoH" is enabled)
- Install and start a kernel network-filter driver (WinDivert) and a SYSTEM service (`tarndpi`) for the packet filter engine (see "Runtime Transparency" above)

On disable, **only** the values this code changed are restored. Your original settings are preserved.

## Changes to This Policy

This policy may be updated with new releases. Check the `PRIVACY.md` file in the repository for the current version.
