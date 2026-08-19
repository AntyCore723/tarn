# Changelog

All notable changes to Tarn are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.12.0] - 2026-08-19

### Fixed
- **ERR_SSL_PROTOCOL_ERROR on a range of sites while the packet filter was
  on.** Aggressive strategies (`hostfakesplit`, the fake-* and hybrid
  families) were applied to *every* HTTPS connection when no domains were
  listed: winws treats an empty `--hostlist` include list as "match
  everything" (zapret `nfq/hostlist.c`: all include lists empty → check
  passes), so with the default empty `dom.user`/`dom.lst` the desync ran on
  all of 80/443, all alt ports and every IP in `ip.lst` (32k CIDR). Servers
  with strict TLS record-framing validation rejected the desynced stream
  (chat.qwen.ai and others). Aggressive strategies are now strictly
  allowlisted via a materialized `dom.active` file — the user's domains, or
  a match-nothing `0.invalid` sentinel when none are listed — so unlisted
  sites are never touched (IPSet/Game-filter blocks included).
- Clearing "Additional domains" in the UI now also clears `dom.user`
  (previously stale domains survived after the list was emptied).
- `engine/conf/dom.lst` header now documents its real role (exclusion
  list); it was previously described as a processing allowlist.

### Changed
- Probe verification now includes the user's own bypass domains: the
  auto-select and the full strategy test verify TLS against the sites the
  user actually wants to open, so a strategy that breaks one of them is
  rejected instead of being cached as "verified".
- `start_dpi_bypass` response includes a warning when an aggressive
  strategy runs with no listed domains ("touches no site until you add
  domains").
- README troubleshooting tables (EN/RU/ZH) gained an
  `ERR_SSL_PROTOCOL_ERROR` row explaining the v1.11.x root cause and the
  v1.12.0 fix.

### Tests
- `tests/test_neutralization.py`: 5 new regression tests — aggressive
  general blocks allowlisted to `dom.active`, aggressive IPSet/Game blocks
  restricted to it, safe strategies never use it, `_ensure_dom_active`
  sentinel/user-domain materialization (15 total, all passing).

## [1.11.1] - 2026-08-15

### Fixed
- `native-host/tarn_host.py` (`_load_doh_state`): `_doh_prev_autodoh` was
  assigned without a `global` declaration, so a fresh host process could
  never restore the user's original `EnableAutoDoh` value after a crash —
  Windows 11 DoH auto-detect stayed forced to `2` (and `--cleanup-filter`
  could not fully restore DNS). The `global` declaration is now present.
- `native-host/tarn_host.py` (`_configure_doh`): running without
  Administrator rights silently "succeeded" (the inner `except OSError`
  swallowed the elevation `PermissionError`, so the outer handler never
  fired). Elevation failure is now reported and returns `False`.
- `native-host/tarn_host.py` (`_configure_doh`): disabling DoH now removes
  the well-known-server value this code added even when it was set with a
  different server than the current invocation (e.g. AdGuard
  `94.140.14.14` enabled, default `1.1.1.1` disabled). The configured DNS
  is persisted in `doh_state.json` and only values still holding one of
  Tarn's known templates are ever removed (user values are never clobbered).
- `native-host/tarn_host.py`: DHCP-only network adapters (no static
  `IPAddress` value) are now also configured for DoH
  (`DhcpIPAddress` is checked too).
- `native-host/tarn_host.py` (service `binPath`): arguments embedding the
  profile path (which can contain a space, e.g. `C:\Users\John Smith\...`)
  are now quoted individually, so the DPI service starts for users whose
  home path contains spaces.
- `native-host/tarn_host.py`: the elevated kill script now uses
  `tempfile.mkstemp` (unpredictable name) instead of a predictable
  `_tarn_kill_{pid}.ps1`, closing a TOCTOU where an attacker could pre-place
  a script executed with Administrator rights.
- `native-host/tarn_host.py` (`_kill_pid_on_port`): the local port is now
  matched exactly instead of by substring (`:1080` no longer matches
  `:10800`/`:21080`).
- `native-host/tarn_host.py` (`_is_our_process`): only THIS tunnel's
  wireproxy (command line contains `tarn-tunnel`) and the Python
  interpreter running this host (`pid == os.getpid()`) are treated as ours —
  an arbitrary `python.exe` or third-party wireproxy is never killed.
- `native-host/tarn_host.py` (`_find_winws_pid`): prefers command-line-
  scoped own winws PIDs, so a winws.exe started by other software is never
  mistaken for ours.
- `native-host/tarn_host.py`: a single malformed native-messaging message
  (bad length/JSON) no longer terminates the host — `read_message()` now
  distinguishes EOF from malformed input, so a crashed or hostile extension
  cannot take down a live tunnel.
- `native-host/tarn_host.py` (hosts file): reads/writes are now byte-
  preserving (latin-1 round-trip) and atomic (`os.replace`), so a crash
  mid-write can never corrupt the hosts file or re-encode user data.
- `native-host/tarn_host.py` (`_probe_bypass`): the dead `min_ok` parameter
  is now actually honored by the pass/fail verdict.
- `background.js` (`startNative`): the `startNative()` promise now resolves
  immediately on the first "ready" before any side effects, so a rejecting
  `applyProxy`/`clearKillSwitch` can never leave `_connectInFlight=true`
  (which blocked every future connect until SW reload). Post-ready side
  effects are wrapped in try/catch.
- `background.js` (`startNative`): the port identity + `stopping` are
  re-checked after the awaited side effects, so a Disconnect-during-connect
  is no longer overwritten back to "connecting".
- `background.js` (SW restart recovery): a stale `"connecting"` state is now
  also force-disconnected on SW restart (previously only `"connected"` /
  `"reconnecting"`, so a SW killed mid-connect left the UI stuck on
  "Подключение..." forever).
- `lib/proxy.js` (`applyStripHeaders`): DPI strip header names are validated
  against RFC 7230 `tchar` and deduplicated (case-insensitive), so a single
  invalid user-configured header can no longer make the whole atomic
  `updateDynamicRules` call fail silently. `chrome.runtime.lastError` is
  checked and surfaced.
- `native-host/install.sh`: the native-messaging manifest `path` now points
  at `tarn_host.py` alone (it has a `#!/usr/bin/env python3` shebang and is
  `chmod +x`). The previous two-token value (`"python /path/to/host.py"`)
  was exec'd directly by the browser without a shell and broken the host on
  Linux/macOS.
- `native-host/install.sh`: the downloaded `wireproxy` archive (`$WP.tmp`)
  is now removed on the success path too (previously only on failure).
- `uninstall.bat`: the `--cleanup-filter` restore now also runs when a
  system Python was used (install.bat only bundles embedded Python when no
  system Python is found) — detected via `where python` / `where py`, so
  hosts/DNS/DoH settings are no longer left behind.
- `install.bat` / `install_service.bat`: the `:log` subroutine no longer
  truncates the last character of messages ending in a digit (the `%~1>>`
  form parsed a trailing digit as a file-handle redirect).
- `uninstall.bat`: the winws kill filter now matches install.bat's filter,
  so no own winws instance is left running after uninstall.
- `tools/gen_key.py`: the default private-key location moved from
  `~/.tarn-tunnel/keys/` to `~/.tarn-keys/` — the old path lived inside
  `~/.tarn-tunnel`, which `uninstall.bat` deletes entirely (the Web Store
  signing key was being destroyed on uninstall).
- `native-host/diagnose.ps1`: malformed manifests no longer crash the
  diagnostics (both `ConvertFrom-Json` calls are guarded).

### Changed
- `tools/build_release.py`: zips are now built reproducibly (fixed
  1980-01-01 timestamp + fixed DOS attributes), so the artifact is
  byte-identical across machines/checkouts and `SHA256SUMS.txt` stays valid
  for supply-chain verification.
- `.github/workflows/release.yml`: GitHub Actions are now pinned by commit
  SHA (with the human-readable tag in a comment) instead of mutable tags, to
  prevent a compromised/moved tag from running attacker code in CI.
- `native-host/tarn_host.py` (`_install_engine_from`): `wireproxy.exe` is no
  longer copied into the engine dir — it is managed separately (installed to
  `APP_DIR/bin`, verified against `WIREPROXY_SHA256`) and never executed
  from `ENGINE_BINS`; this avoids planting an unverified 10 MB binary.

## [1.11.0] - 2026-08-15

### Changed
- Native messaging host description unified to "Tarn - WireGuard tunnel native
  messaging host" in both `native-host/com.tarn.host.json` and the generated
  manifest written by `install.bat` (Step 4). The previous wording was a stale
  reference to the project's former brand.
- Anti-fingerprinting (`dpiAntiTrack`) description no longer claims WebGL/font
  noise — only canvas and audio are patched (`lib/antitrack-injected.js`).
- `native-host/install.sh` step text is now language-neutral (the extension's
  default UI locale is Russian, so it no longer quotes literal UI strings).
- `install_service.bat` SDDL comment corrected: SYSTEM gets start/stop/query
  only (not "full"); Administrators get full; users get start/stop/query.

### Fixed
- `uninstall.bat`: now restores the hosts file and system DNS/DoH registry
  settings before removing the app directory, via a new `--cleanup-filter`
  CLI mode in the native host (`tarn_host.py`). Previously those settings
  were left in place when the app dir (with its state backup) was deleted.
- `EXPORT_CONTROL.md`: embargoed-destination list now includes the
  Zaporizhzhia and Kherson regions of Ukraine (previously only Crimea,
  Donetsk, and Luhansk were listed).
- `background.js` (`applyProxy`): refuses to route browser traffic to a
  non-loopback proxy address (defense-in-depth; the native host already
  binds loopback only).
- `lib/parser.js`: removed the unused `redact` export (dead code).
- Typo fixed: `ANTRITACK_SYNC` → `ANTITRACK_SYNC` in `background.js` and
  `lib/antitrack-content.js` (message type was consistent on both sides, so
  this was cosmetic).
- `THIRD_PARTY_NOTICES.md`: markdown table was split by an inline blockquote;
  the note now sits below the table, and a fork-transparency note documents
  that `wireproxy.exe` is built from the `windtf/wireproxy` community fork.
- `engine/bins/ATTRIBUTION.md`: documents that some payload files are
  byte-identical aliases of the same upstream payload (intentional).

### Security
- `background.js`: native-host message handler now rejects messages whose
  `sender.id` is not the extension's own ID. This is defense-in-depth — the
  extension has no `externally_connectable` entry and registers no
  `onMessageExternal`/`onConnectExternal` listeners, so external pages and
  third-party extensions already cannot reach it.
- `SECURITY.md` wording corrected: engine verification happens in the native
  host before every `sc start` it issues (a manual elevated `sc start` does
  not pass through it); hosts/DNS edits are done by the native host at
  runtime, not by `install.bat`.

## [1.10.0] - 2026-08-14

### Added
- Registry: `HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts`
  now also registers the native host, in addition to Chrome and Edge.

### Fixed
- `install_service.bat`: the `tarndpi` service SDDL no longer grants
  `SERVICE_CHANGE_CONFIG` to all Authenticated Users (which would have been a
  local privilege-escalation vector). Change-config is now granted only to the
  installing user's SID; all users keep start/stop only.
- `install_service.bat`: `winws.exe` and `WinDivert64.sys` are verified against
  pinned SHA-256 hashes before the service/driver is created, refusing tampered
  engine files from a user-writable directory.
- `install.bat`: the bundled embedded Python is verified against a pinned
  SHA-256 hash before extraction (tampered archives are refused).

## [1.9.0] - 2026-08-13

### Changed
- DPI probe defaults switched to neutral hosts (`www.cloudflare.com`,
  `www.wikipedia.org`, `example.com`, `www.example.org`) — no service-specific
  families in probe targets.
- `HOSTS_ENTRIES` no longer contains service family entries.

### Security
- DPI strategies use denylist-first semantics: safe strategies pass only
  `--hostlist-exclude` (with `dom.user`, `tgt.lst`, `exc.user`), aggressive
  strategies keep the user-domain allowlist while keeping service lists
  excluded.
- `dpiExcludedDomains` from the extension are written to `exc.user` and fed to
  the engine as exclusions.

## [1.8.0] - 2026-08-12

### Changed
- Rebranded engine payloads to neutral equivalents; no service-specific fake
  payloads or list names remain in the engine.
- All shipped `.bin` payloads carry neutral SNI/hostnames only.

## [1.7.0] - 2026-08-11

### Added
- Full DPI strategy test battery (`DPI_TEST_STRATEGIES`) with per-strategy
  diagnostics.
- DNS-over-HTTPS configuration (`_configure_doh`) with prior-value capture and
  exact restore on disable.

## [1.6.0] - 2026-08-10

### Added
- Wireproxy binary verification by pinned SHA-256 on every launch.
- Idle watchdog (120 s) that stops the tunnel when the extension goes away.

## [1.5.0] - 2026-08-09

### Added
- Split tunneling with PAC script (include/exclude modes).
- WebRTC leak protection and QUIC blocking via declarativeNetRequest.

## [1.4.0] - 2026-08-08

### Added
- Kill switch via declarativeNetRequest dynamic rules (blocks all traffic when
  the SOCKS proxy is down; localhost and the extension itself are allowed).
- Ad blocker module (`lib/adblock.js`).

## [1.3.0] - 2026-08-07

### Added
- Anti-track content scripts (`antitrack-content.js` / `antitrack-injected.js`)
  with banking-site exclusions.

## [1.2.0] - 2026-08-06

### Added
- QR code generation for profiles.
- Backup export/import (`exportAll`/`importAll` with schema validation).

## [1.1.0] - 2026-08-05

### Added
- Profile management (create/edit/delete/activate).
- Traffic statistics tracking and session history.

## [1.0.0] - 2026-08-04

### Added
- Initial release: WireGuard profile import, connection management through the
  native messaging host, and the packet filter engine (wireproxy + winws).
