# Third-Party Notices

Tarn bundles the following third-party components. Their licenses are kept in
the `LICENSES/` directory; the full texts are reproduced there.

| Component | Purpose | License | Files |
|---|---|---|---|
| wireproxy | WG client for userspace proxies (SOCKS5/HTTP) | ISC — Copyright (c) 2026 Tsz Fung Wong (windtf/wireproxy fork of pufferffish/wireproxy) | `engine/bins/wireproxy.exe` |
| Packet filter engine (winws) | Desync-based packet filter (zapret/flowseal strategy family) | MIT — Copyright (c) bol-van / Copyright (c) Flowseal (see below) | `engine/bins/winws.exe`, `engine/conf/*`, `engine/bins/*.bin` |
| zlib (static, inside winws.exe) | Compression library statically linked into the filter engine | zlib License 1.2.11+ (zlib/libpng terms; `Copyright (c) 1995-2023 Jean-loup Gailly and Mark Adler`) — `LICENSES/zlib.txt` | `engine/bins/winws.exe` |
| WinDivert | Windows kernel packet capture/re-injection driver | LGPL-3.0 / GPL-2.0 (dual) | `engine/bins/WinDivert64.sys`, `WinDivert.dll` |
| Cygwin runtime | WinDivert library dependency | LGPL-3.0+ (with Cygwin Linking Exception); see `Cygwin-COPYING.txt` | `engine/bins/cygwin1.dll` |
| Press Start 2P | Pixel UI font | SIL OFL 1.1 | `fonts/PressStart2P-*.woff2` |
| Share Tech Mono | Monospace UI font | SIL OFL 1.1 | `fonts/ShareTechMono-latin.woff2` |
| Embedded Python | Fallback Python runtime for the native host | Python License (PSF) — `Python-LICENSE.txt` | `python-embed-amd64.zip` (bundle) — Python 3.12.8 amd64 |
| OpenSSL 3.x | TLS/crypto for the embedded Python runtime (`_ssl`, `_hashlib` modules) | Apache-2.0 — `Apache-2.0.txt` | `python-embed-amd64.zip`: `libcrypto-3.dll`, `libssl-3.dll` (used by `_ssl.pyd`) |
| Microsoft VC++ Runtime | C runtime for the embedded Python runtime | Microsoft Software License Terms (redistributable; see https://learn.microsoft.com/visualstudio/releases/2019/redistribution) | `python-embed-amd64.zip`: `vcruntime140.dll`, `vcruntime140_1.dll` |
| libffi | Foreign Function Interface for the embedded Python runtime (`_ctypes` module) | MIT — `libffi-MIT.txt` | `python-embed-amd64.zip`: `libffi-8.dll` |
| SQLite | Embedded SQL engine for the embedded Python runtime (`_sqlite3` module) | Public Domain — https://sqlite.org/copyright.html | `python-embed-amd64.zip`: `sqlite3.dll` (used by `_sqlite3.pyd`) |
| Chromium Dino physics | Runner game physics (adapted) | BSD-3-Clause — Copyright 2015 The Chromium Authors | `lib/game.js` |
| TweetNaCl | Curve25519 for WG key derivation | Public Domain | `lib/parser.js` |

> **Note:** wireproxy upstream describes itself as a "WireGuard client"; Tarn uses "WG" for trademark-neutral reference.
> **Fork transparency:** `engine/bins/wireproxy.exe` is built from the `windtf/wireproxy` fork (of `pufferffish/wireproxy`), chosen because it adds HTTP proxy support used by Tarn's split-tunneling. It is a community fork, not an official release; the bundled binary is verified against a pinned SHA-256 before use, and the upstream ISC license text ships next to it. Users may rebuild from source: https://github.com/windtf/wireproxy

## Notes

- **Filter engine**: the bundled `winws.exe` and strategy configs are derived
  from the packet filter project (bol-van/zapret) and the flowseal strategy
  family, both under the MIT License. Copyright notices:
  `Copyright (c) bol-van and the zapret contributors`,
  `Copyright (c) Flowseal (flowseal distribution)`. The flowseal
  distribution LICENSE.txt grants MIT terms for the zapret-derived engine;
  the original copyright notices are preserved in the engine's own files.
  The full MIT text ships next to the binaries in
  `engine/bins/LICENSE.txt`, and the per-file attribution map (renamed
  payloads, strategy origin, upstream references) in
  `engine/bins/ATTRIBUTION.md`. Source for `winws.exe`:
  https://github.com/bol-van/zapret/. The flowseal strategy distribution is
  https://github.com/Flowseal/zapret-discord-youtube; the MIT terms of the
  code bundled here remain valid, and attribution continues to refer to the
  upstream project.
- **Engine config lists**: the shipped `engine/conf/*.lst` files are
  *user-editable configuration*, not third-party content. The exclusion
  lists ship as an empty template (`exc.lst`; an optional user-provided
  profile `exc.default-template` can be copied into it) plus `ipexc.lst` for
  private/link-local IP ranges, which is pre-filled for safety. The target
  lists (`dom.lst`, `tgt.lst`) ship empty and are populated by the user
  through the extension UI (`dom.user`). `ipexc.lst` is byte-for-byte
  identical to the `ipset-exclude.txt` of the flowseal distribution and is
  redistributed under the same MIT terms (verified against
  zapret-discord-youtube 1.10.1).
- **WinDivert**: dual-licensed LGPL-3.0 OR GPL-2.0 — Copyright (c) basil00.
  The binaries are used unmodified, in accordance with the license terms of
  both licenses. The license notice ships next to the binaries in
  `engine/bins/LICENSE.WinDivert.txt`; source:
  https://github.com/basil00/WinDivert.
- **Cygwin**: the Cygwin API library (cygwin1.dll) is covered by LGPL-3.0
  or later with the Cygwin Linking Exception (per
  https://cygwin.com/licensing.html — not the GCC Runtime Library
  Exception). The full license text is reproduced in
  `LICENSES/Cygwin-COPYING.txt`; the notice next to the binary is
  `engine/bins/LICENSE.cygwin.txt`.
- **Bundled license texts**: every bundled component ships a license notice
  next to its binaries in `engine/bins/` (`LICENSE.txt`,
  `LICENSE.WinDivert.txt`, `LICENSE.cygwin.txt`, `LICENSE.wireproxy.txt`)
  plus the full attribution map `engine/bins/ATTRIBUTION.md`; the canonical
  texts live in `LICENSES/`.
- **Embedded Python**: the fallback Python runtime (`python-embed-amd64.zip`,
  bundled by the installer) is distributed under the Python License (PSF
  Version 2, plus the historical CNRI/BeOpen/CWI texts) — reproduced in
  `LICENSES/Python-LICENSE.txt`. The runtime archive additionally contains
  third-party DLLs which are attributed separately in the table above:
  OpenSSL 3.x (`libcrypto-3.dll`, `libssl-3.dll`) under Apache-2.0
  (`LICENSES/Apache-2.0.txt`), libffi (`libffi-8.dll`) under MIT
  (`LICENSES/libffi-MIT.txt`), SQLite (`sqlite3.dll`, Public Domain), and
  the Microsoft VC++ Runtime (`vcruntime140.dll`, `vcruntime140_1.dll`)
  redistributed under the Microsoft Software License Terms. These DLLs are
  used unmodified, as provided by the official CPython embeddable
  distribution.
- **Fonts**: OFL 1.1. The upstream fonts declare Reserved Font Names
  ("Press Start 2P" and "Share" — see `LICENSES/OFL-1.1.txt`); per OFL §4,
  the subset fonts ship with renamed name tables
  (nameID 1/3/4/6 → "TarnPixelFont-*" / "TarnMonoFont-*") to comply with the
  RFN restriction. The rename was applied via `fonttools ttx`
  post-processing to produce OFL-compliant derivative names. Unmodified
  upstream TTF sources are available from:
  - Press Start 2P: https://fonts.google.com/specimen/Press+Start+2P
  - Share Tech Mono: https://fonts.google.com/specimen/Share+Tech+Mono
- **Chromium Dino**: the runner game physics in `lib/game.js` is adapted from
  the Chromium "Dino" runner (chrome://dino), used under BSD-3-Clause.
  Copyright 2015 The Chromium Authors. Full license text in
  `LICENSES/BSD-3-Clause.txt`. Game sprites are original pixel art.
- **TweetNaCl**: the Curve25519 scalar-multiplication implementation in
  `lib/parser.js` (used to derive WG public keys locally) is adapted from
  TweetNaCl.js by Dmitry Chestnykh & Devolutions, released into the
  Public Domain.

Nothing in this file grants rights beyond what the respective upstream
licenses already grant. Tarn itself is licensed under GPL-3.0 (see `LICENSE`).

## Trademarks

- **WireGuard** is a registered trademark of Jason A. Donenfeld. This project
  is not affiliated with or endorsed by the WireGuard project. The name "WG"
  is used as a trademark-neutral reference.
- **Chromium** and **Chrome** are trademarks of Google LLC. This project is
  not affiliated with or endorsed by Google.
