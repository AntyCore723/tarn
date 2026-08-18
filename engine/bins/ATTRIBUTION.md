# Tarn Engine — File Attribution

This document maps the files in `engine/bins/` and `engine/conf/` to their
upstream origins. License texts live in this directory (`LICENSE.txt`,
`LICENSE.WinDivert.txt`, `LICENSE.cygwin.txt`, `LICENSE.wireproxy.txt`) and
in `LICENSES/` at the project root.

## Engine binaries

| File | Origin | License |
|---|---|---|
| `winws.exe` | compiled from bol-van/zapret C sources (flowseal build variant; upstream source, no Tarn modifications) | MIT |
| `WinDivert.dll` | basil00/WinDivert | LGPL-3.0 OR GPL-2.0 |
| `WinDivert64.sys` | basil00/WinDivert | LGPL-3.0 OR GPL-2.0 |

**WinDivert note:** The bundled `WinDivert64.sys` is **byte-for-byte identical** to the upstream basil00/WinDivert v2.2.2-A release (SHA-256 `8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2`). The embedded EV code-signing certificate from 成都密思听科技有限公司 (Mistiny Technology, Chengdu) was publicly solicited by basil00 (GitHub Issue #53, 2022-07-29) and acknowledged at https://reqrypt.org/windivert.html. Mistiny is a legitimate EDR vendor that donated EV-signing to the WinDivert project — no executable content was modified.
| `cygwin1.dll` | Cygwin runtime | LGPL-3.0+ + Cygwin Linking Exception |
| `wireproxy.exe` | windtf/wireproxy fork of pufferffish/wireproxy | ISC |

## Payload files (renamed)

All payload files below are taken from the zapret / flowseal payload sets
(verified current as of zapret-discord-youtube 1.10.1) and renamed by Tarn.
The **original upstream filenames refer to specific blocked services** and
are intentionally not reproduced in shipped documentation; the rename is
part of the project's neutralization work (see the deprecated-artifact list
in `tarn_host.py`). In addition to renaming, every payload has had its TLS
**Server Name Indication replaced with a neutral `*.example` name** — the
files are byte-identical to the upstream payloads except for that SNI
field (verified by byte-diff), so payload sizes and handshake structure
are preserved while no real service is referenced. The upstream sets:

| Tarn name | Upstream set |
|---|---|
| `fake_tls.bin` | **not from upstream — original to Tarn** (TLS client-hello payload; GPL-3.0) |
| `fake_quic.bin` | QUIC initial fake payload |
| `fake_http.bin` | HTTP/TLS fake payload variant |
| `quic_initial_sample.bin` | QUIC initial sample payload |
| `tls_clienthello_large.bin` | TLS client-hello sample |
| `tls_clienthello_sample.bin` | TLS client-hello sample |
| `voice_udp.bin` | voice/VoIP UDP payload |
| `game_udp.bin` | gaming UDP payload |
| `stun.bin` | STUN probe payload |
| `stun2.bin` | STUN probe payload variant |
| `probe.bin` | connectivity probe packet (Tarn-specific reuse) |

> **Note on duplicate payloads:** some Tarn names are **byte-identical aliases**
> of the same upstream payload — `quic_initial_sample.bin` ≡ `game_udp.bin`,
> `stun.bin` ≡ `probe.bin`, and `tls_clienthello_large.bin` ≡ `fake_http.bin`
> (verified by SHA-256). They exist as separate files because different
> strategies reference them under distinct names; each is independently pinned
> in the host's `ENGINE_SHA256` dictionary. This is intentional, not an
> accidental duplication.

## Engine strategy configs

The desync strategy arguments are defined in `native-host/tarn_host.py`
(`_build_args`). They mirror the strategy family of the upstream engine
(`fake+fakedsplit`, `simple fake`, `fake+multisplit`, `hostfakesplit`,
`EXP`, `fake TLS auto`, `multisplit`, `syndata+multidisorder`,
`fake badseq`, plus hybrid variants), with strategy selection, probing and
verification logic added by Tarn.

## Engine config lists (`engine/conf/`)

| File | Origin | Notes |
|---|---|---|
| `dom.lst` | Tarn template | empty by design; user-populated (`dom.user`) |
| `tgt.lst` | Tarn template (migrated from the legacy targeted-group list) | empty by design |
| `exc.lst` | Tarn template | empty by design; optional profile `exc.default-template` |
| `exc.default-template` | derived from an exclusion list profile of the upstream distribution | optional profile |
| `exc.user` | Tarn runtime | populated via the extension UI |
| `ipexc.lst` | derived from the private-range exclusion list of the flowseal distribution (`ipset-exclude.txt`) | pre-filled for safety |
| `ipexc.user` | Tarn runtime | populated via the extension UI |
| `ip.lst` | upstream engine's ipset data (shipped static, renamed); used by the filter rules (`--ipset`) | MIT |

## Tarn-original files

The following are original to Tarn (GPL-3.0, see `LICENSE` at the project
root): extension code (`background.js`, `options.js`, `popup.js`, `lib/*`),
`native-host/tarn_host.py`, installer scripts (`install.bat`,
`install_service.bat`, `uninstall.bat`, `native-host/diagnose.ps1`),
`engine/conf/*.user` handling, and the connectivity probe logic.

## Upstream references

- bol-van/zapret: https://github.com/bol-van/zapret/
- Flowseal strategy distribution: https://github.com/Flowseal/zapret-discord-youtube
- basil00/WinDivert: https://github.com/basil00/WinDivert
- windtf/wireproxy: https://github.com/windtf/wireproxy (fork of pufferffish/wireproxy)
- Cygwin: https://cygwin.com/

The MIT terms of the code bundled here remain valid, and attribution
continues to refer to the upstream project.
