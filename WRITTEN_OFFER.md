# Written Offer for Source Code

This software is distributed under the terms of the GNU General Public License
version 3 (GPL-3.0). In compliance with GPL-3.0 §6, we hereby offer any
third party a complete machine-readable copy of the source code for all
GPL-3.0-licensed components.

## Components Covered

This offer applies to:

- **lib/\*.js** — all extension JavaScript (GPL-3.0-only)
- **background.js**, **popup.js**, **options.js** — extension UI/service worker
- **native-host/tarn_host.py** — native messaging host (GPL-3.0-only)
- **tools/\*.py** — build utilities (GPL-3.0-only)

## How to Obtain Source

The complete source code is available at the project repository:

- **Primary**: https://github.com/AntyCore723/tarn

If the repository is unavailable, or you received this software on a physical
media, you may request the source code by contacting the project maintainer
through the GitHub Issues page. To keep the three-year offer enforceable even
if the primary repository is taken down, the source is also mirrored at:

- **Mirror**: https://codeberg.org/AntyCore723/tarn

This offer is valid for three (3) years from the date of distribution of
the corresponding binary, per GPL-3.0 §6b.

## Components Under Other Licenses

The following components are distributed under their own licenses (see
`THIRD_PARTY_NOTICES.md` for details):

| Component | License |
|-----------|---------|
| wireproxy.exe | ISC |
| winws.exe, engine/conf/\* | MIT |
| WinDivert64.sys, WinDivert.dll | LGPL-3.0 / GPL-2.0 (dual) |
| cygwin1.dll | LGPL-3.0+ (Cygwin Linking Exception) |
| Fonts (Press Start 2P, Share Tech Mono) | OFL 1.1 |
| python-embed-amd64.zip | Python License (PSF) |
| lib/parser.js Curve25519 | Public Domain (TweetNaCl) |

For LGPL-3.0 components (WinDivert, Cygwin), the corresponding upstream
source is available at:

- WinDivert: https://github.com/basil00/WinDivert
- Cygwin: https://cygwin.com/licensing.html

## LGPL-3.0 Election for WinDivert

WinDivert64.sys and WinDivert.dll are distributed upstream under the dual
license **LGPL-3.0-or-later OR GPL-2.0-only**. This project is licensed
GPL-3.0-only, and the GNU GPL v3 is not compatible with the GPL v2. The
WinDivert components are therefore used, and offered to you, under the
**LGPL-3.0** option of that dual license.

Per LGPL-3.0 §4d, this notice is provided with each copy of the library:

- We did **not** modify the WinDivert source code. The unmodified upstream
  binaries are used exactly as released (WinDivert **v2.2.2-A**).
- The upstream source code is available at
  https://github.com/basil00/WinDivert (see the v2.2.2-A release tag).
- The unmodified WinDivert binaries remain licensed under LGPL-3.0-or-later
  OR GPL-2.0-only; your rights under either option are preserved.

There are no additional requirements imposed by this project beyond those of
the LGPL-3.0.
