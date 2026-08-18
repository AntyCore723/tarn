# Export Control

This software contains cryptographic functionality and may be subject to export
control regulations in certain jurisdictions.

## Classification

The cryptographic components in this software are classified as:

- **ECCN 5D002.c.1**: Encryption software for data confidentiality
- **Relevant exemption**: §742.15(b)(1) — publicly available encryption source
  code (as amended at 15 CFR §742.15(b)(1))

## Non-Cryptographic Components

The following components are **not** encryption items under the EAR and are
not classified under ECCN 5D002:

- **Packet filter engine** (`winws.exe`, WinDivert, payload `.bin` files,
  `engine/conf/*`) — network packet manipulation / traffic analysis
  (desynchronization, fragmentation), not cryptography. Classified as EAR99
  or not subject to the EAR.
- **Anti-tracking protections** (`lib/antitrack-*.js`) — browser-level
  fingerprinting noise and header management, not encryption.
- **Ad blocker** (declarativeNetRequest dynamic rules) — content filtering,
  not encryption.

ECCN 5D002.c.1 applies only to the WireGuard protocol implementation
(wireproxy: ChaCha20-Poly1305, Curve25519) and the TweetNaCl-derived key
derivation code in `lib/parser.js`.

## Notices

- This software uses **WireGuard** protocol implementation (wireproxy),
  **Curve25519** elliptic-curve Diffie-Hellman (TweetNaCl-derived), and
  **ChaCha20-Poly1305** (RFC 8439, via WireGuard handshake) — all standard,
  publicly documented cryptographic primitives.
- The source code is publicly available on GitHub. Under §742.15(b)(1),
  publicly available encryption source code is exempt from license exception
  requirements, **except** when exported to embargoed destinations.
- **Embargoed destinations**: this software may not be exported or re-exported
  to Cuba, Iran, North Korea, Syria, or the Crimea, Donetsk, Luhansk,
  Zaporizhzhia, and Kherson regions of Ukraine, or any other embargoed
  destination under US/EU sanctions without appropriate authorization.
- **Russia/Belarus**: export of encryption items to Russia and Belarus is
  restricted under BIS sanctions (15 CFR §746.8). The §742.15(b)(1)
  publicly-available source-code exemption generally covers open-source
  code published on public repositories; users remain responsible for
  complying with applicable sanctions in their jurisdiction.

## Source Code Availability

The source code for this software is available at:
- **Repository**: https://github.com/AntyCore723/tarn

For GPL-3.0-licensed object code (binary releases), the corresponding source
code is available at the same repository, per GPL-3.0 §6 and §742.15(b)(2).

> **Note**: Since March 2021 (86 FR 16488), no BIS/NSA email notification is
> required for publicly available encryption source code published on public
> repositories; this document is maintained for record-keeping purposes only.

## Compliance

Users are responsible for complying with all applicable export control laws
in their jurisdiction. The authors make no representation regarding the
legality of use in any specific jurisdiction.

> **Note**: This document is for informational purposes only and does not
> constitute legal advice. Consult qualified counsel for specific guidance.
