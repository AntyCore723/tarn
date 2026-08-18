#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""
ext_id.py - Deterministic Chrome extension ID from the manifest.json "key" field.

Matches Chromium's algorithm (extensions/common/id_util.cc, crx_file::GenerateId):

    ID = 32 characters, each character is one 4-bit nibble (a..p) of
    SHA-256(public key DER SPKI bytes), using the FIRST 16 bytes of the digest:

        char[i] = "abcdefghijklmnop"[ (digest[i // 2] >> (4 * (1 - i % 2))) & 0xF ]

    In other words: take the base64 "key" value from manifest.json, decode it
    to DER SubjectPublicKeyInfo bytes, SHA-256 them, take the first 16 bytes,
    and map every 4-bit nibble (high nibble first) to the alphabet "abcdefghijklmnop".

    This is the ONLY correct way to predict what chrome://extensions will show.
    Do NOT use base64url or hex encoding - that gives a wrong ID (the ID looks
    like e.g. "jiadcegfgdohggekdciecfialalkbnpo", 32 chars, letters a-p only).

Usage:
    python tools/ext_id.py                  # reads ./manifest.json
    python tools/ext_id.py <manifest.json>  # explicit path

Printing the ID lets install.bat (and humans) verify/pin allowed_origins.
"""

import base64
import hashlib
import json
import sys

ID_ALPHABET = "abcdefghijklmnop"


def extension_id_from_manifest_key(key_b64: str) -> str:
    """Derive the 32-char extension ID from the manifest 'key' (base64 DER SPKI)."""
    der_spki = base64.b64decode(key_b64)
    digest = hashlib.sha256(der_spki).digest()[:16]
    chars = []
    for byte in digest:
        chars.append(ID_ALPHABET[(byte >> 4) & 0xF])
        chars.append(ID_ALPHABET[byte & 0xF])
    return "".join(chars)


def load_key_from_manifest(path: str) -> str:
    with open(path, "r", encoding="utf-8-sig") as f:
        manifest = json.load(f)
    key = manifest.get("key")
    if not key:
        raise ValueError(
            f"No 'key' field found in {path}. Without it Chrome derives the ID "
            "from the folder path, so the ID would change on every machine."
        )
    return key


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "manifest.json"
    try:
        key = load_key_from_manifest(path)
        ext_id = extension_id_from_manifest_key(key)
    except Exception as exc:  # noqa: BLE001 - installer needs a single catch
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    if len(ext_id) != 32 or not all(c in ID_ALPHABET for c in ext_id):
        print("[ERROR] computed ID has unexpected shape - algorithm regression?", file=sys.stderr)
        return 1
    print(ext_id)
    return 0


if __name__ == "__main__":
    sys.exit(main())
