#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""
gen_key.py - Generate the deterministic Chrome extension "key" field (once per project).

Produces an RSA keypair, derives the Chrome extension ID from the PUBLIC key
(exactly matching Chromium: SHA-256 over the DER SubjectPublicKeyInfo bytes,
first 16 bytes, each 4-bit nibble mapped to "abcdefghijklmnop"), and writes
the private key to a SAFE location OUTSIDE the extension folder.

Usage:
    python tools/gen_key.py
    python tools/gen_key.py --bits 4096

WARNING:
  * Run this ONCE. Changing the "key" field afterwards changes the extension
    ID and breaks the native-messaging host for every existing user.
  * The PRIVATE key must NEVER be placed inside the folder that users load
    with "Load unpacked" - Chrome then shows a scary "This extension contains
    key files" warning. Keep it outside the repo or in an ignored folder.
    It is only needed if you later publish to the Chrome Web Store.
"""

import argparse
import base64
import hashlib
import json
import os
import sys

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
except ImportError:
    sys.exit("cryptography package required:\n  pip install cryptography")

# Canonical ID derivation - keep in sync with tools/ext_id.py
ID_ALPHABET = "abcdefghijklmnop"


def chrome_id_from_pub_spki(der_spki: bytes) -> str:
    """Chrome's GenerateId: SHA-256(public key DER SPKI)[:16], nibble-mapped a-p."""
    digest = hashlib.sha256(der_spki).digest()
    chars = []
    for byte in digest[:16]:
        chars.append(ID_ALPHABET[(byte >> 4) & 0xF])
        chars.append(ID_ALPHABET[byte & 0xF])
    return "".join(chars)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bits", type=int, default=2048)
    ap.add_argument(
        "--out",
        default=os.path.join(os.path.expanduser("~"), ".tarn-keys", "extension_key.json"),
        help="Where to store the PRIVATE key (default: ~/.tarn-keys/ - "
        "outside the extension folder so Chrome never sees it, and OUTSIDE "
        "~/.tarn-tunnel which the uninstaller deletes entirely)",
    )
    args = ap.parse_args()

    private = rsa.generate_private_key(
        public_exponent=65537, key_size=args.bits, backend=default_backend()
    )

    der_pub = private.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    key_field = base64.b64encode(der_pub).decode("ascii")

    pem_priv = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    ext_id = chrome_id_from_pub_spki(der_pub)
    if len(ext_id) != 32 or not all(c in ID_ALPHABET for c in ext_id):
        sys.exit(f"[ERROR] ID has unexpected shape: {ext_id}")

    print(f"Extension ID       : {ext_id}")
    print(f"ID length          : {len(ext_id)}  (must be 32)")
    print()
    print("--- paste this into manifest.json \"key\" field ---")
    print(f'  "key": "{key_field}",')
    print()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    if os.path.exists(args.out):
        ans = input(f"{args.out} exists! OVERWRITE? (yes/no): ").strip().lower()
        if ans != "yes":
            print("Aborted - kept existing key file.")
            return
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(
            {
                "extension_id": ext_id,
                "key_public_base64_spki": key_field,
                "private_key_pem": pem_priv,
                "notes": [
                    "Keep private_key_pem OFFLINE (printed once now, kept nowhere else).",
                    "Needed only if you publish to the Chrome Web Store.",
                    "The folder users load with 'Load unpacked' must NOT contain this",
                    "file (or any .pem) - Chrome then warns 'This extension contains key files'.",
                    "If you lose the private key, you can NEVER push updates to the",
                    "Web Store under the same listing; on-disk installs keep working.",
                ],
            },
            f,
            indent=2,
        )
    print(f"PRIVATE key stored at: {args.out}")
    print("DONE.")


if __name__ == "__main__":
    main()
