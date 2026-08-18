#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Build the Tarn release zip.

Single source of truth for the release artifact: used locally and by
.github/workflows/release.yml. Produces a Windows-Explorer-compatible zip
(python zipfile, deflate, directory entries, no "./" prefixes) — the format
that ships in dist/ and is tested locally.

Usage:
    python tools/build_release.py [version] [--out DIR]

Exclusions mirror the release policy: private keys, tests, git metadata,
build output.
"""
import hashlib
import os
import re
import struct
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Fixed timestamp for reproducible builds (ZIP stores DOS-time; 1980-01-01 is
# the earliest representable). Keeps the artifact byte-identical across
# machines so SHA256SUMS.txt can verify supply-chain integrity.
FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
EXCLUDE = {
    ".git",
    ".github",
    "tests",
    "dist",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}
EXCLUDE_FILES = {
    ".gitattributes",
    ".gitignore",
    "tools/extension_key.json",
    "tools/extension_key.pem",
    "tools/extension_private.pem",
}
EXCLUDE_SUFFIXES = (".crx", ".log", ".pyc", ".pyo", ".pem", ".key", ".conf")
# Pattern-based exclusion: any file matching these regexes is excluded.
# Catches worklog.md, worklog(1).md (browser auto-rename), and any audit files.
EXCLUDE_PATTERNS = [
    re.compile(r"^worklog.*\.md$", re.IGNORECASE),
    re.compile(r".*audit.*\.md$", re.IGNORECASE),  # catches audit.md, foo.audit.md, etc.
]
# Text extensions get CRLF -> LF normalization when packed. Git stores text
# blobs as LF, but a Windows checkout (core.autocrlf=true) produces CRLF
# working files; normalizing here keeps the artifact byte-identical with the
# GitHub Actions build (Linux, LF) regardless of the checkout platform.
TEXT_SUFFIXES = (
    ".css", ".default-template", ".html", ".js", ".json", ".lst",
    ".md", ".py", ".sh", ".txt", ".user", ".yml",
)
# Windows script extensions are packed with forced CRLF: cmd.exe can choke
# on LF-only .bat (label jumps, `set /p` prompts), and PowerShell reads CRLF
# without issues. Forcing CRLF makes the artifact identical no matter which
# platform built it.
CRLF_SUFFIXES = (".bat", ".cmd", ".ps1")


def _read_for_archive(path):
    """Read a file for the zip, normalizing CRLF to LF for text files.

    Binary files (0x00 present, or an extension not listed in TEXT_SUFFIXES)
    are packed byte-for-byte.
    """
    with open(path, "rb") as f:
        data = f.read()
    ext = os.path.splitext(path)[1].lower()
    if ext in CRLF_SUFFIXES:
        return data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    if ext in TEXT_SUFFIXES or (ext == "" and b"\x00" not in data):
        return data.replace(b"\r\n", b"\n")
    return data


def _pin_version_made_by(path):
    """Force the central-directory "version made by" field to (20, Unix).

    zipfile writes it differently across Python versions: 3.12.0-3.12.10
    emit the reserved byte (0, MS-DOS) while 3.12.11+/3.13+ emit the
    create_system value (3, Unix). Patching the two-byte field in every
    central-directory record keeps the artifact byte-identical regardless of
    the Python version that built it.
    """
    with open(path, "rb") as f:
        data = bytearray(f.read())
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        raise RuntimeError("zip EOCD record not found")
    cd_off = int.from_bytes(data[eocd + 16:eocd + 20], "little")
    off = cd_off
    while data[off:off + 4] == b"PK\x01\x02":
        data[off + 4:off + 6] = b"\x14\x03"  # version 20, system 3 (Unix)
        # Records are variable-length: fixed header + filename + extra +
        # comment (lengths live at fixed offsets in the header).
        fn_len, ex_len, cm_len = struct.unpack("<HHH", data[off + 28:off + 34])
        off += 46 + fn_len + ex_len + cm_len
    with open(path, "wb") as f:
        f.write(bytes(data))


def main():
    # Filter out flags to find the positional version argument
    args = sys.argv[1:]
    version = None
    out_dir = os.path.join(ROOT, "dist")
    i = 0
    while i < len(args):
        if args[i] == "--out" and i + 1 < len(args):
            out_dir = args[i + 1]
            i += 2
        elif args[i].startswith("--out="):
            out_dir = args[i].split("=", 1)[1]
            i += 1
        elif not args[i].startswith("--"):
            version = args[i]
            i += 1
        else:
            i += 1
    version = version.lstrip("v") if version else None
    if not version:
        import json
        with open(os.path.join(ROOT, "manifest.json"), encoding="utf-8") as f:
            version = json.load(f)["version"]
    out_path = os.path.join(out_dir, f"Tarn-v{version}.zip")

    entries = []
    for base, dirs, files in os.walk(ROOT):
        dirs.sort()  # deterministic walk order across OSes (readdir differs)
        rel = os.path.relpath(base, ROOT).replace("\\", "/")
        parts = [] if rel == "." else rel.split("/")
        if any(p in EXCLUDE or (p == "__pycache__") for p in parts):
            dirs[:] = []
            continue
        if rel != ".":
            entries.append((rel + "/", None))
        dirs[:] = [d for d in dirs if d not in EXCLUDE and d != "__pycache__"]
        for fn in sorted(files):
            arc = (rel + "/" + fn) if rel != "." else fn
            if fn.endswith(EXCLUDE_SUFFIXES):
                continue
            if arc in EXCLUDE_FILES or any(p in EXCLUDE for p in arc.split("/")[:-1]):
                continue
            # Pattern-based exclusion (catches worklog(1).md etc.)
            if any(pat.match(fn) for pat in EXCLUDE_PATTERNS):
                continue
            entries.append((arc, os.path.join(base, fn)))

    # Pre-publish assertion: no audit/worklog files in the artifact
    leaked = [arc for arc, _ in entries if any(pat.match(os.path.basename(arc)) for pat in EXCLUDE_PATTERNS)]
    assert not leaked, f"ABORT: audit files would be published: {leaked}"

    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as z:
        for arc, src in entries:
            if src is None:
                z.writestr(zipfile.ZipInfo(arc), b"")
            else:
                # Reproducible build: pin a fixed timestamp + DOS attributes so
                # the artifact is byte-identical across machines/checkouts and
                # SHA256SUMS.txt stays valid for supply-chain verification.
                zi = zipfile.ZipInfo(arc, date_time=FIXED_TIMESTAMP)
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.create_system = 3  # Unix
                zi.external_attr = (0o100644 << 16)  # regular file, rw-r--r--
                with open(src, "rb") as f:
                    z.writestr(zi, _read_for_archive(src))

    _pin_version_made_by(out_path)

    # Self-check: the zip must remain fully readable after the patch.
    with zipfile.ZipFile(out_path) as z:
        for info in z.infolist():
            z.read(info.filename)

    with open(out_path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    print(f"{out_path}")
    print(f"entries: {len(entries)}")
    print(f"sha256: {digest}")


if __name__ == "__main__":
    main()
