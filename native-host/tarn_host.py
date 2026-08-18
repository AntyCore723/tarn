#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""
WG Browser Tunnel — Native Messaging Host (v2)
=====================================================
Receives a WG config from the Chrome extension, launches **wireproxy**
(a userspace WG client that exposes a SOCKS5/HTTP proxy without needing
a TUN interface or root), and reports status/stats back to the browser.

Why wireproxy?
--------------
A pure Chrome extension CANNOT route packets through WG by itself.
`chrome.proxy` can only point at an existing SOCKS5/HTTP proxy.  wireproxy
(https://github.com/windtf/wireproxy) is a single Go binary that:
  • runs WG entirely in userspace (no TUN, no CAP_NET_ADMIN)
  • exposes a local SOCKS5 + HTTP proxy
  • actually encrypts traffic through the WG tunnel

So the real data path is:
  Chrome  →  chrome.proxy (SOCKS5)  →  wireproxy (127.0.0.1:1080)
         →  WG encryption  →  peer Endpoint  →  internet

Protocol (Chrome Native Messaging):
  stdin  →  uint32 LE length + JSON {cmd, config, socksAddr, ...}
  stdout ←  uint32 LE length + JSON {status, ...}

Commands : connect, disconnect, ping, stats
Statuses : ready, stopped, error, alive, stats, log

Install: see install.sh  (auto-downloads wireproxy)
"""

import json
import os
import re
import struct
import sys
import threading
import time
import socket
import subprocess
import shutil
import signal
import platform
import hashlib
import urllib.request
import tempfile
from pathlib import Path

HOST_NAME = "com.tarn.host"
DEFAULT_SOCKS = "127.0.0.1:1080"
APP_DIR = Path.home() / ".tarn-tunnel"
LOG_PATH = APP_DIR / "host.log"
WIREPROXY_DIR = APP_DIR / "bin"
WIREPROXY_BIN = WIREPROXY_DIR / ("wireproxy.exe" if os.name == "nt" else "wireproxy")
CONFIG_DIR = APP_DIR / "configs"

# wireproxy release info — pinned for reproducibility.
WIREPROXY_VERSION = "v1.1.3"
WIREPROXY_RELEASES = {
    # (os, machine) -> (filename_fragment, archive_suffix)
    ("linux", "x86_64"):  ("wireproxy_linux_amd64.tar.gz",   ".tar.gz"),
    ("linux", "aarch64"): ("wireproxy_linux_arm64.tar.gz",   ".tar.gz"),
    ("darwin", "x86_64"): ("wireproxy_darwin_amd64.tar.gz",  ".tar.gz"),
    ("darwin", "aarch64"):("wireproxy_darwin_arm64.tar.gz",  ".tar.gz"),
    ("windows", "AMD64"): ("wireproxy_windows_amd64.tar.gz", ".tar.gz"),
    ("windows", "x86_64"): ("wireproxy_windows_amd64.tar.gz", ".tar.gz"),
}
WIREPROXY_DOWNLOAD_URL = "https://github.com/windtf/wireproxy/releases/download/{version}/{file}"


def log(msg):
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        with _log_lock:
            with open(LOG_PATH, "a") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except Exception:
        pass


_log_lock = threading.Lock()


# ----------------- Native messaging IO -----------------
# Sentinel distinguishing "EOF (host should exit)" from "malformed message
# (host must NOT exit — a single bad message must not kill a live tunnel)".
_EOF = object()
_MALFORMED = object()


def read_message():
    header = sys.stdin.buffer.read(4)
    if len(header) < 4:
        return _EOF
    (length,) = struct.unpack("<I", header)
    # Hard cap on inbound message size (16 MB): the largest legitimate
    # payload is a WG config (~KBs). Anything bigger is hostile.
    if length == 0 or length > 16 * 1024 * 1024:
        return _MALFORMED
    body = sys.stdin.buffer.read(length)
    if len(body) < length:
        return _MALFORMED
    try:
        return json.loads(body.decode("utf-8"))
    except Exception as e:
        send_message({"status": "error", "message": f"bad json: {e}"})
        return _MALFORMED


_io_lock = threading.Lock()


def send_message(obj):
    try:
        data = json.dumps(obj).encode("utf-8")
        with _io_lock:
            sys.stdout.buffer.write(struct.pack("<I", len(data)))
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
    except Exception:
        # stdout closed — host is being torn down
        pass


# ----------------- Config parsing -----------------
# Whitelist of allowed keys — a config with any other key is rejected.
# This prevents injection of wireproxy-specific sections (Socks5, HttpServer,
# API, etc.) via a crafted config that could redirect the proxy or exfiltrate.
_ALLOWED_IFACE_KEYS = {
    "PrivateKey", "Address", "DNS", "MTU", "ListenPort",
    "FwMark", "Table", "PreUp", "PostUp", "PreDown", "PostDown", "SaveConfig",
}
_ALLOWED_PEER_KEYS = {"PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"}


def parse_wg_config(text):
    """Parse a standard WG .conf into interface + peers dict.
    Rejects configs with unknown keys (prevents wireproxy section injection)."""
    cfg = {"interface": {}, "peers": []}
    section = None
    peer = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip().lower()
            if name == "interface":
                section = "interface"; peer = None
            elif name == "peer":
                section = "peer"; peer = {}; cfg["peers"].append(peer)
            else:
                # Reject non-WG sections ([Socks5], [HttpServer], etc.)
                raise ValueError(f"unexpected section [{name}] — only [Interface] and [Peer] allowed")
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip(); v = v.strip()
        if section == "interface":
            if k not in _ALLOWED_IFACE_KEYS:
                raise ValueError(f"unknown Interface key '{k}' — possible config injection")
            cfg["interface"][k] = v
        elif section == "peer" and peer is not None:
            if k not in _ALLOWED_PEER_KEYS:
                raise ValueError(f"unknown Peer key '{k}' — possible config injection")
            peer[k] = v
    if not cfg["interface"].get("PrivateKey"):
        raise ValueError("missing [Interface] PrivateKey")
    if not cfg["peers"]:
        raise ValueError("missing [Peer] section")
    for i, p in enumerate(cfg["peers"]):
        if not p.get("PublicKey"):
            raise ValueError(f"peer {i+1}: missing PublicKey")
        if not p.get("Endpoint"):
            raise ValueError(f"peer {i+1}: missing Endpoint")
    return cfg


def to_wireproxy_config(cfg, socks_addr, http_addr=None):
    """Convert a parsed WG config into a wireproxy .conf.

    wireproxy accepts standard [Interface]/[Peer] sections and adds its own
    [Socks5] / [HttpServer] / [API] sections to expose local proxies.
    """
    out = ["[Interface]"]
    for k, v in cfg["interface"].items():
        # wireproxy understands: PrivateKey, Address, DNS, MTU
        out.append(f"{k} = {v}")
    for p in cfg["peers"]:
        out.append("")
        out.append("[Peer]")
        for k, v in p.items():
            out.append(f"{k} = {v}")

    out.append("")
    out.append("[Socks5]")
    out.append(f"BindAddress = {socks_addr}")

    if http_addr:
        out.append("")
        out.append("[HttpServer]")
        out.append(f"BindAddress = {http_addr}")

    return "\n".join(out) + "\n"


def parse_addr(addr):
    """Parse host:port or [ipv6]:port → (host, port).
    Raises ValueError on malformed input so values received from the
    extension can never reach a shell."""
    if not isinstance(addr, str) or not addr:
        raise ValueError("empty address")
    try:
        if addr.startswith("["):
            idx = addr.index("]")
            host = addr[1:idx]
            port = int(addr[idx + 2:])
        else:
            host, port = addr.rsplit(":", 1)
            port = int(port)
    except (ValueError, IndexError) as e:
        raise ValueError(f"invalid address: {addr!r}") from e
    if not host or not (1 <= port <= 65535):
        raise ValueError(f"invalid address: {addr!r}")
    if host in ("::1", "localhost"):
        host = "127.0.0.1"
    if host != "127.0.0.1":
        # The extension can only ever bind the local SOCKS/HTTP proxy to
        # loopback. Accepting a non-loopback host here would let a crafted
        # message make the host proxy for the whole LAN or write an
        # unreachable bind address — reject it outright.
        raise ValueError(f"non-loopback address: {addr!r}")
    return host, port


# ----------------- wireproxy binary management -----------------
# SHA-256 of the wireproxy binaries this build trusts, keyed by (os, machine).
# Auto-download is REFUSED for any build without a pinned hash - the bundled
# binary is verified too, so a tampered engine/bins/wireproxy.exe is caught.
# To add a platform: download the official release, run
#   certutil -hashfile wireproxy SHA256   (or: sha256sum wireproxy)
# and add the hash here.
WIREPROXY_SHA256 = {
    ("windows", "AMD64"): "b176b561fd8bf15d828fcab484cfd5b4fb941cb9f61807901ca64b955af27e1f",
    ("windows", "x86_64"): "b176b561fd8bf15d828fcab484cfd5b4fb941cb9f61807901ca64b955af27e1f",
    # Hashes below are of the extracted binary (not the .tar.gz archive),
    # computed from the official v1.1.3 release assets.
    ("linux", "x86_64"): "70ae5e52223dac7974af8d98a321f14a0e1689d2b14655ebc8dadfa1ec69466d",
    ("linux", "aarch64"): "5852e32671afb8918c39c59330b85f833c187ed41b6b1f683c90b6bfd320f3fa",
    ("darwin", "x86_64"): "1e76b051e47fa34d40904712484ae94b82d9a9ee01afe0a5ceb8f7eac555c7b4",
    ("darwin", "aarch64"): "37889c2f0ea4a9f2f59fc1bfefc372b24ffc4e56e2e34a0188aabe3a4e8c1ec3",
}


def detect_platform():
    os_name = platform.system().lower()  # linux / darwin / windows
    machine = platform.machine().lower()  # x86_64 / amd64 / aarch64 / arm64
    if machine in ("x86-64", "x86_64", "amd64"):
        machine = "x86_64" if os_name != "windows" else "AMD64"
    elif machine in ("aarch64", "arm64"):
        machine = "aarch64"
    return os_name, machine


def _verify_wireproxy(binary_path, os_name, machine):
    """Refuse to run a wireproxy binary that does not match the pinned
    SHA-256 for this platform. Returns True on match."""
    import hashlib
    expected = WIREPROXY_SHA256.get((os_name, machine))
    if expected is None:
        return False
    try:
        with open(binary_path, "rb") as f:
            actual = hashlib.sha256(f.read()).hexdigest()
    except OSError as e:
        log(f"wireproxy SHA-256 check failed: {e}")
        return False
    return actual.lower() == expected


def find_wireproxy():
    """Locate wireproxy: only the bundled dir, verified against the pinned
    hash. PATH is deliberately NOT searched: an unverified 'wireproxy' on
    PATH could be an arbitrary executable planted by an attacker."""
    if WIREPROXY_BIN.exists() and os.access(WIREPROXY_BIN, os.X_OK):
        os_name, machine = detect_platform()
        if not _verify_wireproxy(WIREPROXY_BIN, os_name, machine):
            log("bundled wireproxy.exe failed SHA-256 verification - "
                "refusing to use it")
            return None
        return str(WIREPROXY_BIN)
    return None


def download_wireproxy():
    """Download the wireproxy binary for the current platform into APP_DIR/bin.

    Returns the path to the binary on success, raises RuntimeError on failure.
    Falls back gracefully when offline — the caller will then report that
    wireproxy is missing and the extension stays in simulation mode.
    """
    os_name, machine = detect_platform()
    key = (os_name, machine)
    if key not in WIREPROXY_RELEASES:
        raise RuntimeError(f"No wireproxy build for {os_name}/{machine}. "
                           f"Download manually from https://github.com/windtf/wireproxy/releases "
                           f"and place at {WIREPROXY_BIN}")

    file_fragment, archive_suffix = WIREPROXY_RELEASES[key]
    url = WIREPROXY_DOWNLOAD_URL.format(version=WIREPROXY_VERSION, file=file_fragment)

    WIREPROXY_DIR.mkdir(parents=True, exist_ok=True)
    tmp_path = WIREPROXY_DIR / f"wireproxy_download{archive_suffix}"

    log(f"downloading wireproxy from {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "tarn-tunnel/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp, open(tmp_path, "wb") as out:
            shutil.copyfileobj(resp, out)
    except Exception as e:
        # Clean up partial download
        try: tmp_path.unlink()
        except: pass
        raise RuntimeError(f"download failed: {e}. Install wireproxy manually: "
                           f"https://github.com/windtf/wireproxy/releases")

    # Extract binary from archive
    if archive_suffix == ".tar.gz":
        import tarfile
        try:
            with tarfile.open(tmp_path, "r:gz") as tar:
                # Find wireproxy binary inside the archive
                binary_name = "wireproxy.exe" if os_name == "windows" else "wireproxy"
                for member in tar.getmembers():
                    if member.name.endswith(binary_name) and member.isreg():
                        # Extract to WIREPROXY_DIR
                        # filter='data' adds symlink/hardlink guard (CVE-2007-4559 defense-in-depth)
                        # Fall back to no filter for Python < 3.12
                        member.name = binary_name
                        try:
                            tar.extract(member, path=str(WIREPROXY_DIR), filter='data')
                        except TypeError:
                            tar.extract(member, path=str(WIREPROXY_DIR))
                        break
                else:
                    raise RuntimeError(f"wireproxy binary not found in archive")
        except Exception as e:
            try: tmp_path.unlink()
            except: pass
            raise RuntimeError(f"failed to extract wireproxy: {e}")
    else:
        # Direct binary (no archive)
        os.replace(str(tmp_path), str(WIREPROXY_BIN))

    try: tmp_path.unlink()
    except: pass

    # Verify the downloaded binary against the pinned SHA-256. Unknown
    # platform builds are refused - the binary could be anything.
    if not _verify_wireproxy(WIREPROXY_BIN, os_name, machine):
        try:
            WIREPROXY_BIN.unlink()
        except Exception:
            pass
        raise RuntimeError(
            f"wireproxy binary failed SHA-256 verification - refused to install. "
            f"Download it manually from "
            f"https://github.com/windtf/wireproxy/releases and place at {WIREPROXY_BIN}")

    try:
        os.chmod(WIREPROXY_BIN, 0o755)
    except Exception:
        pass

    # quick sanity check
    try:
        r = subprocess.run([str(WIREPROXY_BIN), "--version"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode not in (0, 2):  # wireproxy returns 2 on --version sometimes
            log(f"wireproxy --version rc={r.returncode} stderr={r.stderr[:200]}")
    except Exception as e:
        log(f"wireproxy sanity check failed: {e}")

    log(f"wireproxy installed at {WIREPROXY_BIN}")
    return str(WIREPROXY_BIN)


# ----------------- Tunnel backend -----------------
class WireproxyTunnel:
    """Manages a wireproxy subprocess that exposes a SOCKS5 proxy."""

    def __init__(self):
        self.proc = None
        self.config_file = None
        self.socks_addr = DEFAULT_SOCKS
        self.stop_evt = threading.Event()
        self.reader_thread = None
        self.tx = 0
        self.rx = 0
        self.last_hs = 0
        self.last_log = ""
        self.connected_at = 0
        self.binary = None
        self.monitor_thread = None
        # Health check state
        self._last_health_check = 0
        self._health_ok = False
        self._health_latency = 0
        self._health_ip = None
        self._health_consecutive_fails = 0
        self._last_tx_delta = 0
        self._last_rx_delta = 0
        self._stale_delta_count = 0
        self._last_netstat_at = 0

    def start(self, cfg, socks_addr):
        self.binary = find_wireproxy()
        if not self.binary:
            # try to auto-download once
            try:
                self.binary = download_wireproxy()
            except Exception as e:
                raise RuntimeError(f"wireproxy not installed: {e}")

        host, port = parse_addr(socks_addr or DEFAULT_SOCKS)
        self.socks_addr = f"{host}:{port}"

        # write wireproxy config
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        fd, self.config_file = tempfile.mkstemp(
            suffix=".conf", prefix="wireproxy_", dir=str(CONFIG_DIR))
        wp_config = to_wireproxy_config(cfg, self.socks_addr)
        with os.fdopen(fd, "w") as f:
            f.write(wp_config)
        os.chmod(self.config_file, 0o600)

        # pre-flight: make sure the SOCKS port is free
        result_port = self._ensure_port_free(host, port)
        if result_port and result_port != port:
            host = self.socks_addr.split(":")[0]
            port = result_port

        # launch wireproxy
        try:
            self.proc = subprocess.Popen(
                [self.binary, "-c", self.config_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                bufsize=1,
                universal_newlines=True,
            )
        except Exception as e:
            self._cleanup()
            raise RuntimeError(f"failed to start wireproxy: {e}")

        self.connected_at = time.time()
        self.stop_evt.clear()

        # reader thread — parses wireproxy output for handshake/log info
        self.reader_thread = threading.Thread(target=self._read_output, daemon=True)
        self.reader_thread.start()

        # monitor thread — checks process alive
        self.monitor_thread = threading.Thread(target=self._monitor, daemon=True)
        self.monitor_thread.start()

        # give wireproxy a moment to bind the SOCKS port
        if not self._wait_for_socks(host, port, timeout=8):
            self.stop()
            raise RuntimeError("wireproxy started but SOCKS port never opened "
                               "(check config / endpoint reachability)")

        # NOTE: no blocking health check here — sending "ready" immediately
        # (after the SOCKS port is up) is faster. The extension requests the
        # first "stats" right after "ready", and _update_health() runs the
        # initial check with fast timeouts during the first ~12s of uptime.
        # A broken tunnel therefore gets its 2-fail verdict within ~5-7s and
        # the extension's fail-fast aborts it ~8-10s after the click.

        backend = "wireproxy"
        return {"socksAddr": self.socks_addr, "backend": backend}

    def _ensure_port_free(self, host, port):
        # Try to bind — if it works, great
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            s.close()
            return port
        except OSError:
            pass

        log(f"port {port} is busy, attempting to free it")

        # Step 1: find and kill the process using this port
        self._kill_pid_on_port(host, port)

        # Step 2: kill ALL wireproxy processes
        self._kill_all_wireproxy()

        # Step 3: wait and retry
        for attempt in range(5):
            time.sleep(0.5)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, port))
                s.close()
                log(f"port {port} freed after attempt {attempt + 1}")
                return port
            except OSError:
                continue

        # Step 4: find a completely free port
        free_port = self._find_free_port(host, port)
        log(f"port {port} still busy, using fallback port {free_port}")
        self.socks_addr = f"{host}:{free_port}"
        return free_port

    def _is_our_process(self, pid):
        """True only for processes this host owns: the wireproxy backing THIS
        tunnel (~/.tarn-tunnel) and the Python interpreter running this very
        host process. Never kill a third-party process — the port holder may
        be a completely unrelated local service, a different wireproxy
        instance (other software/users) or an unrelated Python app."""
        try:
            if os.name == "nt":
                out = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                    capture_output=True, timeout=5,
                ).stdout.decode("cp866", errors="replace")
                for line in out.splitlines():
                    parts = [p.strip('"') for p in line.split('","')]
                    name = parts[0].lower() if parts else ""
                    if name.endswith("wireproxy.exe"):
                        # Only OUR tunnel's wireproxy. Third-party wireproxy
                        # instances (other software, other users, other
                        # config dirs) must never be killed.
                        cmd = subprocess.run(
                            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                             f"(Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\").CommandLine"],
                            capture_output=True, text=True, timeout=10,
                        )
                        return bool(cmd.stdout and "tarn-tunnel" in cmd.stdout)
                    if name in ("python.exe", "pythonw.exe", "python3.exe"):
                        # Only the interpreter running THIS host process.
                        return pid == os.getpid()
                return False
            else:
                out = subprocess.run(["ps", "-p", str(pid), "-o", "comm=", "-o", "args="],
                                     capture_output=True, text=True, timeout=5)
                text = (out.stdout or "").strip().lower()
                if text.startswith("wireproxy"):
                    return "tarn-tunnel" in text
                if any(n in text for n in ("python", "python3")):
                    return pid == os.getpid()
                return False
        except Exception as e:
            log(f"_is_our_process error: {e}")
            return False

    def _kill_pid_on_port(self, host, port):
        """Find the process holding a specific port and kill it ONLY if it is
        one of our own (wireproxy / tarn_host.py). Anything else is left alone
        — the caller then falls back to a different port."""
        try:
            if os.name == "nt":
                # Windows: use netstat to find PID
                result = subprocess.run(
                    ["netstat", "-ano", "-p", "TCP"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.splitlines():
                    # netstat -ano line: proto  local        foreign  state    PID
                    # Match the LOCAL port exactly (":1080" must never match
                    # ":10800" or ":21080").
                    parts = line.split()
                    if len(parts) < 5 or "LISTENING" not in line:
                        continue
                    local = parts[1]
                    try:
                        local_port = int(local.rsplit(":", 1)[1])
                    except (ValueError, IndexError):
                        continue
                    if local_port != port:
                        continue
                    pid = parts[-1].strip()
                    if pid.isdigit() and int(pid) > 0:
                        if not self._is_our_process(int(pid)):
                            log(f"pid {pid} on port {port} is not ours, skipping kill")
                            continue
                        log(f"killing PID {pid} on port {port}")
                        subprocess.run(["taskkill", "/F", "/PID", pid],
                                       capture_output=True, timeout=5)
            else:
                # Linux/macOS: use lsof
                result = subprocess.run(
                    ["lsof", "-i", f":{port}", "-t"],
                    capture_output=True, text=True, timeout=5
                )
                for pid in result.stdout.strip().split():
                    if pid.isdigit():
                        if not self._is_our_process(int(pid)):
                            log(f"pid {pid} on port {port} is not ours, skipping kill")
                            continue
                        log(f"killing PID {pid} on port {port}")
                        subprocess.run(["kill", "-9", pid],
                                       capture_output=True, timeout=5)
        except Exception as e:
            log(f"_kill_pid_on_port error: {e}")

    def _kill_all_wireproxy(self):
        """Kill wireproxy processes belonging to this tunnel.

        Only wireproxy processes whose command line points at this tunnel's
        config dir (~/.tarn-tunnel) are terminated — these are stale
        orphans from a crashed/previous host session. Third-party wireproxy
        instances (other software, other users) are never touched, consistent
        with _own_winws_pids / _kill_pid_on_port."""
        marker = "tarn-tunnel"
        pids = []
        try:
            if os.name == "nt":
                script = (
                    "Get-CimInstance Win32_Process -Filter \"Name='wireproxy.exe'\" | "
                    "Where-Object { $_.CommandLine -like '*tarn-tunnel*' } | "
                    "ForEach-Object { $_.ProcessId }"
                )
                out = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, timeout=10,
                )
                pids = [int(p) for p in (out.stdout or "").split() if p.strip().isdigit()]
            else:
                out = subprocess.run(
                    ["ps", "-axo", "pid=,args="],
                    capture_output=True, text=True, timeout=5,
                ).stdout
                for line in out.splitlines():
                    if "wireproxy" in line and marker in line:
                        pid = line.split(None, 1)[0]
                        if pid.isdigit() and int(pid) > 0:
                            pids.append(int(pid))
        except Exception as e:
            log(f"_kill_all_wireproxy scan error: {e}")
            return
        for pid in set(pids):
            try:
                log(f"killing stale wireproxy pid {pid}")
                if os.name == "nt":
                    subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                                   capture_output=True, timeout=5)
                else:
                    subprocess.run(["kill", "-9", str(pid)],
                                   capture_output=True, timeout=5)
            except Exception as e:
                log(f"_kill_all_wireproxy kill error: {e}")

    def _find_free_port(self, host, start_port, max_attempts=20):
        for i in range(max_attempts):
            port = start_port + i + 1
            if port > 65535:
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, port))
                s.close()
                return port
            except OSError:
                continue
        return start_port

    def _wait_for_socks(self, host, port, timeout=8):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.stop_evt.is_set():
                return False
            if self.proc and self.proc.poll() is not None:
                return False
            try:
                with socket.create_connection((host, port), timeout=0.5):
                    return True
            except Exception:
                time.sleep(0.3)
        return False

    def _read_output(self):
        """Read wireproxy stdout/stderr line by line for status + stats."""
        if not self.proc or not self.proc.stdout:
            return
        try:
            for line in self.proc.stdout:
                if self.stop_evt.is_set():
                    break
                line = line.rstrip()
                if not line:
                    continue
                self.last_log = line
                log(f"[wireproxy] {line}")
                # wireproxy prints lines like:
                #   "Listening socks5 on 127.0.0.1:1080"
                #   "Peer endpoint updated"
                #   "Handshake OK"
                low = line.lower()
                if "handshake" in low and "ok" in low:
                    self.last_hs = int(time.time() * 1000)
                # wireproxy doesn't natively print byte counters, so we
                # approximate via /proc or netstat when available (Linux).
        except Exception as e:
            log(f"reader error: {e}")

    def _monitor(self):
        """Watch the subprocess; if it dies, log the exit code."""
        if not self.proc:
            return
        rc = self.proc.wait()
        if not self.stop_evt.is_set():
            log(f"wireproxy exited unexpectedly rc={rc}")
            self.last_log = f"wireproxy exited (code {rc})"

    def _health_check(self, fast=False):
        """Active health check: make an actual HTTP request THROUGH the SOCKS5 proxy.

        This tests the ENTIRE chain: SOCKS5 → WG tunnel → internet → back.
        If any part is broken, the request fails and we know the tunnel is dead.

        fast=True: shortened timeouts for the initial startup check, so a
        broken tunnel is declared dead quickly and "ready" is not held up for
        the full normal timeout (TCP 3s + recv 5s).

        Returns (alive: bool, latency_ms: int, public_ip: str|None)
        """
        try:
            host, port = parse_addr(self.socks_addr)
            t0 = time.time()

            # Step 1: TCP connect to SOCKS5 proxy (local)
            tcp_to = 1.5 if fast else 3
            recv_to = 3 if fast else 5
            s = socket.create_connection((host, port), timeout=tcp_to)
            s.settimeout(recv_to)

            # Step 2: SOCKS5 handshake (RFC 1928)
            s.send(b'\x05\x01\x00')  # Version 5, 1 auth method, no auth
            resp = s.recv(2)
            if len(resp) < 2 or resp[0] != 5 or resp[1] != 0:
                # SOCKS5 auth rejected or wrong version = tunnel is dead
                s.close()
                return False, 0, None
            # resp[1] == 0 means "no auth required" — accepted

            # Step 3: SOCKS5 CONNECT to ifconfig.me:80 (through the tunnel)
            # Domain name: \x03 + length + bytes
            target = b'ifconfig.me'
            req = b'\x05\x01\x00\x03' + bytes([len(target)]) + target + b'\x00\x50'
            s.send(req)
            resp = s.recv(10)
            if len(resp) < 2 or resp[1] != 0:
                # SOCKS5 connect failed = tunnel is dead
                s.close()
                return False, 0, None

            # Measure latency at CONNECT response — this is the true tunnel RTT
            # (excludes HTTP processing time on the remote server)
            latency = int((time.time() - t0) * 1000)

            # Step 4: Send HTTP GET through the tunnel
            s.send(b'GET /ip HTTP/1.1\r\nHost: ifconfig.me\r\nConnection: close\r\n\r\n')

            # Step 5: Read response (with timeout)
            data = b''
            deadline = time.time() + 5
            while time.time() < deadline:
                try:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 4096:
                        break
                except socket.timeout:
                    break
            s.close()

            # Parse IP from HTTP response body
            if b'\r\n\r\n' in data:
                body = data.split(b'\r\n\r\n', 1)[-1].strip()
                ip_str = body.decode('utf-8', errors='ignore').split('\n')[0].strip()
                # Validate it looks like an IP
                if ip_str and '.' in ip_str and len(ip_str) < 50:
                    return True, latency, ip_str

            # Got response but no valid IP = something is wrong
            if data:
                return True, latency, None
            return False, 0, None

        except (socket.timeout, ConnectionRefusedError, OSError):
            return False, 0, None
        except Exception as e:
            log(f"health check error: {e}")
            return False, 0, None

    def _update_health(self):
        """Run health check if enough time has passed since last check.
        Cache is adaptive: while the tunnel is NOT yet verified (_health_ok
        still False — i.e. startup), re-check every 3s so a dead tunnel gets
        2 consecutive failures fast (~5-7s). Once verified, slow down to 5s —
        cheap on healthy tunnels. During the first ~12s of uptime the check
        itself uses shortened timeouts (fast=True) so a broken tunnel is
        declared dead quickly without delaying "ready"."""
        now = time.time()
        cache = 3 if not self._health_ok else 5
        if now - self._last_health_check < cache:
            return  # Use cached result

        self._last_health_check = now
        fast = (now - self.connected_at) < 12
        alive, latency, ip = self._health_check(fast=fast)

        if alive:
            self._health_ok = True
            self._health_latency = latency
            self._health_ip = ip
            self._health_consecutive_fails = 0
        else:
            self._health_consecutive_fails += 1
            # Only mark as dead after 2 consecutive failures (avoid false positives)
            if self._health_consecutive_fails >= 2:
                self._health_ok = False
                self._health_latency = 0

    def _estimate_stats(self):
        """Estimate traffic stats and tunnel health.

        Uses ACTIVE health check (HTTP request through SOCKS5 proxy) to determine
        if the tunnel actually works. Previous approach checked if SOCKS5 port was
        responsive — but wireproxy always listens locally regardless of tunnel state.

        Active health check tests the ENTIRE chain: SOCKS5 → WG → internet.
        """
        try:
            import subprocess as sp
            host, port = parse_addr(self.socks_addr)
            conns = 0
            tx = self.tx
            rx = self.rx

            # Run active health check (cached every ~15 seconds)
            self._update_health()

            # Use health check latency as the real ping
            latency = self._health_latency if self._health_ok else 0

            if os.name == "nt":
                # Windows: count established connections to SOCKS port.
                # NOTE: was Get-NetTCPConnection via powershell (1-3s spawn per
                # stats poll!) — that made the very first stats reply slow and
                # delayed the health verdict. netstat -an is a single fast
                # process (~100-300ms) and does the same job.
                try:
                    r = sp.run(["netstat", "-an"], capture_output=True, timeout=2)
                    lines = r.stdout.decode("cp866", errors="replace").splitlines()
                    for line in lines:
                        if "ESTABLISHED" in line.upper() and f":{port}" in line:
                            conns += 1
                except Exception:
                    pass

                # System-wide traffic deltas via netstat -e
                # NOTE: netstat -e on Windows outputs in console encoding (cp866 on Russian).
                # Output format (single line with both values):
                #   Р‘Р°Р№С‚        <received>   <sent>     (Russian)
                #   Bytes        <received>   <sent>     (English)
                # We parse raw bytes as cp866 and find the first line with 2 large numbers.
                # Only refresh every 10s — the deltas are cumulative counters,
                # sampling them once per 3s poll is unnecessary overhead.
                if time.time() - self._last_netstat_at >= 10:
                    try:
                        r = sp.run(["netstat", "-e"], capture_output=True, timeout=2)
                        lines = r.stdout.decode("cp866", errors="replace").splitlines()
                        for line in lines:
                            parts = line.split()
                            if len(parts) >= 3:
                                nums = []
                                for p in parts[1:]:
                                    p_clean = p.replace(",", "")
                                    if p_clean.isdigit():
                                        nums.append(int(p_clean))
                                if len(nums) == 2 and nums[0] > 100000 and nums[1] > 100000:
                                    total_rx = nums[0]
                                    total_tx = nums[1]
                                    if hasattr(self, '_last_netstat_rx'):
                                        self.rx += max(0, total_rx - self._last_netstat_rx)
                                    if hasattr(self, '_last_netstat_tx'):
                                        self.tx += max(0, total_tx - self._last_netstat_tx)
                                    self._last_netstat_rx = total_rx
                                    self._last_netstat_tx = total_tx
                                    break
                    except Exception:
                        pass
            else:
                # Linux: try ss for per-connection bytes, fallback to /proc/net/dev
                try:
                    r = sp.run(["ss", "-tiH", f"sport = :{port}"], capture_output=True, text=True, timeout=3)
                    for line in r.stdout.splitlines():
                        if "ESTAB" in line:
                            conns += 1
                        import re
                        m = re.search(r"bytes_sent:(\d+)", line)
                        if m:
                            self.tx += int(m.group(1))
                        m2 = re.search(r"bytes_received:(\d+)", line) or re.search(r"bytes_acked:(\d+)", line)
                        if m2:
                            self.rx += int(m2.group(1))
                except Exception:
                    try:
                        with open("/proc/net/dev") as f:
                            total_rx = 0
                            total_tx = 0
                            for line in f:
                                if ":" in line and not line.strip().startswith("Inter"):
                                    parts = line.split(":")[1].split()
                                    if len(parts) >= 10:
                                        total_rx += int(parts[0])
                                        total_tx += int(parts[8])
                            if hasattr(self, '_last_total_rx'):
                                self.tx += max(0, total_tx - self._last_total_tx)
                                self.rx += max(0, total_rx - self._last_total_rx)
                            self._last_total_tx = total_tx
                            self._last_total_rx = total_rx
                    except Exception:
                        pass

            alive = self.proc is not None and self.proc.poll() is None

            # === TUNNEL HEALTH: active health check is the source of truth ===
            # Previous bug: checked if SOCKS5 port responds (always true since
            # wireproxy listens locally). Now we check if HTTP request through
            # the proxy actually succeeds (tests full WG chain).
            tunnel_alive = alive and self._health_ok

            # Handshake staleness: WG re-handshakes every 2 min by default.
            # If no handshake logged for >3 min, tunnel is likely dead.
            handshake_stale = False
            if self.last_hs > 0:
                time_since_hs = (time.time() * 1000) - self.last_hs
                handshake_stale = time_since_hs > 180000  # 3 minutes
            elif alive and self.connected_at > 0:
                # No handshake ever logged but process is running for >3 min
                # This means handshake log parsing failed — rely on health check
                uptime = time.time() - self.connected_at
                if uptime > 180 and not self._health_ok:
                    handshake_stale = True

            # Traffic delta detection: if health check fails AND no traffic
            # change for 3+ consecutive polls, tunnel is definitely dead
            tx_delta = self.tx - tx if self.tx > tx else 0
            rx_delta = self.rx - rx if self.rx > rx else 0
            if tx_delta == 0 and rx_delta == 0:
                self._stale_delta_count += 1
            else:
                self._stale_delta_count = 0

            return {
                "txBytes": self.tx,
                "rxBytes": self.rx,
                "lastHandshake": self.last_hs,
                "latency": latency,
                "connections": conns,
                "alive": alive,
                "tunnelAlive": tunnel_alive and not handshake_stale,
                "handshakeStale": handshake_stale,
                "healthCheckOk": self._health_ok,
                # True only after 2+ REAL consecutive failed checks (not a
                # cached/transient first failure) — a definitive dead verdict
                # from the host side. Lets the extension abort a broken
                # tunnel fast without false positives on slow-starting ones.
                "healthChecked": self._health_consecutive_fails >= 2,
                "healthCheckIp": self._health_ip,
                "uptime": int(time.time() - self.connected_at) if self.connected_at else 0,
                "backend": "wireproxy",
                "lastLog": self.last_log[:200] if self.last_log else "",
            }
        except Exception:
            alive = self.proc is not None and self.proc.poll() is None
            return {
                "txBytes": self.tx, "rxBytes": self.rx,
                "lastHandshake": self.last_hs, "latency": 0,
                "connections": 0, "alive": alive,
                "tunnelAlive": False, "handshakeStale": True,
                "healthCheckOk": False, "healthCheckIp": None,
                "uptime": int(time.time() - self.connected_at) if self.connected_at else 0,
                "backend": "wireproxy", "lastLog": "",
            }

    def stats(self):
        est = self._estimate_stats()
        alive = self.proc is not None and self.proc.poll() is None
        est["alive"] = alive
        est["lastLog"] = self.last_log[:200] if self.last_log else ""
        return est

    def stop(self):
        self.stop_evt.set()
        if self.proc:
            try:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=3)
                except Exception:
                    try:
                        self.proc.kill()
                    except Exception:
                        pass
            except Exception:
                pass
            self.proc = None
        self._cleanup()

    def _cleanup(self):
        if self.config_file:
            try:
                os.unlink(self.config_file)
            except Exception:
                pass
            self.config_file = None


# ----------------- packet filter (bundled engine) -----------------
dpi_process = None
dpi_pid = None
dpi_strategy = None
_doh_enabled_by_us = False
# Per-interface previous DNS values captured when DoH was enabled
# ({subkey_name: {"ns": str|None, "prio": int|None}}), so disable restores
# exactly what was there before - including static user DNS.
_doh_saved = {}
# Previous EnableAutoDoh value, "missing" if the value did not exist.
_doh_prev_autodoh = None
# Which DoH server we configured (e.g. "1.1.1.1" or "94.140.14.14"), so a
# disable/restore removes exactly the registry value this code added even if
# the current invocation uses a different server (e.g. AdGuard was enabled).
_doh_used_dns = None
# DoH state is persisted to disk: if the host process dies while DPI is
# active (browser crash, SW restart), a fresh host instance must still be
# able to restore the user's original DNS settings on stop.
_DOH_STATE_FILE = APP_DIR / "doh_state.json"


def _save_doh_state():
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        _DOH_STATE_FILE.write_text(json.dumps({
            "saved": _doh_saved,
            "prev_autodoh": _doh_prev_autodoh,
            "used_dns": _doh_used_dns,
        }), encoding="utf-8")
    except Exception:
        pass


def _load_doh_state():
    global _doh_prev_autodoh, _doh_used_dns
    try:
        data = json.loads(_DOH_STATE_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            saved = data.get("saved")
            if isinstance(saved, dict):
                _doh_saved.update(saved)
            if "prev_autodoh" in data:
                _doh_prev_autodoh = data["prev_autodoh"]
            if "used_dns" in data:
                _doh_used_dns = data["used_dns"]
    except Exception:
        pass


def _clear_doh_state():
    try:
        _DOH_STATE_FILE.unlink(missing_ok=True)
    except Exception:
        pass


dpi_verified = False

ENGINE_DIR = APP_DIR / "engine"
ENGINE_BINS = ENGINE_DIR / "bins"
ENGINE_CONF = ENGINE_DIR / "conf"

HOSTS_FILE = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
HOSTS_BACKUP = HOSTS_FILE.with_suffix(".bak.wgbt")
HOSTS_MARKER = "# === WG Tunnel DPI entries ==="

# Full hosts content to add when DPI is enabled. GitHub content hosts are
# pinned to their CDN IPs as an optional workaround for regions where the
# GitHub CDN is degraded. This is OFF by default — the hosts file is not
# modified unless the user explicitly enables it (see HOSTS_GITHUB_IPS_ENABLED).
HOSTS_ENTRIES = """# === WG Tunnel DPI entries ===
185.199.109.133 objects.githubusercontent.com
185.199.109.133 raw.githubusercontent.com
185.199.109.133 release-assets.githubusercontent.com
185.199.108.133 private-user-images.githubusercontent.com
185.199.108.133 gist.githubusercontent.com
185.199.108.133 avatars.githubusercontent.com

"""

# Opt-in: set TARN_GITHUB_HOSTS=1 in the environment to enable GitHub CDN
# pinning via the hosts file. Off by default.
HOSTS_GITHUB_IPS_ENABLED = os.environ.get("TARN_GITHUB_HOSTS", "").strip().lower() in ("1", "yes", "true")


def _find_hosts_file():
    """Find the hosts file (cross-platform)."""
    if os.name == "nt":
        sys_root = os.environ.get("SystemRoot", r"C:\Windows")
        return Path(sys_root) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


def _hosts_bytes():
    """Read the hosts file as byte-preserving text (latin-1 = 1:1 bytes,
    never drops or re-encodes user data in other codepages)."""
    hosts = _find_hosts_file()
    if not hosts.exists():
        return None, ""
    return hosts, hosts.read_bytes().decode("latin-1")


def _atomic_write_hosts(path, text):
    """Write the hosts file atomically: temp file in the same directory +
    os.replace, so a crash mid-write can never corrupt the hosts file."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(text.encode("latin-1"))
    os.replace(str(tmp), str(path))


def _enable_hosts():
    """Backup original hosts file and add DPI entries."""
    if not HOSTS_GITHUB_IPS_ENABLED:
        return True  # hosts pinning is opt-in (HOSTS_GITHUB_IPS_ENABLED)
    try:
        hosts, content = _hosts_bytes()
        if not hosts:
            log(f"hosts file not found")
            return False
        if HOSTS_MARKER in content:
            log("hosts already has DPI entries, skipping")
            return True
        backup = hosts.with_suffix(".bak.wgbt")
        if not backup.exists():
            shutil.copy2(str(hosts), str(backup))
            log(f"hosts backup created at {backup}")
        _atomic_write_hosts(hosts, content.rstrip("\n") + "\n\n" + HOSTS_ENTRIES + "\n")
        log("hosts file updated with DPI entries")
        return True
    except Exception as e:
        log(f"hosts update failed: {e}")
        return False


def _strip_hosts_marker():
    """Remove only the DPI marker block from the hosts file, keeping any
    user edits made while the tunnel was active."""
    hosts, content = _hosts_bytes()
    if not hosts:
        return
    marker_start = content.find(HOSTS_MARKER)
    if marker_start < 0:
        return
    line_start = content.rfind("\n", 0, marker_start)
    if line_start < 0:
        line_start = 0
    else:
        line_start += 1
    after_marker = content.find("\n\n", marker_start)
    if after_marker < 0:
        after_marker = len(content)
    else:
        after_marker += 1
    new_content = content[:line_start].rstrip() + "\n" + content[after_marker:]
    _atomic_write_hosts(hosts, new_content)
    log("hosts entries removed")


def _disable_hosts():
    """Restore the hosts file without destroying user edits.

    The backup taken at enable time is only used when the current hosts file
    still contains exactly what this tunnel wrote. If it was modified since
    (by the user or another app), we remove just the DPI marker block
    surgically and keep their changes."""
    try:
        hosts, current = _hosts_bytes()
        if not hosts:
            return
        backup = hosts.with_suffix(".bak.wgbt")
        if backup.exists():
            # Only restore wholesale when the current file contains EXACTLY
            # what we appended at enable time (backup + marker block). If the
            # user or another app changed anything in between, strip just our
            # marker block surgically instead of clobbering their edits.
            backup_content = backup.read_bytes().decode("latin-1")
            written = backup_content.rstrip("\n") + "\n\n" + HOSTS_ENTRIES + "\n"
            if current == written:
                shutil.copy2(str(backup), str(hosts))
                backup.unlink()
                log("hosts file restored from backup")
            else:
                log("hosts modified since enable - removing only DPI entries")
                _strip_hosts_marker()
                backup.unlink()
            return
        _strip_hosts_marker()
    except Exception as e:
        log(f"hosts restore failed: {e}")


def _enable_game_filter():
    """Enable game filter (TCP+UDP all ports)."""
    try:
        flag_dir = ENGINE_DIR
        flag_dir.mkdir(parents=True, exist_ok=True)
        flag_file = flag_dir / "game_filter.enabled"
        flag_file.write_text("all", encoding="utf-8")
        log("game filter enabled (TCP+UDP all ports)")
        return True
    except Exception as e:
        log(f"game filter enable failed: {e}")
        return False


def _disable_game_filter():
    """Disable game filter."""
    try:
        flag_file = ENGINE_DIR / "game_filter.enabled"
        if flag_file.exists():
            flag_file.unlink()
            log("game filter disabled")
    except Exception:
        pass


def _find_winws_pid():
    """Find PID of a running winws.exe that belongs to THIS tunnel.

    Command-line-scoped own PIDs (matching ~/.tarn-tunnel/engine) are
    preferred so a winws.exe started by other software or another user is
    never mistaken for ours. Falls back to the raw tasklist scan only when
    no own instance is found (covers exotic cases where the command-line
    filter fails)."""
    try:
        own = _own_winws_pids()
        if own:
            return own[0]
        out = subprocess.check_output(
            ["tasklist", "/fi", "imagename eq winws.exe", "/fo", "csv", "/nh"],
            text=True, timeout=5
        )
        for line in out.strip().split("\n"):
            if "winws.exe" in line.lower():
                return int(line.split(",")[1].strip('"'))
    except Exception:
        pass
    return None


def _own_winws_pids():
    """PIDs of winws.exe processes whose command line points at this tunnel's
    engine dir. Instances of OTHER software (or other users) are never
    matched, so we can never kill something we did not start."""
    script = (
        "Get-CimInstance Win32_Process -Filter \"Name='winws.exe'\" | "
        "Where-Object { $_.CommandLine -like '*tarn-tunnel*engine*' } | "
        "ForEach-Object { $_.ProcessId }"
    )
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            text=True, timeout=10)
    except Exception:
        return []
    return [int(p) for p in out.split() if p.strip().isdigit()]


def _kill_own_winws():
    """Stop winws instances that belong to THIS tunnel: the DPI service first
    (sc stop), then any remaining own winws PIDs (matched by command line).
    Never touches winws instances started by other software or other users.
    Returns True if no own winws remains after the attempt."""
    if _service_installed():
        _service_stop()
        if not _own_winws_pids():
            return True

    for pid in _own_winws_pids():
        try:
            subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                           capture_output=True, timeout=10)
        except Exception:
            pass

    time.sleep(0.5)
    if _own_winws_pids():
        log("own winws.exe still alive, trying elevated kill via UAC")
        ps1 = None
        fd = None
        try:
            fd, ps1 = tempfile.mkstemp(prefix="_tarn_kill_", suffix=".ps1")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                fd = None
                f.write(
                    "Get-CimInstance Win32_Process -Filter \"Name='winws.exe'\" | "
                    "Where-Object { $_.CommandLine -like '*tarn-tunnel*engine*' } | "
                    "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }\n"
                )
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 f"Start-Process powershell -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','{ps1}' "
                 f"-Verb RunAs -WindowStyle Hidden -Wait"],
                capture_output=True, timeout=60
            )
        except Exception as e:
            log(f"elevated kill failed: {e}")
        finally:
            if ps1 is not None:
                try:
                    os.unlink(ps1)
                except Exception:
                    pass
        time.sleep(0.5)
    return not _own_winws_pids()


# ----------------- DPI strategies -----------------
# Ported 1:1 from the flowseal strategy family.
# The winners were verified on the target ISP with the bundled 21-config
# test suite (HTTP+TLS probes against the probe targets).
# Each strategy defines the desync "tail" for four TCP rule blocks:
#   media    – alt-port TCP (2053/2083/2087/2096/8443)
#   targeted   – targeted 443 list (tgt.lst, ip-id=zero); None => reuse media
#   general  – general web TCP (80/443)
#   game     – game-filter TCP (any protocol on ipset IPs)
# Canonical .bin fakes live in engine/bins/.

DPI_STRATEGY_ORDER = [
    "hostfakesplit",         # general (ALT9).bat — the ONLY strategy verified
    #                         # working on BOTH stable LAN and high-jitter WiFi
    #                         # links (no fake packets to be lost/reordered)
    "syndata_multidisorder", # general (ALT5).bat — also works on both; SYN carries data
    "fake_tls_auto_ts",      # general (FAKE TLS AUTO ALT3).bat — LAN champion (18.7ms)
    "fake_fakedsplit_ts",    # general (ALT).bat — solid on stable links
    "exp",                   # general (EXP).bat
    "simple_fake_ts",        # general (SIMPLE FAKE).bat
    "fake_multisplit",       # general (ALT11).bat
    "fake_tls_auto",         # general (FAKE TLS AUTO).bat
    "multisplit",            # general.bat (vanilla)
    "fake_badseq",           # no canonical equivalent, kept as last resort
    # Hybrids: ONE winws process, but the targeted 443 group (tgt.lst,
    # ip-id=zero) uses strategy A while the general group (dom.*) uses
    # strategy B. The WiFi runs proved no single strategy covers
    # both groups: hostfakesplit aced HTTP but died on critical TLS, while
    # the badseq family kept the critical TLS alive yet killed plain HTTP.
    # A hybrid merges the two winners so each group gets the desync it needs.
    "hybrid_tlsauto_hostfakesplit",    # targeted=fake_tls_auto_ts + general=hostfakesplit
    "hybrid_badseq_hostfakesplit",     # targeted=fake_tls_auto (badseq) + general=hostfakesplit
]

# targeted-group strategy -> general-group strategy for the hybrid profiles
HYBRID_TARGETED_GENERAL = {
    "hybrid_tlsauto_hostfakesplit": ("fake_tls_auto_ts", "hostfakesplit"),
    "hybrid_badseq_hostfakesplit": ("fake_tls_auto", "hostfakesplit"),
}

# Default probe targets: the connectivity-verification set used to decide
# whether a desync strategy actually works on the user's network. These are
# neutral public examples; the extension exposes them as a user-editable
# list (Settings -> DPI -> probe targets) because the "right" targets depend
# on what the user is testing. Includes video/CDN hosts because a strategy
# can pass neutral HTTP yet leave the actual media path dead.
DEFAULT_PROBE_HOSTS = ("www.cloudflare.com", "www.wikipedia.org", "example.com", "www.example.org")
PROBE_HOSTS = DEFAULT_PROBE_HOSTS

# Weighted scoring: the two public CDN targets form the "critical pair" a
# strategy must cover coherently (2+2 passes, a single working host does
# not); example.com is a lightweight third check (weight 1.0). The fourth
# probe target carries additional weight — a strategy that kills it breaks
# even when neutral HTTP passes.
# User-supplied targets that are not in the default set get weight 1.0.
PROBE_WEIGHTS = {
    "www.cloudflare.com": 2.0,
    "www.wikipedia.org": 2.0,
    "example.com": 1.0,
    "www.example.org": 2.0,
}

# Hosts whose real TLS must be alive for a strategy to count as "strong".
# Used for the "weak HTTPS" warnings.
PROBE_CRITICAL = ("www.cloudflare.com", "www.wikipedia.org", "www.example.org")

# Hosts that carry actual media payload. The neutral default set has none,
# so the test report marks no targets as media hosts.
PROBE_MEDIA = ("www.example.org",)

# Minimum weighted score for a strategy to be accepted, and the HTTPS floor
# for _auto_select_dpi: fewer working TLS hosts than this and the strategy
# is treated as HTTP-only (SNI-blocked) and skipped.
PROBE_MIN_OK = 2
PROBE_MIN_SCORE = 4.0

_PROBE_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def _sanitize_probe_targets(raw):
    """Whitelist-validate a probe-target override from the extension.

    Accepts only bare DNS hostnames (no scheme, port, path or IDN). Returns
    a de-duplicated list, empty when nothing valid was supplied."""
    if not isinstance(raw, list):
        return []
    out, seen = [], set()
    for item in raw:
        if not isinstance(item, str):
            continue
        host = item.strip().lower().rstrip(".")
        if len(host) > 253 or not _PROBE_HOSTNAME_RE.match(host):
            continue
        if host in seen:
            continue
        seen.add(host)
        out.append(host)
        if len(out) >= 16:
            break
    return out


def _set_probe_targets(targets):
    """Apply a user-supplied probe-target override (module-global swap).

    User-supplied targets are MERGED with the defaults (deduplicated), not a
    replacement — the defaults cover neutral HTTP/TLS; the user adds the
    specific hosts they actually care about (e.g. a video CDN). An empty
    user list falls back to the defaults."""
    global PROBE_HOSTS
    user = _sanitize_probe_targets(targets)
    merged = list(DEFAULT_PROBE_HOSTS)
    seen = set(merged)
    for h in user:
        if h not in seen:
            merged.append(h)
            seen.add(h)
    PROBE_HOSTS = tuple(merged) if merged else DEFAULT_PROBE_HOSTS


def _probe_score_floor():
    """Minimum weighted score for the ACTIVE probe set.

    The default thresholds (PROBE_MIN_SCORE / PROBE_MIN_OK) are calibrated
    for the default weighted set. Custom sets use uniform weight 1.0, so the
    floor scales down: require all but one host, capped at the default."""
    if PROBE_HOSTS == DEFAULT_PROBE_HOSTS:
        return PROBE_MIN_SCORE
    return min(PROBE_MIN_SCORE, max(1.0, float(len(PROBE_HOSTS) - 1)))


def _game_filter_ports():
    """Game-filter port ranges, mirroring service.bat load_game_filter.
    The flag file (engine/game_filter.enabled) holds 'all'/'tcp'/'udp'.
    Port 12 (unused) is the canonical no-op when the filter is off.
    Tunnel default port (51820) is excluded from UDP to prevent
    tunnel drops when DPI filter and tunnel are used simultaneously."""
    tcp = udp = "12"
    flag = ENGINE_DIR / "game_filter.enabled"
    try:
        mode = flag.read_text(encoding="utf-8").strip().lower() if flag.exists() else ""
    except Exception:
        mode = ""
    if mode == "all":
        tcp = "1024-65535"
        udp = "1024-51819,51821-65535"  # exclude tunnel default port
    elif mode == "tcp":
        tcp = "1024-65535"
    elif mode == "udp":
        udp = "1024-51819,51821-65535"  # exclude tunnel default port
    return tcp, udp


def _strategy_defs():
    BIN = str(ENGINE_BINS)

    def p(name):
        return f"{BIN}\\{name}"

    gch = p("fake_tls.bin")
    tls_large = p("tls_clienthello_large.bin")
    stun = p("stun.bin")
    stun2 = p("stun2.bin")
    quic = p("fake_quic.bin")
    quics = p("quic_initial_sample.bin")
    adu = p("voice_udp.bin")  # voice/STUN fake payload
    agu = p("game_udp.bin")   # game fake payload

    def voice(repeats=6, l7="discord,stun", discord=None, stun_bin=None, unknown=None):
        # "discord" / "stun" here are winws built-in L7 protocol identifiers
        # (traffic-signature classes), NOT service names. The winws engine
        # classifies packets by these protocol families for port-scoped
        # handling. This is analogous to filtering by "http" or "tls".
        return {
            "l7": l7,
            "discord": discord or [adu],
            "stun": stun_bin or [adu],
            "unknown": unknown or [],
            "repeats": repeats,
        }

    def game_udp(repeats, cutoff, bins=None):
        return {"repeats": repeats, "cutoff": cutoff, "bins": bins or [agu]}

    defs = {
        # general (ALT).bat
        "fake_fakedsplit_ts": {
            "media": ["--dpi-desync=fake,fakedsplit", "--dpi-desync-repeats=6",
                      "--dpi-desync-fooling=ts", "--dpi-desync-fakedsplit-pattern=0x00",
                      f"--dpi-desync-fake-tls={gch}"],
            "general": ["--dpi-desync=fake,fakedsplit", "--dpi-desync-repeats=6",
                        "--dpi-desync-fooling=ts", "--dpi-desync-fakedsplit-pattern=0x00",
                        f"--dpi-desync-fake-tls={stun}", f"--dpi-desync-fake-tls={gch}",
                        f"--dpi-desync-fake-http={tls_large}"],
            "game": ["--dpi-desync=fake,fakedsplit", "--dpi-desync-repeats=6",
                     "--dpi-desync-any-protocol=1", "--dpi-desync-cutoff=n4",
                     "--dpi-desync-fooling=ts", "--dpi-desync-fakedsplit-pattern=0x00",
                     f"--dpi-desync-fake-tls={stun}", f"--dpi-desync-fake-tls={gch}",
                     f"--dpi-desync-fake-http={tls_large}"],
            "quic_repeats": 6,
            "voice": voice(6),
            "game_udp": game_udp(12, "n3"),
        },
        # general (SIMPLE FAKE).bat
        "simple_fake_ts": {
            "media": ["--dpi-desync=fake", "--dpi-desync-repeats=6",
                      "--dpi-desync-fooling=ts", f"--dpi-desync-fake-tls={gch}"],
            "general": ["--dpi-desync=fake", "--dpi-desync-repeats=6",
                        "--dpi-desync-fooling=ts", f"--dpi-desync-fake-tls={stun}",
                        f"--dpi-desync-fake-tls={gch}", f"--dpi-desync-fake-http={tls_large}"],
            "game": ["--dpi-desync=fake", "--dpi-desync-repeats=6",
                     "--dpi-desync-any-protocol=1", "--dpi-desync-cutoff=n4",
                     "--dpi-desync-fooling=ts", f"--dpi-desync-fake-tls={stun}",
                     f"--dpi-desync-fake-tls={gch}", f"--dpi-desync-fake-http={tls_large}"],
            "quic_repeats": 6,
            "voice": voice(6),
            "game_udp": game_udp(12, "n3"),
        },
        # general (ALT11).bat
        "fake_multisplit": {
            "media": ["--dpi-desync=fake,multisplit", "--dpi-desync-split-seqovl=681",
                      "--dpi-desync-split-pos=1", "--dpi-desync-fooling=ts",
                      "--dpi-desync-repeats=8", f"--dpi-desync-split-seqovl-pattern={gch}",
                      f"--dpi-desync-fake-tls={gch}"],
            "general": ["--dpi-desync=fake,multisplit", "--dpi-desync-split-seqovl=664",
                        "--dpi-desync-split-pos=1", "--dpi-desync-fooling=ts",
                        "--dpi-desync-repeats=8", f"--dpi-desync-split-seqovl-pattern={tls_large}",
                        f"--dpi-desync-fake-tls={stun}", f"--dpi-desync-fake-tls={tls_large}",
                        f"--dpi-desync-fake-http={tls_large}"],
            "game": ["--dpi-desync=fake,multisplit", "--dpi-desync-split-seqovl=664",
                     "--dpi-desync-split-pos=1", "--dpi-desync-any-protocol=1",
                     "--dpi-desync-cutoff=n4", "--dpi-desync-fooling=ts",
                     "--dpi-desync-repeats=8", f"--dpi-desync-split-seqovl-pattern={tls_large}",
                     f"--dpi-desync-fake-tls={stun}", f"--dpi-desync-fake-tls={tls_large}",
                     f"--dpi-desync-fake-http={tls_large}"],
            "quic_repeats": 11,
            "voice": voice(6),
            "game_udp": game_udp(10, "n4"),
        },
        # general (ALT9).bat
        "hostfakesplit": {
            "media": ["--dpi-desync=hostfakesplit", "--dpi-desync-repeats=4",
                      "--dpi-desync-fooling=ts",
                      "--dpi-desync-hostfakesplit-mod=host=example.com"],
            "general": ["--dpi-desync=hostfakesplit", "--dpi-desync-repeats=4",
                        "--dpi-desync-fooling=ts,md5sig",
                        "--dpi-desync-hostfakesplit-mod=host=example.com"],
            "game": ["--dpi-desync=hostfakesplit", "--dpi-desync-repeats=4",
                     "--dpi-desync-any-protocol=1", "--dpi-desync-cutoff=n3",
                     "--dpi-desync-fooling=ts,md5sig",
                     "--dpi-desync-hostfakesplit-mod=host=example.com"],
            "quic_repeats": 6,
            "voice": voice(6),
            "game_udp": game_udp(12, "n2"),
        },
        # general (EXP).bat
        "exp": {
            "media": ["--dpi-desync=fake,multisplit", "--dpi-desync-split-seqovl=681",
                      "--dpi-desync-split-pos=1", "--dpi-desync-fooling=ts",
                      "--dpi-desync-repeats=8", f"--dpi-desync-split-seqovl-pattern={gch}",
                      f"--dpi-desync-fake-tls={gch}"],
            "targeted": ["--dpi-desync=hostfakesplit", "--dpi-desync-fooling=ts",
                       "--dpi-desync-hostfakesplit-mod=host=example.com"],
            "general": ["--dpi-desync=fake,multisplit", "--dpi-desync-split-seqovl=480",
                        "--dpi-desync-split-pos=1", "--dpi-desync-fooling=ts",
                        "--dpi-desync-repeats=4", f"--dpi-desync-split-seqovl-pattern={stun2}",
                        f"--dpi-desync-fake-tls={tls_large}", f"--dpi-desync-fake-http={tls_large}"],
            "game": ["--dpi-desync=fake,multisplit", "--dpi-desync-split-seqovl=664",
                     "--dpi-desync-split-pos=1", "--dpi-desync-any-protocol=1",
                     "--dpi-desync-cutoff=n4", "--dpi-desync-fooling=ts",
                     "--dpi-desync-repeats=8", f"--dpi-desync-split-seqovl-pattern={tls_large}",
                     f"--dpi-desync-fake-tls={stun2}", f"--dpi-desync-fake-tls={tls_large}",
                     f"--dpi-desync-fake-http={tls_large}"],
            "quic_repeats": 11,
            "quic_filter": "--filter-l7=quic",
            "voice": voice(4, l7="discord,stun,unknown",
                            discord=[quic, adu], unknown=[quic, adu]),
            "game_udp": game_udp(5, "n4", [quics, agu]),
        },
        # general (FAKE TLS AUTO ALT3).bat
        "fake_tls_auto_ts": {
            "media": ["--dpi-desync=fake,multisplit", "--dpi-desync-split-seqovl=681",
                      "--dpi-desync-split-pos=1", "--dpi-desync-fooling=ts",
                      "--dpi-desync-repeats=8", f"--dpi-desync-split-seqovl-pattern={gch}",
                      "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=example.com"],
            "general": ["--dpi-desync=fake,multisplit", "--dpi-desync-split-seqovl=681",
                        "--dpi-desync-split-pos=1", "--dpi-desync-fooling=ts",
                        "--dpi-desync-repeats=8", f"--dpi-desync-split-seqovl-pattern={gch}",
                        "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=example.com",
                        f"--dpi-desync-fake-http={tls_large}"],
            "game": ["--dpi-desync=fake,multisplit", "--dpi-desync-split-seqovl=681",
                     "--dpi-desync-split-pos=1", "--dpi-desync-any-protocol=1",
                     "--dpi-desync-cutoff=n4", "--dpi-desync-fooling=ts",
                     "--dpi-desync-repeats=8", f"--dpi-desync-split-seqovl-pattern={gch}",
                     "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=example.com",
                     f"--dpi-desync-fake-http={tls_large}"],
            "quic_repeats": 11,
            "voice": voice(6),
            "game_udp": game_udp(10, "n3"),
        },
        # general (FAKE TLS AUTO).bat
        "fake_tls_auto": {
            "media": ["--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=1,midsld",
                      "--dpi-desync-repeats=11", "--dpi-desync-fooling=badseq",
                      "--dpi-desync-fake-tls=0x00000000", "--dpi-desync-fake-tls=!",
                      "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=example.com"],
            "general": ["--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=1,midsld",
                        "--dpi-desync-repeats=11", "--dpi-desync-fooling=badseq",
                        "--dpi-desync-fake-tls=0x00000000", "--dpi-desync-fake-tls=!",
                        "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=example.com",
                        f"--dpi-desync-fake-http={tls_large}"],
            "game": ["--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=1,midsld",
                     "--dpi-desync-repeats=11", "--dpi-desync-any-protocol=1",
                     "--dpi-desync-cutoff=n4", "--dpi-desync-fooling=badseq",
                     "--dpi-desync-fake-tls=0x00000000", "--dpi-desync-fake-tls=!",
                     "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=example.com",
                     f"--dpi-desync-fake-http={tls_large}"],
            "quic_repeats": 11,
            "voice": voice(6),
            "game_udp": game_udp(10, "n2"),
        },
        # general.bat (vanilla)
        "multisplit": {
            "media": ["--dpi-desync=multisplit", "--dpi-desync-split-seqovl=681",
                      "--dpi-desync-split-pos=1", f"--dpi-desync-split-seqovl-pattern={gch}"],
            "general": ["--dpi-desync=multisplit", "--dpi-desync-split-seqovl=568",
                        "--dpi-desync-split-pos=1",
                        f"--dpi-desync-split-seqovl-pattern={p('tls_clienthello_sample.bin')}"],
            "game": ["--dpi-desync=multisplit", "--dpi-desync-split-seqovl=568",
                     "--dpi-desync-split-pos=1", "--dpi-desync-any-protocol=1",
                     "--dpi-desync-cutoff=n3",
                     f"--dpi-desync-split-seqovl-pattern={p('tls_clienthello_sample.bin')}"],
            "quic_repeats": 6,
            "voice": voice(6),
            "game_udp": game_udp(12, "n2"),
        },
        # general (ALT5).bat — NOT RECOMMENDED, exotic ISPs only
        "syndata_multidisorder": {
            "special": ["--filter-l3=ipv4", "--filter-tcp=80,443,2053,2083,2087,2096,8443",
                        f"--ipset-exclude={ENGINE_CONF}\\ipexc.lst", f"--ipset-exclude={ENGINE_CONF}\\ipexc.user",
                        "--dpi-desync=syndata,multidisorder"],
            "media": [],
            "general": ["--dpi-desync=syndata,multidisorder"],
            "game": ["--dpi-desync=syndata,multidisorder", "--dpi-desync-any-protocol=1",
                     "--dpi-desync-cutoff=n4"],
            "quic_repeats": 6,
            "voice": voice(6),
            "game_udp": game_udp(14, "n3"),
        },
        # no canonical equivalent — kept as last resort
        "fake_badseq": {
            "media": ["--dpi-desync=fake", "--dpi-desync-repeats=6", "--dpi-desync-fooling=badseq",
                      "--dpi-desync-badseq-increment=2", "--dpi-desync-fake-tls-mod=none",
                      f"--dpi-desync-fake-tls={p('fake_tls.bin')}"],
            "general": ["--dpi-desync=fake", "--dpi-desync-repeats=6", "--dpi-desync-fooling=badseq",
                        "--dpi-desync-badseq-increment=2", "--dpi-desync-fake-tls-mod=none",
                        f"--dpi-desync-fake-tls={p('fake_tls.bin')}",
                        f"--dpi-desync-fake-http={tls_large}"],
            "game": ["--dpi-desync=fake", "--dpi-desync-repeats=6", "--dpi-desync-fooling=badseq",
                     "--dpi-desync-badseq-increment=2", "--dpi-desync-any-protocol=1",
                     "--dpi-desync-cutoff=n4", "--dpi-desync-fake-tls-mod=none",
                     f"--dpi-desync-fake-tls={p('fake_tls.bin')}",
                     f"--dpi-desync-fake-http={tls_large}"],
            "quic_repeats": 6,
            "voice": voice(6),
            "game_udp": game_udp(12, "n3"),
        },
    }
    return defs


def _build_args(strategy_key="fake_fakedsplit_ts"):
    """Build winws.exe arguments for the given strategy (DPI port)."""
    LISTS = str(ENGINE_CONF)
    gf_tcp, gf_udp = _game_filter_ports()

    def p(name):
        return f"{ENGINE_BINS}\\{name}"

    defs = _strategy_defs()
    hybrid_parts = None
    d_targeted = {}
    if strategy_key in HYBRID_TARGETED_GENERAL:
        # Hybrid: ONE winws process, but the targeted 443 group gets its
        # own desync tail while the rest of the process
        # (general/media/game/quic/voice) uses the second key.
        gkey, ckey = HYBRID_TARGETED_GENERAL[strategy_key]
        d = defs[ckey]
        d_targeted = defs[gkey]
        hybrid_parts = (gkey, ckey)
    elif strategy_key not in defs:
        raise RuntimeError(f"unknown strategy: {strategy_key}")
    else:
        d = defs[strategy_key]

    # Strategy classification: the safe strategies run as an exclusion-based
    # (denylist) filter over all traffic; the aggressive ones run only
    # against user-listed domains (dom.user) so they never touch unlisted
    # hosts. dom.lst and exc.* are always exclusions; tgt.lst excludes the
    # targeted 443 group.
    aggressive = strategy_key not in ("multisplit", "syndata_multidisorder")
    if aggressive:
        dom_user = [f"--hostlist={LISTS}\\dom.user"]
    else:
        dom_user = [f"--hostlist-exclude={LISTS}\\dom.user"]

    media = d.get("media") or []
    targeted = d.get("targeted")
    if hybrid_parts is not None:
        # Explicitly drive the targeted block from the hybrid's targeted key
        # (its own "targeted" override or, lacking one, its media tail).
        targeted = d_targeted.get("targeted") or d_targeted.get("media") or []
    if targeted is None:
        targeted = media
    general = d.get("general") or []
    game = d.get("game") or (general + ["--dpi-desync-any-protocol=1", "--dpi-desync-cutoff=n4"])
    quic_repeats = d.get("quic_repeats", 6)
    quic_filter = d.get("quic_filter", "--filter-udp=443")
    voice_cfg = d.get("voice", {})
    voice_l7 = voice_cfg.get("l7", "discord,stun")
    voice_repeats = voice_cfg.get("repeats", 6)
    voice_discord = voice_cfg.get("discord") or [p("voice_udp.bin")]
    voice_stun = voice_cfg.get("stun") or [p("voice_udp.bin")]
    voice_unknown = voice_cfg.get("unknown") or []
    gu = d.get("game_udp", {})
    gu_repeats = gu.get("repeats", 12)
    gu_cutoff = gu.get("cutoff", "n3")
    gu_bins = gu.get("bins") or [p("game_udp.bin")]
    special = d.get("special")
    ipset_tcp_extra = d.get("ipset_tcp_extra") or []

    args = [
        f"--wf-tcp=80,443,2053,2083,2087,2096,8443,{gf_tcp}",
        f"--wf-udp=443,19294-19344,50000-50100,{gf_udp}",
    ]

    if special is not None:
        args += special + ["--new"]
    else:
        args += [
            # QUIC UDP (exclusion-based)
            quic_filter,
            f"--hostlist-exclude={LISTS}\\dom.lst",
            *dom_user,
            f"--hostlist-exclude={LISTS}\\exc.lst",
            f"--hostlist-exclude={LISTS}\\exc.user",
            f"--ipset-exclude={LISTS}\\ipexc.lst",
            f"--ipset-exclude={LISTS}\\ipexc.user",
            "--dpi-desync=fake",
            f"--dpi-desync-repeats={quic_repeats}",
            f"--dpi-desync-fake-quic={p('fake_quic.bin')}",
            "--new",
        ]

    # Voice UDP (port-scoped, protocol-detected)
    args += [
        "--filter-udp=19294-19344,50000-50100",
        f"--filter-l7={voice_l7}",
        "--dpi-desync=fake",
    ]
    for b in voice_discord:
        args.append(f"--dpi-desync-fake-discord={b}")
    for b in voice_stun:
        args.append(f"--dpi-desync-fake-stun={b}")
    for b in voice_unknown:
        args.append(f"--dpi-desync-fake-unknown-udp={b}")
    args += [f"--dpi-desync-repeats={voice_repeats}", "--new"]

    if special is None:
        # Media alt-ports TCP
        args += [
            "--filter-tcp=2053,2083,2087,2096,8443",
            f"--hostlist-exclude={LISTS}\\dom.lst",
            *dom_user,
            f"--hostlist-exclude={LISTS}\\exc.lst",
            f"--hostlist-exclude={LISTS}\\exc.user",
            f"--ipset-exclude={LISTS}\\ipexc.lst",
            f"--ipset-exclude={LISTS}\\ipexc.user",
            *media,
            "--new",
        ]
        # Targeted TCP 443 (tgt.lst exclusion)
        args += [
            "--filter-tcp=443",
            f"--hostlist-exclude={LISTS}\\tgt.lst",
            f"--hostlist-exclude={LISTS}\\dom.lst",
            *dom_user,
            f"--hostlist-exclude={LISTS}\\exc.lst",
            f"--hostlist-exclude={LISTS}\\exc.user",
            f"--ipset-exclude={LISTS}\\ipexc.lst",
            f"--ipset-exclude={LISTS}\\ipexc.user",
            "--ip-id=zero",
            *targeted,
            "--new",
        ]
        # General TCP (exclusion-based / allowlist for aggressive)
        args += [
            "--filter-tcp=80,443",
            f"--hostlist-exclude={LISTS}\\dom.lst",
            *dom_user,
            f"--hostlist-exclude={LISTS}\\exc.lst",
            f"--hostlist-exclude={LISTS}\\exc.user",
            f"--ipset-exclude={LISTS}\\ipexc.lst",
            f"--ipset-exclude={LISTS}\\ipexc.user",
            *general,
            "--new",
        ]

    # IPSet QUIC
    args += [
        "--filter-udp=443",
        f"--ipset={LISTS}\\ip.lst",
        f"--hostlist-exclude={LISTS}\\exc.lst",
        f"--hostlist-exclude={LISTS}\\exc.user",
        f"--ipset-exclude={LISTS}\\ipexc.lst",
        f"--ipset-exclude={LISTS}\\ipexc.user",
        "--dpi-desync=fake",
        "--dpi-desync-repeats=6",
        f"--dpi-desync-fake-quic={p('fake_quic.bin')}",
        "--new",
    ]

    # IPSet TCP
    args += [
        "--filter-tcp=80,443,8443",
        f"--ipset={LISTS}\\ip.lst",
        f"--hostlist-exclude={LISTS}\\exc.lst",
        f"--hostlist-exclude={LISTS}\\exc.user",
        f"--ipset-exclude={LISTS}\\ipexc.lst",
        f"--ipset-exclude={LISTS}\\ipexc.user",
        *ipset_tcp_extra,
        *general,
        "--new",
    ]

    # Game Filter TCP
    args += [
        f"--filter-tcp={gf_tcp}",
        f"--ipset={LISTS}\\ip.lst",
        f"--ipset-exclude={LISTS}\\ipexc.lst",
        f"--ipset-exclude={LISTS}\\ipexc.user",
        *game,
        "--new",
    ]

    # Game Filter UDP
    args += [
        f"--filter-udp={gf_udp}",
        f"--ipset={LISTS}\\ip.lst",
        f"--ipset-exclude={LISTS}\\ipexc.lst",
        f"--ipset-exclude={LISTS}\\ipexc.user",
        "--dpi-desync=fake",
        f"--dpi-desync-repeats={gu_repeats}",
        "--dpi-desync-any-protocol=1",
    ]
    for b in gu_bins:
        args.append(f"--dpi-desync-fake-unknown-udp={b}")
    args.append(f"--dpi-desync-cutoff={gu_cutoff}")

    return args


# ---------------- strategy probe & auto-select ----------------

DPI_CACHE_BLACKLIST = set()
# Universal fallback: verified working on BOTH stable LAN (18.8ms avg) and
# high-jitter WiFi (48ms avg, 5/5 passes) in real-world tests. Older
# fake-timestamp strategies (e.g. fake_tls_auto_ts) fail 0/5 over WiFi,
# so they must never be the last-resort choice.
DPI_FALLBACK_STRATEGY = "hostfakesplit"


def _strategy_cache_file():
    return Path(os.path.expanduser("~")) / ".tarn-tunnel" / "dpi_strategy.txt"


def _network_fingerprint():
    """Cheap-but-honest identity of the current network: default gateway IP
    plus the WiFi SSID when present. The strategy cache is only valid on the
    network it was verified on - a strategy tuned on stable LAN can be dead
    on a WiFi hotspot (the ts-family dies behind NAT routers that mangle TCP
    options, and jitter kills fake-based strategies). Reusing it would
    silently pick a broken strategy. Returns a short hex hash or None."""
    import hashlib
    parts = []
    try:
        out = subprocess.run(["route", "print", "-4"], capture_output=True,
                             text=True, errors="replace", timeout=5).stdout
        m = re.search(r"\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+(\S+)", out)
        if m:
            parts.append(f"gw={m.group(1)}")
    except Exception:
        pass
    try:
        out = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                             capture_output=True, text=True, errors="replace",
                             timeout=5).stdout
        m = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.M)
        if m and m.group(1).strip():
            parts.append(f"ssid={m.group(1).strip()}")
    except Exception:
        pass
    if not parts:
        return None
    return hashlib.sha1("|".join(parts).encode("utf-8", "replace")).hexdigest()[:12]


def _read_strategy_cache():
    """Returns (strategy|None, from_other_net: bool). A cache written on a
    different network is reported (for diagnostics) but never trusted."""
    net = _network_fingerprint()
    try:
        lines = _strategy_cache_file().read_text(encoding="utf-8").splitlines()
        v = lines[0].strip()
        if v in DPI_STRATEGY_ORDER and v not in DPI_CACHE_BLACKLIST:
            for line in lines[1:]:
                m = re.match(r"#\s*net=(\w+)", line.strip())
                if m:
                    if net is not None and m.group(1) != net:
                        log(f"strategy cache from a DIFFERENT network "
                            f"({m.group(1)} != {net}), ignoring")
                        return None, True
                    break
            return v, False
    except Exception:
        pass
    return None, False


def _strategy_cache_meta():
    """(key, stats_line|None, net_fp|None). The key is the first line of the
    cache file; stats (appended by _write_strategy_cache) live on the second
    line and are informational only - old single-line cache files stay
    compatible."""
    try:
        lines = _strategy_cache_file().read_text(encoding="utf-8").strip().splitlines()
        if not lines or lines[0].strip() not in DPI_STRATEGY_ORDER:
            return None, None, None
        stats = net = None
        for line in lines[1:]:
            line = line.strip()
            if line.startswith("# net="):
                net = line[len("# net="):].strip()
            elif stats is None and line.startswith("# "):
                stats = line[2:].strip()
        return lines[0].strip(), stats, net
    except Exception:
        return None, None, None


def _write_strategy_cache(key, tls13_ok=None, tls13_total=None,
                          tls12_ok=None, tls12_total=None):
    try:
        f = _strategy_cache_file()
        f.parent.mkdir(parents=True, exist_ok=True)
        lines = [key]
        if tls13_ok is not None and tls13_total:
            parts = [f"tls13={tls13_ok}/{tls13_total}"]
            if tls12_ok is not None and tls12_total:
                parts.append(f"tls12={tls12_ok}/{tls12_total}")
            lines.append("# " + " ".join(parts))
        net = _network_fingerprint()
        if net:
            lines.append(f"# net={net}")
        f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception as e:
        log(f"strategy cache write failed: {e}")


def _strategy_cache_display():
    """Human-readable cache summary for the diagnostics report, e.g.
    'simple_fake_ts (tls13=9/15 tls12=9/15)' - HTTPS stats help spot a
    strategy that passes HTTP but is dead for real TLS content."""
    key, meta, net = _strategy_cache_meta()
    if not key:
        return None
    s = key
    if meta:
        s += f" ({meta})"
    fp = _network_fingerprint()
    if net and fp and net != fp:
        s += " (кэш с другой сети — игнорируется)"
    return s


def _probe_bypass(timeout=4.0, min_ok=3, detailed=False, rounds=2):
    """Honest HTTP(S) reachability probe, in parallel. Run while winws is
    active to verify the current strategy really bypasses the ISP.
    Mirrors the flowseal test methodology (HTTP GET, not a bare TLS
    handshake): any HTTP status code from the remote side proves the
    connection went through; only connection-level failures count as
    blocked. Passes when the weighted probe score meets the floor for the
    active probe set (see PROBE_MIN_SCORE / _probe_score_floor).

    Always returns (passed: bool, results: {host: {...}}). `detailed` is
    kept for API compatibility with older callers.

    Two safety details:
      * the system proxy is explicitly ignored - a leftover SOCKS proxy
        from tunnel mode would silently route the probe and produce false
        "not verified" results;
      * hosts that fail HTTPS are retried over plain HTTP (port 80 is
        covered by the winws filter rules too).

    Scheme-aware: each result records which transport worked
    ({"https": bool, "http": bool}). HTTPS is attempted first, so
    "https": True means a real TLS handshake went through the desync, not
    just a TCP connection. This matters on SNI-blocking networks where
    plain HTTP (port 80) passes while HTTPS to the same host is killed:
    HTTP-only coverage looks "OK" but the actual content (video, chat) is
    HTTPS and would stay dead.

    Multi-IP: the probe resolves the full A/AAAA set per host and tries
    several addresses, exactly like the browser does. DPI (ТСПУ) throttles
    by IP subnet, and large CDNs rotate dozens of addresses - a probe
    that tries a single random IP both over- and under-reports. This was
    the exact cause of the WiFi runs lying: the probe hit a throttled
    subnet while the browser's next connect landed on a working one.

    rounds: on high-jitter links (WiFi, cellular) a single probe round can
    false-negative even when the bypass works (200-600ms spikes, lost SYN
    retransmits). The whole battery is retried `rounds` times and ANY round
    that meets the score passes. This keeps auto-select honest on slow
    links without weakening the threshold for stable ones.

    With detailed=True returns (passed, {host: {...}}) so callers can score
    strategies by coverage and latency. The boolean call form is kept for
    older callers.
    """
    import urllib.request
    import threading

    def probe(host):
        last_err = None
        t0 = time.time()
        for scheme in ("https", "http"):
            try:
                req = urllib.request.Request(
                    f"{scheme}://{host}/", method="GET",
                    headers={"User-Agent": "Mozilla/5.0",
                             "Accept": "*/*"})
                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({}))
                with opener.open(req, timeout=timeout) as r:
                    r.read(1024)
                return {"ok": True, "ms": round((time.time() - t0) * 1000, 1),
                        "https": scheme == "https", "http": scheme == "http"}
            except Exception as e:
                last_err = e
                if getattr(e, "code", None) is not None:
                    return {"ok": True, "ms": round((time.time() - t0) * 1000, 1),
                            "https": scheme == "https", "http": scheme == "http"}
        return {"ok": False, "ms": None, "err": str(last_err),
                "https": False, "http": False}

    def weighted_ok(ok_hosts):
        score = sum(PROBE_WEIGHTS.get(h, 1.0) for h in ok_hosts)
        floor = _probe_score_floor()
        return len(ok_hosts) >= min_ok and score >= floor, score

    results = {}
    for round_no in range(1, rounds + 1):
        results = {}

        def run_round():
            threads = [threading.Thread(target=lambda h=h: results.__setitem__(h, probe(h)),
                                        daemon=True) for h in PROBE_HOSTS]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        run_round()
        ok_hosts = [h for h, v in results.items() if v["ok"]]
        passed, score = weighted_ok(ok_hosts)
        log(f"dpi probe round {round_no}/{rounds}: {len(ok_hosts)}/{len(results)} OK "
            f"(score {score:.1f}/{_probe_score_floor():.1f}) ({', '.join(ok_hosts) or 'none'})")
        if passed or rounds == 1:
            return passed, results
        # A full battery failed once on a jittery link - give it a second
        # chance before condemning the strategy.
        time.sleep(1.0)
    return False, results


def _host_addresses(host, port, limit=3):
    """Up to `limit` distinct IPs for a host, IPv4 first. The browser tries
    several addresses per domain (DNS rotation); the probe must too, or a
    single throttled CDN subnet makes the whole host look dead."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        seen, addrs = set(), []
        for info in infos:
            ip = info[4][0]
            if ip not in seen:
                seen.add(ip)
                addrs.append(ip)
            if len(addrs) >= limit:
                break
        return addrs or [host]
    except Exception:
        return [host]


def _probe_host_detail(host, timeout=4.0):
    """Detailed probe for one host: HTTP, TLS1.2, TLS1.3,
    ICMP ping (TCP-RTT fallback), and a data-plane check. Any HTTP response
    counts as reachable (redirects/errors still prove the connection went
    through), exactly like the reference test suite. Returns:
    {"host", "http": bool, "tls12": bool, "tls13": bool,
     "data": bool, "pingMs": float|None, "err": str|None}

    data=True means at least one channel (HTTP or TLS 1.3) actually
    delivered >1KB of payload - the handshake went through AND the DPI
    lets real content flow. This is the closest cheap proxy for "a video
    would actually play": pure reachability can be true while the data
    plane is throttled or reset after the first segment.

    TLS tries up to 3 resolved addresses per version (browser-like),
    so a throttled CDN subnet does not condemn the whole host."""
    import ssl as _ssl
    res = {"host": host, "http": False, "tls12": False, "tls13": False,
           "data": False, "dataBytes": 0, "pingMs": None, "err": None}

    def recv_body(sock, target=4096, budget=0.8):
        """Read up to `target` bytes of body with a time budget, so the
        probe measures real throughput without stalling the battery."""
        sock.settimeout(budget)
        got = 0
        deadline = time.time() + budget
        try:
            while got < target and time.time() < deadline:
                chunk = sock.recv(target - got)
                if not chunk:
                    break
                got += len(chunk)
        except Exception:
            pass
        return got

    http_addrs = _host_addresses(host, 80)
    # Browser-like retry for DPI-flaky attempts: ISPs with multiple or
    # load-balanced DPIs (see zapret blockcheck) kill only SOME first
    # connection attempts - e.g. attempts 1,2,7,9 of 10 fail while the rest
    # pass - so a single attempt produces false negatives. The retry round
    # runs only when the first round failed FAST (RST or quick rejection,
    # the DPI signature); a slow full-timeout failure means the channel is
    # genuinely dead and retrying would just burn battery time.
    fast_fail = False
    t_round = time.time()
    for ip in http_addrs:
        try:
            with socket.create_connection((ip, 80), timeout=timeout) as s:
                s.settimeout(timeout)
                s.sendall(b"GET / HTTP/1.0\r\nHost: " + host.encode("ascii", "ignore") +
                          b"\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n")
                data = s.recv(512)
                if data.startswith(b"HTTP/"):
                    res["http"] = True
                    body = recv_body(s)
                    res["dataBytes"] += body
                    if body >= 1024:
                        res["data"] = True
                    break
                # Connected but got garbage or an empty close: with fake-packet
                # strategies the SERVER can receive the fakes and reply with
                # corrupted data (zapret blockcheck documents exactly this:
                # "likely the server receives fakes"). That is a DPI/flaky
                # signature, not proof the channel is dead - Chrome retries and
                # succeeds, so we must too (fast_fail triggers the retry round).
                fast_fail = True
        except ConnectionResetError:
            fast_fail = True
            continue
        except Exception:
            if time.time() - t_round < 1.5:
                fast_fail = True
            continue
    if not res["http"] and fast_fail:
        tmo = min(timeout, 2.0)
        for ip in http_addrs:
            try:
                with socket.create_connection((ip, 80), timeout=tmo) as s:
                    s.settimeout(tmo)
                    s.sendall(b"GET / HTTP/1.0\r\nHost: " + host.encode("ascii", "ignore") +
                              b"\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n")
                    data = s.recv(512)
                    if data.startswith(b"HTTP/"):
                        res["http"] = True
                        body = recv_body(s)
                        res["dataBytes"] += body
                        if body >= 1024:
                            res["data"] = True
                        break
            except Exception:
                continue

    for name, minv, maxv in (("tls12", 2, 2), ("tls13", 3, 3)):
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        tlsv = getattr(_ssl, "TLSVersion", None)
        if tlsv is not None:
            ctx.minimum_version = getattr(tlsv, "TLSv1_%d" % minv)
            ctx.maximum_version = getattr(tlsv, "TLSv1_%d" % maxv)
        tls_addrs = _host_addresses(host, 443)
        # Same adaptive retry as the HTTP loop above.
        fast_fail = False
        t_round = time.time()
        for ip in tls_addrs:
            try:
                with socket.create_connection((ip, 443), timeout=timeout) as raw:
                    raw.settimeout(timeout)
                    with ctx.wrap_socket(raw, server_hostname=host) as ss:
                        ss.sendall(b"GET / HTTP/1.0\r\nHost: " + host.encode("ascii", "ignore") +
                                   b"\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
                        if ss.recv(64):
                            res[name] = True
                            if name == "tls13":
                                body = recv_body(ss)
                                res["dataBytes"] += body
                                if body >= 1024:
                                    res["data"] = True
                            break
                        # Handshake OK but the server sent nothing back: with
                        # fake-packet strategies the server side can be
                        # confused by the fakes (zapret: "server receives
                        # fakes"). Chrome retries on fresh connections and
                        # succeeds - so do we (fast_fail -> retry round).
                        fast_fail = True
            except ConnectionResetError:
                fast_fail = True
                continue
            except Exception:
                if time.time() - t_round < 1.5:
                    fast_fail = True
                continue
        if not res[name] and fast_fail:
            tmo = min(timeout, 2.0)
            for ip in tls_addrs:
                try:
                    with socket.create_connection((ip, 443), timeout=tmo) as raw:
                        raw.settimeout(tmo)
                        with ctx.wrap_socket(raw, server_hostname=host) as ss:
                            ss.sendall(b"GET / HTTP/1.0\r\nHost: " + host.encode("ascii", "ignore") +
                                       b"\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
                            if ss.recv(64):
                                res[name] = True
                                if name == "tls13":
                                    body = recv_body(ss)
                                    res["dataBytes"] += body
                                    if body >= 1024:
                                        res["data"] = True
                                break
                except Exception:
                    continue

    try:
        out = subprocess.run(["ping", "-n", "1", "-w", "3000", host],
                             capture_output=True, text=True, timeout=timeout + 1,
                             errors="replace")
        m = re.search(r"[=<\s](\d+(?:\.\d+)?)\s*(?:ms|мс)", out.stdout, re.I)
        if m:
            res["pingMs"] = round(float(m.group(1)), 1)
    except Exception:
        pass
    if res["pingMs"] is None:
        try:
            t0 = time.time()
            with socket.create_connection((host, 443), timeout=timeout):
                pass
            res["pingMs"] = round((time.time() - t0) * 1000, 1)
        except Exception:
            pass

    if not (res["http"] or res["tls12"] or res["tls13"]):
        res["err"] = "unreachable"
    return res


def _probe_hosts_detailed(timeout=4.0, cancel_check=None):
    """Run _probe_host_detail for every PROBE_HOSTS entry.

    Hosts are probed sequentially (not in parallel) so that cancel_check can
    be honored between hosts — the test's Stop button aborts within one host
    probe (~3-7s) instead of waiting for all hosts to finish. cancel_check:
    optional callable returning True to abort early; remaining hosts are
    marked unreachable."""
    out = []
    for host in PROBE_HOSTS:
        if cancel_check and cancel_check():
            out.append({"host": host, "http": False, "tls12": False, "tls13": False,
                        "data": False, "dataBytes": 0, "pingMs": None, "err": "cancelled"})
            continue
        out.append(_probe_host_detail(host, timeout))
    ok = [d for d in out if d and d["http"]]
    log(f"dpi detailed probe: {len(ok)}/{len(out)} HTTP OK")
    return out


def _probe_quic(timeout=4.0):
    """Probe the QUIC path (UDP 443) with the bundled real Chrome QUIC
    Initial packet. ANY UDP reply from the server proves UDP 443 is not
    dropped/throttled for that destination - important because Chrome
    prefers QUIC for video/chat and a strategy can look dead over TCP
    while QUIC (masked or untouched) actually carries the content.

    Fallback trick (OONI quicping): a captured Initial that gets replayed
    can be silently dropped by the server (stale connection ID / rotated
    keys) even on a perfectly healthy path. Per RFC 9000 sec 6.2 a packet
    with an UNKNOWN QUIC version MUST be answered with a Version
    Negotiation packet, so we flip the version field and get a
    deterministic reply whenever UDP 443 is open.

    Uses the first two hosts of the ACTIVE probe set (custom target lists
    included). Returns {"ok": bool, "host": str|None, "err": str|None}."""
    import socket as _socket
    initial = ENGINE_BINS / "fake_quic.bin"
    try:
        data = initial.read_bytes()
    except Exception as e:
        return {"ok": False, "host": None, "err": f"quic bin unreadable: {e}"}
    vn_pkt = bytearray(data)
    vn_pkt[1:5] = b"\x0d\x0d\x0d\x0d"
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    s.settimeout(min(1.5, timeout))
    try:
        for host in PROBE_HOSTS[:2]:
            try:
                ip = _socket.gethostbyname(host)
            except Exception:
                continue
            for pkt in (data, bytes(vn_pkt)):
                try:
                    s.sendto(pkt, (ip, 443))
                    try:
                        resp, _ = s.recvfrom(4096)
                        if len(resp) > 0:
                            return {"ok": True, "host": host, "err": None}
                    except _socket.timeout:
                        continue
                except OSError:
                    continue
        return {"ok": False, "host": None, "err": "no UDP reply"}
    finally:
        try:
            s.close()
        except Exception:
            pass


SERVICE_NAME = "tarndpi"
# Used solely for migration/compatibility with pre-Tarn installs — not a trademark.
LEGACY_SERVICE_NAMES = ("wgdpi", "zapret")


def _sc(*args, timeout=15):
    """Run sc.exe with the given args. Returns CompletedProcess or None."""
    try:
        return subprocess.run(["sc", *args], capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        log(f"sc {' '.join(args)} failed: {e}")
        return None


def _active_service_name():
    """Name of the DPI service on this machine: 'tarndpi' (new installs) or
    the legacy 'wgdpi'/'zapret' services from older versions (migration)."""
    for name in (SERVICE_NAME,) + LEGACY_SERVICE_NAMES:
        r = _sc("query", name)
        if r is not None and r.returncode == 0:
            return name
    return SERVICE_NAME


def _service_installed():
    """True when a DPI service (installed by install.bat) exists."""
    for name in (SERVICE_NAME,) + LEGACY_SERVICE_NAMES:
        r = _sc("query", name)
        if r is not None and r.returncode == 0:
            return True
    return False


def _service_running():
    for name in (SERVICE_NAME,) + LEGACY_SERVICE_NAMES:
        r = _sc("query", name)
        if r is not None and r.returncode == 0 and "RUNNING" in r.stdout.upper():
            return True
    return False


def _service_set_strategy(strategy_key):
    """Point the DPI service at a strategy.

    Uses the exact quoting format proven by the service manager:
    one quoted binPath value with escaped inner quotes. sc.exe rejects a
    multi-token binPath ("Invalid syntax", rc 1639), and Python's
    subprocess cannot reproduce cmd's `\"` escaping on its own, so the
    command is written to a temp .bat and executed via cmd /c.
    The stored ImagePath is verified afterwards with `sc qc`.

    Requires SERVICE_CHANGE_CONFIG; install.bat grants that right to the
    installing user via SDDL (never to all Authenticated Users - that was a
    local privilege escalation), so this normally works without UAC.
    The service uses start= demand: it is started/stopped together with the
    tunnel and never persists across reboots."""
    name = _active_service_name()
    args = _build_args(strategy_key)
    exe = str(ENGINE_BINS / "winws.exe")
    bat_path = None
    try:
        # Empirically-proven quoting on this system: the binPath value is one
        # plain double-quoted token containing the quoted exe and the unquoted
        # args. The flowseal `\"...\"` wrapper stores a literal leading quote
        # in ImagePath and the service then fails to start with rc=2.
        # Args that embed paths (%USERPROFILE% can contain a space, e.g.
        # "C:\Users\John Smith\.tarn-tunnel\...") must be quoted individually,
        # otherwise SCM splits them at the space and the service fails to
        # start.
        def _q(a):
            return f'"{a}"' if any(c in a for c in " \t") else a

        inner = f'"{exe}" {" ".join(_q(a) for a in args)}'
        bat_path = os.path.join(
            tempfile.gettempdir(), f"_tarn_svc_{os.getpid()}.bat")
        with open(bat_path, "w", encoding="utf-8") as f:
            f.write("@echo off\r\n")
            # Auto-restart on crash/exit: the filter must survive any winws
            # crash, task-kill or driver hiccup (SCM restarts it in 5/10/30s).
            # Failure config needs the same CHANGE_CONFIG right as sc config
            # (granted to the installing user by install.bat's SDDL); failures
            # are logged but never fatal.
            f.write(f'sc failure {name} reset= 86400 actions= restart/5000/restart/10000/restart/30000 >nul 2>&1\r\n')
            f.write(f'sc config {name} binPath= "{inner}" start= demand\r\n')
            f.write("exit /b %errorlevel%\r\n")
        r = subprocess.run(["cmd", "/c", bat_path],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError(f"sc config failed (rc={r.returncode}): "
                               f"{(r.stdout + r.stderr).strip()[:200]}")
    finally:
        if bat_path is not None:
            try:
                os.unlink(bat_path)
            except Exception:
                pass
    # Verify the new ImagePath actually stuck (a silent sc failure would
    # leave the previous strategy running and the probe would lie).
    # NOTE: `sc qc` cannot be used here - sc.exe returns error 1734 when the
    # ImagePath exceeds ~4KB (the full strategy command line is ~5.5KB), even
    # though the config itself is stored and used fine by SCM. Read the value
    # straight from the registry instead (readable by normal users).
    try:
        import winreg as _winreg
        with _winreg.OpenKey(
            _winreg.HKEY_LOCAL_MACHINE,
            rf"SYSTEM\CurrentControlSet\Services\{name}",
        ) as key:
            stored, _ = _winreg.QueryValueEx(key, "ImagePath")
    except Exception as e:
        raise RuntimeError(f"registry ImagePath read failed: {e}")
    if exe not in stored or "--dpi-desync" not in stored:
        raise RuntimeError("service ImagePath not updated with strategy "
                           "args - service is misconfigured, re-run install.bat")


def _service_start():
    name = _active_service_name()
    # P0-fix: re-verify the engine files before starting the service as
    # SYSTEM. The service's ImagePath points at %ENGINE_BINS%\winws.exe —
    # if it was replaced after install (supply-chain or local attacker),
    # starting the service would execute the tampered binary as SYSTEM.
    if not _verify_engine_files(ENGINE_BINS):
        log("[SECURITY] engine files failed integrity check — "
            "service NOT started (tampered binary?)")
        return False
    r = _sc("start", name)
    if r is None:
        return False
    if r.returncode == 0:
        time.sleep(1.0)
        return _service_running()
    if "1056" in r.stdout or "1056" in r.stderr:
        # 1056 = instance already running; accept it when the service is up.
        time.sleep(0.5)
        return _service_running()
    log(f"filter service start failed (rc={r.returncode}): "
        f"{(r.stderr or r.stdout).strip()[:200]}")
    return False


def _service_stop(timeout=10.0):
    name = _active_service_name()
    _sc("stop", name)
    deadline = time.time() + timeout
    while time.time() < deadline and _service_running():
        time.sleep(0.5)


def _launch_winws(args):
    core_exe = ENGINE_BINS / "winws.exe"
    full = [str(core_exe)] + args
    try:
        proc = subprocess.Popen(
            full,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            bufsize=1,
            universal_newlines=True,
            cwd=str(ENGINE_BINS),
        )
        return proc, proc.pid
    except OSError as e:
        if getattr(e, "winerror", 0) == 740 or "740" in str(e):
            log("winws.exe requires elevation, launching with UAC runas")
            pid = _start_elevated_winws(full)
            return None, pid
        raise RuntimeError(f"failed to start winws.exe: {e}")


def _run_dpi_candidate(strategy_key, wait=2.0):
    """Start one strategy. Prefers the DPI system service (no UAC);
    falls back to a direct elevated launch when the service is absent."""
    # Final integrity gate: the engine files are user-writable but run as
    # SYSTEM — refuse to spawn if the pinned hashes no longer match.
    if not _verify_engine_files(ENGINE_BINS):
        raise RuntimeError("engine files failed integrity verification")
    args = _build_args(strategy_key)
    log(f"dpi: launching strategy '{strategy_key}'")
    if _service_installed():
        if _service_running():
            log("dpi: filter service already running, stopping first")
            _service_stop()
        _service_set_strategy(strategy_key)
        if not _service_start():
            raise RuntimeError("filter service failed to start")
        time.sleep(wait)
        pid = None
        deadline = time.time() + 5.0
        while time.time() < deadline:
            pid = _find_winws_pid()
            if pid is not None:
                break
            time.sleep(0.5)
        if pid is None:
            raise RuntimeError("winws exited immediately (service)")
        return None, pid
    proc, pid = _launch_winws(args)
    time.sleep(wait)
    if proc is not None:
        if proc.poll() is not None:
            raise RuntimeError("winws exited immediately")
    else:
        if _find_winws_pid() != pid:
            raise RuntimeError("winws exited immediately (elevated)")
    return proc, pid


def _stop_dpi_candidate(proc, pid):
    """Stop a strategy candidate and verify teardown. Service-mode winws is
    stopped via sc; UAC-launched winws cannot be killed by a plain taskkill —
    fall back to the elevated kill so no filter is left running."""
    if _service_installed():
        _service_stop()
    elif proc is not None:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    else:
        try:
            subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                           capture_output=True, timeout=10)
        except Exception:
            pass
    time.sleep(0.5)
    if _find_winws_pid() is not None:
        log("dpi: candidate still running, forcing full winws kill")
        _kill_own_winws()


def _auto_select_dpi():
    """Try strategies (cached first) until one passes the real-world probe.
    The cache is written only when a strategy is verified, so a broken
    strategy never sticks. Service mode probes every candidate without UAC;
    direct (legacy) mode keeps the first candidate when elevation is needed.

    HTTPS-aware: a strategy that only passes over plain HTTP (port 80) is
    NOT trusted on SNI-blocking networks - the real content (video, chat)
    is HTTPS and would stay dead. Such candidates are remembered
    as a last-resort fallback and the search continues; the fallback is
    used only if no HTTPS-capable strategy exists at all.

    Critical-host aware: a candidate that passes HTTPS but leaves a
    critical probe host TLS-dead is not trusted when a better one may
    exist - the WiFi runs proved exactly this: hostfakesplit
    aced the HTTP battery but the critical TLS stayed dead, while a
    badseq-based tail kept it alive. The search keeps such candidates as
    fallbacks and only accepts one when it also clears the critical TLS
    floor (any critical host TLS live), or when everything
    else failed.

    Hybrid-aware: single strategies that fail the critical TLS floor get a
    second chance through the hybrid profiles (targeted-group strategy +
    general-group strategy in one winws process)."""
    cached, _net_other = _read_strategy_cache()
    if cached:
        log(f"dpi: cached strategy '{cached}'")
    if cached in DPI_CACHE_BLACKLIST:
        log("dpi: cached strategy is blacklisted (broken), ignoring it")
        cached = None
    keys = ([cached] if cached else []) + [k for k in DPI_STRATEGY_ORDER if k != cached]
    elevated_mode = not _service_installed()
    http_only = None  # key of the last HTTP-only strategy; kept as last resort
    good_fallback = None  # key of the best HTTPS-passing but critical-TLS-incomplete strategy

    def probe_score(detail):
        ok_hosts = [h for h, v in detail.items() if v.get("ok")]
        score = sum(PROBE_WEIGHTS.get(h, 1.0) for h in ok_hosts)
        https_ok = [h for h, v in detail.items() if v.get("https")]
        https_score = sum(PROBE_WEIGHTS.get(h, 1.0) for h in https_ok)
        crit_tls = [h for h in PROBE_CRITICAL if detail.get(h, {}).get("https")]
        return score, https_score, crit_tls

    for idx, key in enumerate(keys):
        proc, pid = None, None
        try:
            proc, pid = _run_dpi_candidate(key)
        except Exception as e:
            log(f"dpi: strategy {key} failed to start: {e}")
            _stop_dpi_candidate(proc, pid)
            if elevated_mode and "elevat" in str(e):
                raise RuntimeError("The packet filter needs administrator rights (approve the UAC prompt)")
            continue
        # Fast path: the cached strategy was verified before, a single probe
        # round is enough to confirm it still works (saves ~5 s on start).
        # Every other candidate gets the full 2-round probe for honesty.
        passed, detail = _probe_bypass(rounds=1 if idx == 0 and cached else 2,
                                       detailed=True)
        score, https_score, crit_tls = probe_score(detail)
        if passed and https_score >= _probe_score_floor():
            crit_floor = PROBE_CRITICAL if PROBE_HOSTS == DEFAULT_PROBE_HOSTS else PROBE_HOSTS
            if any(h in crit_tls for h in crit_floor):
                # Critical TLS path alive - this is the real deal.
                log(f"dpi: strategy '{key}' verified via probe "
                    f"(HTTPS {https_score:.1f}/{_probe_score_floor():.1f}, "
                    f"critical TLS: {', '.join(crit_tls) or 'none'})")
                _write_strategy_cache(key)
                return proc, pid, key, True
            # HTTPS passes but critical TLS is dead - remember and
            # keep hunting for something that unblocks the content path.
            log(f"dpi: strategy {key} HTTPS OK but critical TLS dead "
                f"(critical TLS: {', '.join(crit_tls) or 'none'}) - searching")
            if elevated_mode and proc is None:
                log("dpi: elevation mode, keeping first strategy despite weak HTTPS")
                return proc, pid, key, False
            _stop_dpi_candidate(proc, pid)
            if good_fallback is None:
                good_fallback = key
            continue
        if passed:
            # HTTP-only: the DPI blocks TLS by SNI for this strategy, so it
            # would not unblock real HTTPS content. Remember it, keep
            # searching for a split-based strategy that hides the SNI.
            log(f"dpi: strategy {key} passes HTTP only (HTTPS {https_score:.1f}/"
                f"{_probe_score_floor():.1f} blocked) - searching for HTTPS-capable")
            if elevated_mode and proc is None:
                log("dpi: elevation mode, keeping first strategy despite weak HTTPS")
                return proc, pid, key, False
            if http_only is None:
                http_only = (proc, pid, key)
                _stop_dpi_candidate(proc, pid)
            else:
                _stop_dpi_candidate(proc, pid)
            continue
        log(f"dpi: strategy {key} did not bypass the probe")
        if elevated_mode and proc is None:
            # Direct elevated mode: probing another strategy means another
            # UAC prompt. Keep the first one running instead.
            log("dpi: elevation mode, keeping first strategy after failed probe")
            return proc, pid, key, False
        _stop_dpi_candidate(proc, pid)
    if good_fallback is not None:
        # No strategy cleared the critical TLS floor. The best
        # HTTPS-capable candidate still beats nothing - restart it.
        key = good_fallback
        log(f"dpi: no strategy with live critical TLS found, "
            f"restarting best HTTPS candidate '{key}'")
        try:
            proc, pid = _run_dpi_candidate(key)
            return proc, pid, key, False
        except Exception as e:
            log(f"dpi: fallback '{key}' failed to start: {e}")
    if http_only is not None:
        # No HTTPS-capable strategy on this network - restart the HTTP-only
        # one rather than leaving the user with no filter at all.
        key = http_only[2]
        log(f"dpi: no HTTPS-capable strategy found, falling back to HTTP-only '{key}'")
        try:
            proc, pid = _run_dpi_candidate(key)
            return proc, pid, key, False
        except Exception as e:
            log(f"dpi: HTTP-only fallback '{key}' failed to start: {e}")
            return None, None, None, False
    return None, None, None, False


def _start_elevated_winws(args):
    """Launch winws.exe with UAC elevation via PowerShell Start-Process."""
    exe = args[0]
    cwd = str(Path(exe).parent)
    args_list = ", ".join(f'"{a}"' for a in args[1:])

    ps_cmd = (
        f'$p = Start-Process -FilePath "{exe}" '
        f'-ArgumentList {args_list} '
        f'-WorkingDirectory "{cwd}" '
        f'-Verb RunAs -WindowStyle Hidden -PassThru; '
        f'$p.Id'
    )

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=60
        )
    except subprocess.TimeoutExpired:
        # UAC prompt not answered in time. The process may still start
        # after this point — report whatever state we can see now; the
        # caller's teardown verification will catch a late start.
        log("elevation prompt timed out, winws may start later")
        return _find_winws_pid()
    if result.returncode != 0:
        stderr = result.stderr.strip().lower()
        if "cancelled" in stderr or "1223" in stderr or "denied" in stderr:
            raise RuntimeError("UAC elevation cancelled by user")
        raise RuntimeError(f"elevation failed: {result.stderr.strip()[:300]}")

    pid_str = result.stdout.strip()
    if pid_str.isdigit():
        return int(pid_str)
    return _find_winws_pid()


# SHA-256 pins for the DPI engine (zapret winws + WinDivert). The engine runs
# with SYSTEM privileges (elevated winws.exe / tarndpi service) out of the
# user-writable APP_DIR, so a tampered binary there would be a direct
# privilege escalation. Every file is verified against these hashes at copy
# time and again right before launch. To update the engine, replace the files
# and re-run:
#   certutil -hashfile engine\bins\winws.exe SHA256
ENGINE_SHA256 = {
    "winws.exe": "affb4f69d2ea302a7abccd5325d81826e140ddae014f1e070bc4a6c0dd555188",
    "WinDivert64.sys": "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2",
    "WinDivert.dll": "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2",
    "cygwin1.dll": "103104a52e5293ce418944725df19e2bf81ad9269b9a120d71d39028e821499b",
    "fake_tls.bin": "b6587a11479823598884619af8b8b5516a9200d4e715599efafce1c32598c47e",
    "fake_quic.bin": "f4589c57749f956bb30538197a521d7005f8b0a8723b4707e72405e51ddac50a",
    "fake_http.bin": "8aa07b640568185049f3d42f96d7850e8d71315e8904d83c16f63f9f1b13b069",
    "quic_initial_sample.bin": "e065870cb0d13152e6132807bbf42218a9e7cd8d96f5602b61674cc540f3a56e",
    "tls_clienthello_large.bin": "8aa07b640568185049f3d42f96d7850e8d71315e8904d83c16f63f9f1b13b069",
    "tls_clienthello_sample.bin": "6c7ff6e200633398d7ad76535c0a5f05c6ac742f021c7a9a55a19ad4e938ab3d",
    "voice_udp.bin": "2fe18b3bd20807d36704d0b072092ee49ae84edca907a4420ab9a0f0f28fddcf",
    "game_udp.bin": "e065870cb0d13152e6132807bbf42218a9e7cd8d96f5602b61674cc540f3a56e",
    "stun.bin": "9cd5469309780ca56c0bd97266524a48c7ee529d02c3179cfecb20b260a59641",
    "stun2.bin": "b7c2497496039c541f7337ac8536813f0a1cf52363ab2faa5213b7816d458813",
    "probe.bin": "9cd5469309780ca56c0bd97266524a48c7ee529d02c3179cfecb20b260a59641",
}


def _verify_engine_files(engine_dir):
    """Verify every pinned engine binary against ENGINE_SHA256.
    Returns True only if all pinned files are present and match."""
    import hashlib
    try:
        for name, expected in ENGINE_SHA256.items():
            p = engine_dir / name
            if not p.exists():
                log(f"engine: missing {name}")
                return False
            actual = hashlib.sha256(p.read_bytes()).hexdigest()
            if actual.lower() != expected.lower():
                log(f"engine: {name} SHA-256 mismatch")
                return False
        return True
    except Exception as e:
        log(f"engine: verification error: {e}")
        return False


# Deprecated engine artifacts (pre-1.9 neutralization): stale payload files
# left by older installs must not survive in deployed engine directories
# (xcopy and shutil copies never delete). The current canonical payload set
# is defined by ENGINE_SHA256; any legacy payload matching the historical
# naming scheme that is not part of that set is purged.
LEGACY_PAYLOAD_GLOBS = ("tls_clienthello_*.bin", "quic_initial_*.bin")


def _purge_deprecated_engine_files():
    """Remove deprecated engine artifacts left by pre-1.9 installs.

    Legacy payloads used a service-specific filename scheme; purge any file
    matching that scheme unless it is part of the current canonical set
    (ENGINE_SHA256), so stale copies cannot survive after upgrades. The
    legacy names are matched by glob, not listed explicitly.
    """
    current = {name for name in ENGINE_SHA256 if name.endswith(".bin")}
    for dirs in (ENGINE_BINS, ENGINE_CONF):
        if not dirs.exists():
            continue
        for pattern in LEGACY_PAYLOAD_GLOBS:
            for p in dirs.glob(pattern):
                if p.name in current:
                    continue
                try:
                    p.unlink()
                    log(f"engine: removed deprecated file {p.name}")
                except Exception as e:
                    log(f"engine: failed to remove {p.name}: {e}")
    ggl = ENGINE_CONF / "ggl.lst"
    tgt = ENGINE_CONF / "tgt.lst"
    try:
        if ggl.exists() and not tgt.exists():
            ggl.rename(tgt)
            log("engine: migrated ggl.lst -> tgt.lst")
        elif ggl.exists():
            ggl.unlink()
            log("engine: removed deprecated ggl.lst")
    except Exception as e:
        log(f"engine: ggl.lst migration failed: {e}")

def _install_engine_from(src_engine):
    """Copy engine bins+conf from src_engine and verify the copies against
    the pinned hashes. Returns True only when the installed engine verifies;
    on failure the unverified copy is purged."""
    try:
        ENGINE_BINS.mkdir(parents=True, exist_ok=True)
        ENGINE_CONF.mkdir(parents=True, exist_ok=True)
        for f in (src_engine / "bins").iterdir():
            # wireproxy.exe is NOT part of the filter engine: it is managed
            # separately (installed to APP_DIR/bin, verified against
            # WIREPROXY_SHA256) and never executed from ENGINE_BINS. Skipping
            # it here avoids planting an unverified 10 MB binary in the
            # engine dir (the ENGINE_SHA256 set has no entry for it).
            if f.is_file() and f.name.lower() != "wireproxy.exe":
                shutil.copy2(str(f), str(ENGINE_BINS / f.name))
        for f in (src_engine / "conf").iterdir():
            if f.is_file():
                shutil.copy2(str(f), str(ENGINE_CONF / f.name))
    except Exception as e:
        log(f"engine copy from {src_engine} failed: {e}")
        return False
    if not _verify_engine_files(ENGINE_BINS):
        log(f"engine copy from {src_engine} failed SHA-256 verification - "
            "refusing to use it")
        try:
            shutil.rmtree(ENGINE_BINS, ignore_errors=True)
        except Exception:
            pass
        return False
    log("engine installed and verified")
    return True


def _ensure_engine():
    _purge_deprecated_engine_files()
    """Ensure engine files are installed (and intact). Auto-copies from
    extension dir if found; every copy is verified against pinned SHA-256
    hashes before use because the engine runs with SYSTEM privileges."""
    if _verify_engine_files(ENGINE_BINS):
        return True
    if ENGINE_BINS.exists():
        # Installed copy failed verification (tampered or partial) — purge
        # it so only a verified copy can ever be used.
        try:
            shutil.rmtree(ENGINE_BINS, ignore_errors=True)
        except Exception as e:
            log(f"engine: failed to purge unverified copy: {e}")

    # Search multiple possible locations for the source engine
    script_file = Path(__file__).resolve()
    search_paths = [
        script_file.parent / "engine",               # same dir as script
        script_file.parent.parent / "engine",         # parent of script dir (most common)
        script_file.parent.parent.parent / "engine",  # grandparent (extension root when script is nested)
    ]

    for src_engine in search_paths:
        src_core = src_engine / "bins" / "winws.exe"
        if src_core.exists():
            log(f"engine found at {src_engine}, copying to {ENGINE_DIR}")
            if _install_engine_from(src_engine):
                return True

    # Fallback: look for engine via Chrome extension registry
    try:
        import winreg
        for root_key_name in ("HKCU", "HKLM"):
            root_key = winreg.HKEY_CURRENT_USER if root_key_name == "HKCU" else winreg.HKEY_LOCAL_MACHINE
            try:
                with winreg.OpenKey(root_key, r"Software\Google\Chrome\NativeMessagingHosts\com.tarn.host") as key:
                    manifest_path = winreg.QueryValue(key, "")
                    manifest_dir = Path(manifest_path).parent
                    # The manifest is in host dir, walk up to find extension
                    # Chrome extension paths: look in chrome extensions
            except Exception:
                pass
        # Check common dev paths
        for dev_path in [
            Path.home() / "tarn-hosts",
        ]:
            dev_engine = dev_path / "engine"
            dev_core = dev_engine / "bins" / "winws.exe"
            if dev_core.exists():
                log(f"engine found at {dev_engine}, copying to {ENGINE_DIR}")
                if _install_engine_from(dev_engine):
                    return True
    except Exception as e:
        log(f"registry/dev search failed: {e}")

    log(f"engine not found. Searched: {[str(p) for p in search_paths]}")
    return False


def _configure_doh(enable=True, adguard=False):
    """Configure Windows DNS-over-HTTPS settings via registry.

    When enable=True:
    - Sets the DNS server (Cloudflare 1.1.1.1, or AdGuard 94.140.14.14 when
      adguard=True) with its DoH template on every interface that has an
      IPv4 address, remembering the exact previous values first.
    - Enables DoH auto-detection in Windows 11+ (EnableAutoDoh=2),
      remembering the previous value.

    When enable=False:
    - Restores ONLY the interfaces and values this code changed (the user's
      original DHCP/static DNS is put back exactly), restores the previous
      EnableAutoDoh value and removes the DoH template we added. User DNS on
      interfaces we never touched is left alone.
    """
    global _doh_enabled_by_us, _doh_prev_autodoh, _doh_used_dns
    # A fresh host instance may have to finish a restore started by a dead
    # one (or re-enable after a crash left DoH on): reload what the original
    # instance captured so we never treat our own 1.1.1.1 as "the original".
    _load_doh_state()
    if platform.system() != "Windows":
        log("DoH configuration is Windows-only")
        return

    try:
        import winreg

        if adguard:
            doh_dns = "94.140.14.14"
            doh_template = "https://dns.adguard-dns.com/dns-query"
        else:
            doh_dns = "1.1.1.1"
            doh_template = "https://cloudflare-dns.com/dns-query"

        # Find active network adapters with IPv4
        interfaces_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
            0, winreg.KEY_READ)

        i = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(interfaces_key, i)
            except OSError:
                break
            try:
                subkey = winreg.OpenKey(interfaces_key, subkey_name, 0,
                                        winreg.KEY_READ | winreg.KEY_WRITE)
            except PermissionError:
                log(f"DoH configuration FAILED: requires Administrator privileges "
                    f"to modify interface {subkey_name}")
                return False
            except OSError:
                i += 1
                continue

            # Check if interface has an IP address assigned (static IPAddress
            # or DHCP-assigned DhcpIPAddress — DHCP-only adapters have no
            # static IPAddress value and must still get DoH applied).
            has_ip = False
            for val_name in ("IPAddress", "DhcpIPAddress"):
                try:
                    ip = winreg.QueryValueEx(subkey, val_name)[0]
                    if isinstance(ip, tuple):
                        if any(addr and addr != "0.0.0.0" for addr in ip):
                            has_ip = True
                            break
                    elif ip and ip != "0.0.0.0":
                        has_ip = True
                        break
                except (FileNotFoundError, TypeError):
                    pass

            if has_ip:
                if enable:
                    # Save previous values once per session so restore puts
                    # them back exactly (user may have static DNS).
                    if subkey_name not in _doh_saved:
                        prev_ns = None
                        prev_prio = None
                        try:
                            prev_ns = winreg.QueryValueEx(subkey, "NameServer")[0]
                        except FileNotFoundError:
                            pass
                        try:
                            prev_prio = winreg.QueryValueEx(subkey, "DohPriority")[0]
                        except FileNotFoundError:
                            pass
                        _doh_saved[subkey_name] = {"ns": prev_ns, "prio": prev_prio}

                    winreg.SetValueEx(subkey, "NameServer", 0, winreg.REG_SZ, doh_dns)
                    winreg.SetValueEx(subkey, "DohPriority", 0, winreg.REG_DWORD, 300)

                    # Create DoH template entry
                    doh_key_path = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers"
                    try:
                        doh_key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, doh_key_path)
                        winreg.SetValueEx(doh_key, doh_dns, 0, winreg.REG_SZ, doh_template)
                        winreg.CloseKey(doh_key)
                    except Exception as e:
                        log(f"DoH template setup failed: {e}")

                    log(f"DoH configured for interface {subkey_name}: {doh_dns}")
                    _doh_used_dns = doh_dns
                else:
                    saved = _doh_saved.get(subkey_name)
                    if saved is not None:
                        if saved["ns"] is None:
                            try:
                                winreg.DeleteValue(subkey, "NameServer")
                            except FileNotFoundError:
                                pass
                        else:
                            winreg.SetValueEx(subkey, "NameServer", 0, winreg.REG_SZ, saved["ns"])
                        if saved["prio"] is None:
                            try:
                                winreg.DeleteValue(subkey, "DohPriority")
                            except FileNotFoundError:
                                pass
                        else:
                            winreg.SetValueEx(subkey, "DohPriority", 0, winreg.REG_DWORD, saved["prio"])
                        _doh_saved.pop(subkey_name, None)
                        log(f"DoH restored for interface {subkey_name}")
            winreg.CloseKey(subkey)
            i += 1

        winreg.CloseKey(interfaces_key)

        # EnableAutoDoh (Windows 11+): remember the previous value at first
        # enable, restore it (or remove the value) at disable.
        doh_enable_key = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
        if enable:
            try:
                dnscache_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, doh_enable_key, 0,
                                              winreg.KEY_READ | winreg.KEY_WRITE)
                try:
                    _doh_prev_autodoh = winreg.QueryValueEx(dnscache_key, "EnableAutoDoh")[0]
                except FileNotFoundError:
                    _doh_prev_autodoh = "missing"
                winreg.SetValueEx(dnscache_key, "EnableAutoDoh", 0, winreg.REG_DWORD, 2)
                winreg.CloseKey(dnscache_key)
                log("DoH auto-detection enabled in Windows")
            except Exception as e:
                log(f"DoH auto-detect enable failed (non-critical): {e}")
        elif _doh_prev_autodoh is not None:
            try:
                dnscache_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, doh_enable_key, 0,
                                              winreg.KEY_READ | winreg.KEY_WRITE)
                if _doh_prev_autodoh == "missing":
                    try:
                        winreg.DeleteValue(dnscache_key, "EnableAutoDoh")
                    except FileNotFoundError:
                        pass
                else:
                    winreg.SetValueEx(dnscache_key, "EnableAutoDoh", 0,
                                      winreg.REG_DWORD, _doh_prev_autodoh)
                winreg.CloseKey(dnscache_key)
            except Exception as e:
                log(f"DoH auto-detect restore failed: {e}")
            _doh_prev_autodoh = None

        # Remove the DoH template value(s) we added - and only if the value
        # still holds one of our known templates (a user value with the same
        # name must never be clobbered). Both the current invocation's server
        # and any previously persisted one (e.g. AdGuard) are cleaned up.
        candidates = {doh_dns}
        if _doh_used_dns:
            candidates.add(_doh_used_dns)
        our_templates = {
            "https://cloudflare-dns.com/dns-query",
            "https://dns.adguard-dns.com/dns-query",
        }
        try:
            doh_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers",
                0, winreg.KEY_READ | winreg.KEY_WRITE)
            try:
                for cand in candidates:
                    try:
                        val = winreg.QueryValueEx(doh_key, cand)[0]
                    except FileNotFoundError:
                        continue
                    if val in our_templates:
                        winreg.DeleteValue(doh_key, cand)
            except Exception:
                pass
            winreg.CloseKey(doh_key)
        except OSError:
            pass
        _doh_used_dns = None

        _doh_enabled_by_us = bool(_doh_saved)
        if enable or _doh_saved:
            _save_doh_state()
        else:
            _clear_doh_state()
        log(f"DoH configuration {'enabled' if enable else 'disabled'}")
        return True

    except ImportError:
        log("winreg not available (not on Windows)")
        return False
    except PermissionError as e:
        log(f"DoH configuration FAILED: requires Administrator privileges ({e})")
        return False
    except Exception as e:
        log(f"DoH configuration failed: {e}")
        return False


# Watchdog: while a real filter session is active (service mode), winws must
# keep running. If the service dies (crash, taskkill, driver hiccup) the
# watchdog restarts it within ~8s. It is started ONLY by start_dpi_bypass -
# the strategy test worker manages the service itself and must never be
# interfered with.
DPI_WATCHDOG = {"thread": None, "stop": threading.Event()}


def _watchdog_loop():
    log("watchdog: started")
    while not DPI_WATCHDOG["stop"].is_set():
        time.sleep(8)
        if DPI_WATCHDOG["stop"].is_set():
            break
        try:
            if _service_installed() and not _service_running():
                log("watchdog: filter service stopped unexpectedly, restarting")
                _service_start()
        except Exception as e:
            log(f"watchdog error: {e}")
    log("watchdog: stopped")


def _watchdog_start():
    if DPI_WATCHDOG["thread"] and DPI_WATCHDOG["thread"].is_alive():
        return
    DPI_WATCHDOG["stop"].clear()
    DPI_WATCHDOG["thread"] = threading.Thread(target=_watchdog_loop, daemon=True)
    DPI_WATCHDOG["thread"].start()


def _watchdog_stop():
    DPI_WATCHDOG["stop"].set()
    if DPI_WATCHDOG["thread"]:
        try:
            DPI_WATCHDOG["thread"].join(timeout=2)
        except Exception:
            pass
    DPI_WATCHDOG["thread"] = None


def start_dpi_bypass(dpi_settings=None):
    """Start packet filter: ensure engine + enable hosts + run the best strategy."""
    global dpi_process, dpi_pid, dpi_strategy, dpi_verified

    if not _ensure_engine():
        raise RuntimeError(
            "Engine not found. Make sure the 'engine' folder is inside the extension directory."
        )

    # Pre-clean stale winws so filters never conflict
    if dpi_process is None and dpi_pid is None and _find_winws_pid() is not None:
        log("stale winws detected, killing before start")
        _kill_own_winws()

    # Step 1: Enable hosts
    hosts_ok = _enable_hosts()
    if not hosts_ok:
        log("WARNING: hosts file update failed (may require Administrator privileges)")

    # Step 2: Enable game filter (respect the user's toggle, default ON)
    if (dpi_settings or {}).get("dpiGameFilter", True):
        _enable_game_filter()
    else:
        _disable_game_filter()

    # Step 2.5: Configure DoH if requested
    doh_ok = True
    if dpi_settings and dpi_settings.get("dpiForceDoh"):
        doh_ok = _configure_doh(enable=True, adguard=(dpi_settings or {}).get("dpiAdguardDns", True))
        if not doh_ok:
            log("WARNING: DoH configuration failed — requires Administrator privileges")

    # Step 3: Write custom domains from DPI settings
    if dpi_settings:
        custom_domains = dpi_settings.get("dpiCustomDomains", [])
        if custom_domains:
            dom_user = ENGINE_CONF / "dom.user"
            dom_user.write_text("\n".join(custom_domains) + "\n", encoding="utf-8")
            log(f"wrote {len(custom_domains)} custom domains to {dom_user}")

    # Step 3.1: Write excluded domains from DPI settings (never touched
    # by the filter: consumed as --hostlist-exclude/--ipset-exclude).
    if dpi_settings:
        excluded_domains = dpi_settings.get("dpiExcludedDomains", [])
        if excluded_domains:
            exc_user = ENGINE_CONF / "exc.user"
            exc_user.write_text("\n".join(excluded_domains) + "\n", encoding="utf-8")
            log(f"wrote {len(excluded_domains)} excluded domains to {exc_user}")

    # Step 3.5: Apply user-supplied probe targets (empty keeps the defaults)
    _set_probe_targets((dpi_settings or {}).get("dpiProbeHosts"))
    if PROBE_HOSTS != DEFAULT_PROBE_HOSTS:
        log(f"dpi: using {len(PROBE_HOSTS)} custom probe targets")

    # Step 4: Strategy selection
    if not _service_installed():
        log("dpi: tarndpi service is NOT installed - every strategy launch "
            "will prompt for elevation (UAC) and stopping may need UAC too. "
            "Re-run install.bat to (re)install the service.")
    override = (dpi_settings or {}).get("dpiStrategy") or "auto"
    if override == "auto":
        log("dpi: auto-selecting strategy")
        dpi_process, dpi_pid, dpi_strategy, dpi_verified = _auto_select_dpi()
        if dpi_strategy is None:
            # Nothing passed the probe (poisoned DNS, probe targets not
            # blocked, or an extremely lossy link). Fall back to the most
            # universal strategy (works on LAN and WiFi) and give it a fair
            # second chance with the multi-round probe before giving up.
            dpi_strategy = DPI_FALLBACK_STRATEGY
            log(f"dpi: no strategy passed the probe, starting universal fallback '{dpi_strategy}'")
            dpi_process, dpi_pid = _run_dpi_candidate(dpi_strategy)
            dpi_verified = _probe_bypass()[0]
            if dpi_verified:
                _write_strategy_cache(dpi_strategy)
                log(f"dpi: fallback '{dpi_strategy}' verified via probe, cached")
            else:
                log("dpi: fallback also failed the probe - DPI runs unverified")
    else:
        if override not in DPI_STRATEGY_ORDER:
            raise RuntimeError(f"unknown strategy: {override}")
        dpi_process, dpi_pid = _run_dpi_candidate(override)
        dpi_strategy = override
        # Explicit choice - a single honest probe round is enough to
        # confirm it (2 rounds would add ~5 s to every manual start).
        dpi_verified = _probe_bypass(rounds=1)[0]

    # The filter must not die: keep the service alive while it should run.
    if _service_installed():
        _watchdog_start()

    # Collect warnings for UI display
    warnings = []
    if not hosts_ok:
        warnings.append("hosts file update failed — may require Administrator privileges")
    if not doh_ok:
        warnings.append("DoH configuration failed — requires Administrator privileges. Run install_service.bat as Administrator or disable DoH in Settings.")

    return {"pid": dpi_pid, "strategy": dpi_strategy, "verified": dpi_verified, "warnings": warnings}


def stop_dpi_bypass():
    """Stop packet filter: kill engine + restore hosts + disable game filter + restore DNS."""
    global dpi_process, dpi_pid, dpi_strategy, dpi_verified

    _watchdog_stop()
    _set_probe_targets([])  # drop any custom probe-target override

    if dpi_process is not None:
        try:
            dpi_process.terminate()
            try:
                dpi_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                dpi_process.kill()
                dpi_process.wait(timeout=3)
        except Exception:
            pass
        dpi_process = None

    if not _kill_own_winws():
        # Never pretend the filter is off when the filter is still active:
        # without the tarndpi service, stopping an elevated winws needs the
        # user to approve the elevation prompt (or re-run install.bat).
        raise RuntimeError(
            "The filter engine is still running and could not be stopped. "
            "Re-run install.bat to (re)install the tarndpi service, or "
            "approve the elevation prompt to kill the remaining winws.exe")
    dpi_pid = None

    _disable_hosts()
    _disable_game_filter()
    
    # Restore DNS settings (undo DoH if we configured it)
    _configure_doh(enable=False)
    dpi_strategy = None
    dpi_verified = False

    log("Packet filter stopped")


# ----------------- Strategy testing (background worker) -----------------
# The full strategy test runs in a worker thread so the host keeps reading
# stdin: the extension can pause / resume / cancel mid-test and receives a
# progress event after every strategy pass (with per-pass host coverage and
# latency). The final report contains a ranking and the winner, which is
# also written to the strategy cache for the next auto-start.

DPI_TEST_CONTROL = {
    "busy": False,
    "cancel": threading.Event(),
    "pause": threading.Event(),  # set => worker waits between passes
}


def _rank_strategy_results(results):
    """Score strategies. The user's actual use case is video + chat, so the
    sort is gated by the critical group, not by raw probe coverage:
    results: {key: {"passesOk": int, "passesTotal": int, "hostsOk": int,
                    "hostsScore": float, "hostsTotal": int,
                    "critTlsOk": int, "critTlsTotal": int,
                    "dataOk": int, "dataTotal": int,
                    "tls13Ok": int, "tls12Ok": int,
                    "quicOk": bool,
                    "latencySum": float, "latencyN": int,
                    "errors": [str]}}

    Sort chain (most important first):
      1. critTlsOk - TLS alive on the critical probe hosts. On the WiFi
         runs hostfakesplit won every HTTP metric yet left the critical
         TLS path dead - a strategy like that must NEVER rank above one
         with live critical TLS. When no strategy has any (fully
         SNI-blocked network), this key is a no-op and coverage decides;
      2. dataOk     - real payload (>1KB) delivered through the desync on
         critical hosts. Handshake alone can pass while the data plane is
         reset - a video still would not play;
      3. hostsScore - weighted HTTP/TCP coverage (the critical pairs
         outweigh random easy hosts) - the floor that proves the desync
         actually bypasses the ISP, and the tiebreak between strategies
         with equal critical TLS;
      4. tls13Ok    - real HTTPS (TLS 1.3) handshakes that went through;
      5. tls12Ok    - legacy TLS coverage, a weaker HTTPS signal;
      6. latency    - ICMP ping, pure link noise, last tie-break only.
    """
    ranked = []
    for key, r in results.items():
        hosts_total = r.get("hostsTotal") or 1
        avg_lat = None
        if r.get("latencyN"):
            avg_lat = round(r["latencySum"] / r["latencyN"], 1)
        ranked.append({
            "strategy": key,
            "passesOk": r.get("passesOk", 0),
            "passes": r.get("passesTotal", 0),
            "hostsOk": r.get("hostsOk", 0),
            "hostsScore": round(r.get("hostsScore", 0.0), 1),
            "hostsTotal": hosts_total,
            "critTlsOk": r.get("critTlsOk", 0),
            "critTlsTotal": r.get("critTlsTotal", 0),
            "dataOk": r.get("dataOk", 0),
            "dataTotal": r.get("dataTotal", 0),
            "tls13Ok": r.get("tls13Ok", 0),
            "tls12Ok": r.get("tls12Ok", 0),
            "quicOk": r.get("quicOk", False),
            "latencyMs": avg_lat,
            "errors": r.get("errors", []),
            "hostsDetail": r.get("hostsDetail", {}),
        })
    ranked.sort(key=lambda x: (
        -x["critTlsOk"],
        -x["dataOk"],
        -x["hostsScore"],
        -x["tls13Ok"],
        -x["tls12Ok"],
        -(x["latencyMs"] is not None),
        x["latencyMs"] if x["latencyMs"] is not None else 1e9,
        x["strategy"],
    ))
    return ranked


def _dpi_test_worker(params):
    ctl = DPI_TEST_CONTROL
    try:
        _set_probe_targets(params.get("probeHosts"))
        want = params.get("strategies") or list(DPI_STRATEGY_ORDER)
        keys = [k for k in want if k in DPI_STRATEGY_ORDER] or list(DPI_STRATEGY_ORDER)
        passes = max(1, min(int(params.get("passes", 2)), 5))
        probe_timeout = max(1.0, min(float(params.get("probeTimeout", 4.0)), 10.0))
        min_ok = max(1, min(int(params.get("minOk", 3)), len(PROBE_HOSTS)))
        wait = 2.0

        def wait_if_paused():
            while ctl["pause"].is_set() and not ctl["cancel"].is_set():
                time.sleep(0.2)

        def score_of(detail):
            """Weighted score + critical-TLS + data-plane summary for a
            detailed host battery. dataOk measures real payload delivery
            (>1KB) - the cheap proxy for 'a video would actually play'."""
            crit_hosts = PROBE_CRITICAL if PROBE_HOSTS == DEFAULT_PROBE_HOSTS else PROBE_HOSTS
            score = sum(PROBE_WEIGHTS.get(d["host"], 1.0) for d in detail
                        if d.get("http"))
            crit_total = len(crit_hosts)
            crit_ok = sum(1 for d in detail
                          if d.get("host") in crit_hosts and d.get("tls13"))
            data_total = len([d for d in detail if d.get("host") in crit_hosts])
            data_ok = sum(1 for d in detail
                          if d.get("host") in crit_hosts and d.get("data"))
            return score, crit_ok, crit_total, data_ok, data_total

        results = {}
        total = len(keys) * passes
        done = 0
        for idx, key in enumerate(keys, 1):
            if ctl["cancel"].is_set():
                break
            zero_streak = 0  # consecutive all-failed passes -> early stop
            for p in range(1, passes + 1):
                wait_if_paused()
                if ctl["cancel"].is_set():
                    break
                proc, pid, err = None, None, ""
                ok = False
                detail = []
                quic_ok = False
                try:
                    proc, pid = _run_dpi_candidate(key, wait=wait)
                except Exception as e:
                    err = str(e)
                if not err:
                    try:
                        hosts_detail = _probe_hosts_detailed(timeout=probe_timeout,
                                                              cancel_check=lambda: ctl["cancel"].is_set())
                        detail = hosts_detail
                        hosts_ok = sum(1 for d in hosts_detail if d["http"])
                        hosts_total = len(hosts_detail)
                        score, crit_ok, crit_total, data_ok, data_total = score_of(hosts_detail)
                        tls13_ok = sum(1 for d in hosts_detail if d.get("tls13"))
                        tls12_ok = sum(1 for d in hosts_detail if d.get("tls12"))
                        lat_list = [d["pingMs"] for d in hosts_detail
                                    if d.get("pingMs") is not None]
                        lat_ms = (round(sum(lat_list) / len(lat_list), 1)
                                  if lat_list else None)
                        ok = hosts_ok >= min_ok and score >= _probe_score_floor()
                        # QUIC path check: even a TCP-dead strategy can be
                        # fine in practice when UDP 443 (video path) flows.
                        quic_ok = _probe_quic(timeout=min(probe_timeout, 3.0))["ok"]
                    except Exception as e:
                        err = f"probe error: {e}"
                        hosts_detail, hosts_ok, hosts_total, lat_ms = [], 0, 0, None
                        crit_hosts = PROBE_CRITICAL if PROBE_HOSTS == DEFAULT_PROBE_HOSTS else PROBE_HOSTS
                        score, crit_ok, crit_total = 0.0, 0, len(crit_hosts)
                        data_ok = data_total = 0
                        tls13_ok = tls12_ok = 0
                    finally:
                        _stop_dpi_candidate(proc, pid)
                    # Check cancel immediately after the probe finishes — abort
                    # before sending the progress message so the worker exits fast.
                    if ctl["cancel"].is_set():
                        # Record a minimal result for this pass so the final
                        # report isn't missing the strategy entirely.
                        r = results.setdefault(key, {
                            "passesOk": 0, "passesTotal": 0, "hostsOk": 0, "hostsTotal": 0,
                            "hostsScore": 0.0,
                            "critTlsOk": 0, "critTlsTotal": 0,
                            "dataOk": 0, "dataTotal": 0,
                            "tls13Ok": 0, "tls12Ok": 0,
                            "quicOk": False,
                            "latencySum": 0.0, "latencyN": 0, "errors": [],
                            "hostsDetail": {},
                        })
                        r["passesTotal"] += 1
                        r["hostsDetail"] = {h: {"http": False, "tls13": False, "tls12": False, "data": False, "media": h in PROBE_MEDIA} for h in PROBE_HOSTS}
                else:
                    hosts_detail, hosts_ok, hosts_total, lat_ms = [], 0, 0, None
                    crit_hosts = PROBE_CRITICAL if PROBE_HOSTS == DEFAULT_PROBE_HOSTS else PROBE_HOSTS
                    score, crit_ok, crit_total = 0.0, 0, len(crit_hosts)
                    data_ok = data_total = 0
                    tls13_ok = tls12_ok = 0

                r = results.setdefault(key, {
                    "passesOk": 0, "passesTotal": 0, "hostsOk": 0, "hostsTotal": 0,
                    "hostsScore": 0.0,
                    "critTlsOk": 0, "critTlsTotal": 0,
                    "dataOk": 0, "dataTotal": 0,
                    "tls13Ok": 0, "tls12Ok": 0,
                    "quicOk": False,
                    "latencySum": 0.0, "latencyN": 0, "errors": [],
                    "hostsDetail": {},
                })
                r["passesTotal"] += 1
                r["hostsOk"] += hosts_ok
                r["hostsTotal"] += hosts_total
                r["hostsScore"] += score
                r["critTlsOk"] += crit_ok
                r["critTlsTotal"] += crit_total
                r["dataOk"] += data_ok
                r["dataTotal"] += data_total
                r["tls13Ok"] += tls13_ok
                r["tls12Ok"] += tls12_ok
                for d in hosts_detail:
                    hd = r["hostsDetail"].setdefault(d["host"], {
                        "http": 0, "tls13": 0, "tls12": 0, "data": 0,
                        "media": d["host"] in PROBE_MEDIA,
                    })
                    hd["http"] += 1 if d.get("http") else 0
                    hd["tls13"] += 1 if d.get("tls13") else 0
                    hd["tls12"] += 1 if d.get("tls12") else 0
                    hd["data"] += 1 if d.get("data") else 0
                if quic_ok:
                    r["quicOk"] = True
                if lat_ms is not None:
                    r["latencySum"] += lat_ms
                    r["latencyN"] += 1
                if ok:
                    r["passesOk"] += 1
                if err:
                    r["errors"].append(err)

                done += 1
                send_message({
                    "status": "dpi_test_progress",
                    "phase": "run",
                    "strategy": key,
                    "index": idx,
                    "total": len(keys),
                    "pass": p,
                    "passes": passes,
                    "done": done,
                    "totalRuns": total,
                    "pct": int(round(100.0 * done / total)),
                    "ok": ok,
                    "hostsOk": hosts_ok,
                    "hostsScore": round(score, 1),
                    "hostsTotal": hosts_total,
                    "tls13Ok": tls13_ok,
                    "tls12Ok": tls12_ok,
                    "critTlsOk": crit_ok,
                    "dataOk": data_ok,
                    "quicOk": quic_ok,
                    "hosts": hosts_detail,
                    "latencyMs": lat_ms,
                    "err": err or None,
                })
                log(f"dpi_test {key} pass {p}/{passes}: ok={ok} hosts={hosts_ok}/{hosts_total} "
                    f"score={score:.1f} critTls={crit_ok}/{crit_total} data={data_ok}/{data_total} "
                    f"tls13={tls13_ok}/{hosts_total} tls12={tls12_ok}/{hosts_total} "
                    f"quic={'OK' if quic_ok else 'ERR'} lat={lat_ms}ms err={err or 'none'}")

                # Early stop: a strategy that scores 0/5 hosts twice in a row
                # is broken on THIS network (proven by the WiFi runs: all
                # failing strategies were 0/5 on every single pass). Skipping
                # the remaining passes saves ~5-7 minutes per failed strategy
                # on jittery links. Remaining passes are recorded as failed
                # so the ranking stays honest.
                zero_streak = zero_streak + 1 if hosts_ok == 0 else 0
                if zero_streak >= 2 and p < passes:
                    log(f"dpi_test {key}: 0/5 in {zero_streak} passes, skipping "
                        f"passes {p + 1}-{passes}")
                    for skip in range(p + 1, passes + 1):
                        if ctl["cancel"].is_set():
                            break
                        r["passesTotal"] += 1
                        done += 1
                        send_message({
                            "status": "dpi_test_progress",
                            "phase": "skip",
                            "strategy": key,
                            "index": idx,
                            "total": len(keys),
                            "pass": skip,
                            "passes": passes,
                            "done": done,
                            "totalRuns": total,
                            "pct": int(round(100.0 * done / total)),
                            "ok": False,
                            "hostsOk": 0,
                            "hostsTotal": hosts_total,
                            "tls13Ok": 0,
                            "tls12Ok": 0,
                            "hosts": [],
                            "latencyMs": None,
                            "err": "early stop (0/5 in two passes)",
                        })
                    break
                # Honor cancel between passes without waiting for the full pass.
                if ctl["cancel"].is_set():
                    break
            if ctl["cancel"].is_set():
                break

        # Guarantee the filter is OFF when the test ends. If an elevated
        # winws survived a candidate stop (UAC declined), retry briefly,
        # then report so the UI can warn the user.
        cleanup_ok = False
        for _ in range(3):
            if _kill_own_winws():
                cleanup_ok = True
                break
            time.sleep(2)
        if not cleanup_ok:
            log("dpi_test: WARNING winws.exe still running after cleanup")

        ranking = _rank_strategy_results(results)
        winner = None
        if ranking and ranking[0]["hostsScore"] > 0:
            winner = ranking[0]["strategy"]
            w = ranking[0]
            _write_strategy_cache(winner, w["tls13Ok"], w["hostsTotal"],
                                  w["tls12Ok"], w["hostsTotal"])
            log(f"dpi_test: winner '{winner}' cached "
                f"(HTTPS {w['tls13Ok']}/{w['hostsTotal']}, "
                f"critTLS {w['critTlsOk']}/{w['critTlsTotal']}, "
                f"data {w['dataOk']}/{w['dataTotal']}, "
                f"quic={'OK' if w['quicOk'] else 'ERR'})")

        send_message({
            "status": "dpi_test",
            "cancelled": ctl["cancel"].is_set(),
            "cleanup": cleanup_ok,
            "winner": winner,
            "ranking": ranking,
            "results": results,
        })
    except Exception as e:
        log(f"dpi_test worker error: {e}")
        send_message({"status": "error",
                      "message": f"strategy test failed: {e}"})
    finally:
        _set_probe_targets([])
        ctl["cancel"].clear()
        ctl["pause"].clear()
        ctl["busy"] = False


# ----------------- Diagnostics -----------------
def _is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _all_winws_pids():
    try:
        out = subprocess.check_output(
            ["tasklist", "/fi", "imagename eq winws.exe", "/fo", "csv", "/nh"],
            text=True, timeout=5)
        return [int(line.split(",")[1].strip('"'))
                for line in out.strip().splitlines() if "winws.exe" in line.lower()]
    except Exception:
        return []


def _env_checks():
    """DPI environment checks: conflicting services/software and
    Windows settings that break winws or the bypass. Mirrors service.bat
    diagnostics. Returns a dict of {check: {ok: bool, note: str}}."""
    import winreg as _winreg
    out = {}

    def note(name, ok, text):
        out[name] = {"ok": ok, "note": text}

    # Base Filtering Engine
    r = _sc("query", "BFE")
    bfe_running = (r is not None and r.returncode == 0 and "RUNNING" in r.stdout.upper())
    note("bfe", bfe_running,
         "" if bfe_running else
         "Base Filtering Engine not running - required for winws")

    # System proxy (WinINET)
    proxy_on, proxy_server = False, ""
    try:
        with _winreg.OpenKey(_winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as k:
            proxy_on = _winreg.QueryValueEx(k, "ProxyEnable")[0] == 1
            try:
                proxy_server = str(_winreg.QueryValueEx(k, "ProxyServer")[0])
            except Exception:
                pass
    except Exception:
        pass
    if proxy_on:
        note("proxy", False,
             "System proxy is enabled: %s" % proxy_server)
    else:
        note("proxy", True, "")

    # TCP timestamps
    ts_ok = False
    try:
        r = subprocess.run(["netsh", "interface", "tcp", "show", "global"],
                           capture_output=True, text=True, timeout=15,
                           errors="replace")
        ts_ok = ("timestamps" in r.stdout.lower()
                 and "enabled" in r.stdout.lower())
    except Exception:
        pass
    note("tcpTimestamps", ts_ok,
         "" if ts_ok else "TCP timestamps disabled - winws (fake,ts) strategies need them")

    # Adguard process
    adg = False
    try:
        r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq AdguardSvc.exe"],
                           capture_output=True, text=True, timeout=10)
        adg = "AdguardSvc.exe" in r.stdout
    except Exception:
        pass
    note("adguard", not adg,
         "AdguardSvc.exe process found - can interfere with chat/video apps" if adg else "")

    # Killer / Intel Connectivity / Check Point / SmartByte / VPN via sc query
    def services_matching(*words):
        found = []
        try:
            r = _sc("query", "state= all")
            if r is not None and r.returncode == 0:
                for line in r.stdout.splitlines():
                    low = line.lower()
                    if all(w.lower() in low for w in words):
                        name = line.strip().split(":")[-1].strip()
                        found.append(name)
        except Exception:
            pass
        return found

    killer = services_matching("killer")
    note("killer", not killer,
         "Killer services found: %s" % ", ".join(killer) if killer else "")

    intel = services_matching("intel", "connectivity", "network")
    note("intel", not intel,
         "Intel Connectivity Network Service found: %s" % ", ".join(intel) if intel else "")

    cp = services_matching("tracsrvwrapper") + services_matching("epwd")
    note("checkpoint", not cp,
         "Check Point services found: %s" % ", ".join(cp) if cp else "")

    smart = services_matching("smartbyte")
    note("smartbyte", not smart,
         "SmartByte services found: %s" % ", ".join(smart) if smart else "")

    vpn = services_matching("vpn")
    if vpn:
        note("vpn", False,
             "VPN services found: %s. Disable them, they can conflict" % ", ".join(vpn))
    else:
        note("vpn", True, "")

    # DoH configured at system level
    doh_count = 0
    try:
        with _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters") as k:
            for i in range(1024):
                try:
                    sub = _winreg.EnumKey(k, i)
                except OSError:
                    break
                try:
                    with _winreg.OpenKey(k, sub) as s:
                        try:
                            if _winreg.QueryValueEx(s, "DohFlags")[0] > 0:
                                doh_count += 1
                        except OSError:
                            pass
                except OSError:
                    pass
    except Exception:
        pass
    if doh_count == 0:
        note("secureDns", False,
             "No encrypted DNS configured in Windows - DPI still sees plain DNS. "
             "Run install_service.bat as Administrator to enable DoH, or disable the DoH toggle in Settings")
    else:
        note("secureDns", True,
             "Encrypted DNS active on %d interface(s)" % doh_count)

    return out


TOTAL_DIAG_PHASES = 8


def _collect_diagnostics(progress_cb=None):
    """Read-only snapshot of the whole DPI stack for the diagnostics UI."""
    def emit(step, phase):
        if progress_cb:
            progress_cb(step, TOTAL_DIAG_PHASES, phase)

    emit(1, "base")
    d = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "hostVersion": 2,
        "python": platform.python_version(),
        "os": platform.platform(),
        "admin": _is_admin(),
        "engine": {},
        "service": {},
        "winwsProcesses": _all_winws_pids(),
        "strategyCache": _strategy_cache_display(),
        "gameFilter": "",
        "dohEnabledByUs": _doh_enabled_by_us,
        "wireproxy": find_wireproxy() or None,
        "dns": {},
        "internet": {},
        "env": {},
        "logTail": [],
    }

    try:
        for name in ("winws.exe", "WinDivert.dll", "WinDivert64.sys",
                     "cygwin1.dll", "probe.bin"):
            p = ENGINE_BINS / name
            d["engine"][name] = {
                "exists": p.exists(),
                "size": p.stat().st_size if p.exists() else None,
            }
        d["engine"]["confDir"] = ENGINE_CONF.exists()
    except Exception as e:
        d["engine"]["error"] = str(e)
    emit(2, "engine")

    try:
        d["service"]["installed"] = _service_installed()
        d["service"]["running"] = _service_running()
        if d["service"]["installed"]:
            import winreg
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    rf"SYSTEM\CurrentControlSet\Services\{_active_service_name()}") as k:
                    d["service"]["imagePath"] = winreg.QueryValueEx(k, "ImagePath")[0]
            except Exception as e:
                d["service"]["imagePathError"] = str(e)
            r = _sc("sdshow", SERVICE_NAME)
            if r is not None and r.returncode == 0:
                d["service"]["sddl"] = r.stdout.strip()
    except Exception as e:
        d["service"]["error"] = str(e)
    emit(3, "service")

    try:
        flag = ENGINE_DIR / "game_filter.enabled"
        d["gameFilter"] = flag.read_text(encoding="utf-8").strip() if flag.exists() else ""
    except Exception:
        pass
    emit(4, "runtime")

    import socket as _socket
    for host in PROBE_HOSTS:
        try:
            _socket.setdefaulttimeout(3)
            ips = sorted({x[4][0] for x in _socket.getaddrinfo(host, 443)})
            d["dns"][host] = ips[:3]
        except Exception as e:
            d["dns"][host] = f"FAILED: {e}"
    emit(5, "dns")

    try:
        dpi_running = (_find_winws_pid() is not None)
        ok, detail = _probe_bypass(timeout=4, min_ok=1, detailed=True, rounds=1)
        d["internet"] = {
            "dpiRunningDuringCheck": dpi_running,
            "okCount": sum(1 for v in detail.values() if v.get("ok")),
            "total": len(detail),
            "hosts": detail,
        }
    except Exception as e:
        d["internet"]["error"] = str(e)
    emit(6, "internet")

    try:
        d["env"] = _env_checks()
    except Exception as e:
        d["env"] = {"error": str(e)}
    emit(7, "env")

    try:
        lines = LOG_PATH.read_text(encoding="utf-8", errors="ignore").splitlines()
        d["logTail"] = lines[-40:]
    except Exception:
        pass
    emit(8, "log")

    return d


# ----------------- Main loop -----------------
def _cleanup_on_exit():
    """Cancel an in-flight start/test when the native port closes.

    IMPORTANT: this must NOT stop a packet filter that is already running.

    Why (regression fixed in 1.7.2): in MV3 Chrome terminates the extension
    service worker at any moment (closing the popup does not keep it alive),
    and every native-messaging port created by a dead service worker is
    disconnected. On top of that, background.js's _dpiStart() deliberately
    disconnects its port immediately after receiving "dpi_started" - the port
    close is the NORMAL end of the start conversation, not a failure signal.
    If EOF stopped the bypass, the freshly started winws.exe would be killed
    within milliseconds of starting: the user sees "bypass dies right after
    the popup hides". The 1.6.10 host simply exited on EOF and the bypass
    kept working - that is the contract we must preserve.

    A winws.exe left behind by an exiting host keeps filtering (it is either
    the tarndpi service or a detached child process). It is intentionally
    reaped ONLY by an explicit stop_dpi command, which the extension sends
    over a fresh port whenever the user asks to stop (or the extension's own
    watchdog decides to). The tiny race where EOF lands between winws launch
    and the "dpi_started" reply self-heals: a later dpiQueryStatus reports
    running=true from _find_winws_pid() and the UI resyncs.

    The only thing EOF must do is abort an in-flight strategy test: the
    probe worker would otherwise keep cycling winws candidates for minutes
    with nobody left to consume the results. The worker's own cancel path
    kills the current candidate, so after the wait below nothing of ours
    remains running."""
    try:
        if DPI_TEST_CONTROL["busy"]:
            DPI_TEST_CONTROL["cancel"].set()
            deadline = time.time() + 30
            while time.time() < deadline and DPI_TEST_CONTROL["busy"]:
                time.sleep(0.5)
            if DPI_TEST_CONTROL["busy"]:
                log("cleanup on stdin close: probe still busy after 30s, abandoning it")
    except Exception as e:
        log(f"cleanup on stdin close failed: {e}")


def _cleanup_orphan_configs():
    """Remove wireproxy_*.conf files left behind by a crashed host.

    Each connect writes a temporary wireproxy config containing the
    profile's private key into CONFIG_DIR. It is deleted on clean
    disconnect (_cleanup), but a hard host crash (SIGKILL, power loss)
    can leave it on disk with the key in plaintext. Running at startup
    of every fresh host instance bounds the exposure window.
    """
    try:
        if not CONFIG_DIR.exists():
            return
        for orphan in CONFIG_DIR.glob("wireproxy_*.conf"):
            try:
                orphan.unlink()
                log(f"startup: removed orphan config {orphan.name}")
            except Exception:
                pass
    except Exception as e:
        log(f"startup orphan config cleanup failed: {e}")


def main():
    log("host started (v2, wireproxy backend)")
    sigpipe = getattr(signal, "SIGPIPE", None)
    if sigpipe is not None:
        signal.signal(sigpipe, signal.SIG_DFL)

    _cleanup_orphan_configs()

    current = None
    binary_status = {"wireproxy": bool(find_wireproxy())}

    # Idle watchdog: bound the lifetime of orphaned instances. Chrome
    # sometimes kills a service worker without closing the native pipe,
    # leaving cmd/python host processes running indefinitely (they also
    # hold wrapper.bat open, which made install.bat's rewrite of it fail
    # on re-run). Exit when quiet for 120s with nothing active.
    last_msg_time = [time.time()]
    def _idle_watchdog():
        while True:
            time.sleep(5)
            if time.time() - last_msg_time[0] > 120:
                if current is None and dpi_process is None and dpi_pid is None \
                        and not DPI_TEST_CONTROL["busy"]:
                    log("idle watchdog: no activity for 120s, exiting")
                    os._exit(0)
    threading.Thread(target=_idle_watchdog, daemon=True).start()

    while True:
        msg = read_message()
        if msg is _EOF:
            log("stdin closed, exiting")
            _cleanup_on_exit()
            break
        if msg is _MALFORMED:
            # A single malformed message must not kill the host (a crashed
            # or hostile extension must not take down a live tunnel).
            log("malformed native message, ignoring")
            continue
        assert isinstance(msg, dict)
        last_msg_time[0] = time.time()
        cmd = msg.get("cmd", "")

        # Command whitelist: reject unknown commands immediately. The extension
        # only ever sends the commands listed below — anything else is a bug
        # or a crafted message from a compromised extension.
        _ALLOWED_CMDS = {
            "ping", "connect", "disconnect", "stats", "check_wireproxy",
            "start_dpi", "stop_dpi", "dpi_status", "dpi_list_strategies",
            "dpi_test", "dpi_test_cancel", "dpi_test_pause", "dpi_test_resume",
            "diagnostics",
        }
        if not isinstance(cmd, str) or cmd not in _ALLOWED_CMDS:
            send_message({"status": "error", "message": f"unknown cmd: {cmd}"})
            continue

        try:
            if cmd == "ping":
                # Report whether wireproxy is available
                wp = find_wireproxy()
                binary_status["wireproxy"] = bool(wp)
                send_message({
                    "status": "alive",
                    "wireproxyAvailable": bool(wp),
                    "wireproxyPath": wp or "",
                    "version": 2,
                })

            elif cmd == "check_wireproxy":
                wp = find_wireproxy()
                if not wp:
                    send_message({
                        "status": "log",
                        "message": "wireproxy not found, attempting download...",
                    })
                    try:
                        wp = download_wireproxy()
                    except Exception as e:
                        send_message({
                            "status": "error",
                            "message": f"wireproxy download failed: {e}",
                        })
                        continue
                send_message({
                    "status": "alive",
                    "wireproxyAvailable": True,
                    "wireproxyPath": wp,
                })

            elif cmd == "connect":
                if current:
                    try:
                        current.stop()
                    except Exception:
                        pass
                    current = None

                config_text = msg.get("config", "")
                socks_addr = msg.get("socksAddr") or DEFAULT_SOCKS
                cfg = parse_wg_config(config_text)

                # AdGuard DNS toggle (default ON): route the tunnel's DNS
                # through AdGuard (94.140.14.14) when enabled. When disabled,
                # keep whatever DNS the profile specifies (or none).
                if msg.get("dpiAdguardDns"):
                    cfg["interface"]["DNS"] = "94.140.14.14,94.140.15.15"

                current = WireproxyTunnel()
                info = current.start(cfg, socks_addr)
                log(f"connected backend={info.get('backend')} socks={info.get('socksAddr')}")
                send_message({
                    "status": "ready",
                    "socksAddr": info["socksAddr"],
                    "backend": info.get("backend", "wireproxy"),
                    "wireproxyPath": current.binary,
                })

            elif cmd == "disconnect":
                if current:
                    try:
                        current.stop()
                    except Exception:
                        pass
                    current = None
                send_message({"status": "stopped"})

            elif cmd == "stats":
                if current:
                    send_message({"status": "stats", **current.stats()})
                else:
                    send_message({
                        "status": "stats",
                        "txBytes": 0, "rxBytes": 0,
                        "lastHandshake": 0, "latency": 0,
                        "connections": 0, "alive": False, "uptime": 0,
                    })

            elif cmd == "start_dpi":
                if DPI_TEST_CONTROL["busy"]:
                    send_message({"status": "error",
                                  "message": "strategy test in progress, stop it first"})
                    continue
                try:
                    dpi_settings = msg.get("dpiSettings", {})
                    dpi_result = start_dpi_bypass(dpi_settings)
                    resp = {"status": "dpi_started", "pid": dpi_result.get("pid"),
                            "cachedStrategy": _read_strategy_cache()}
                    if dpi_result.get("warnings"):
                        resp["warnings"] = dpi_result["warnings"]
                    send_message(resp)
                except Exception as e:
                    send_message({"status": "error", "message": f"DPI start failed: {e}"})

            elif cmd == "stop_dpi":
                if DPI_TEST_CONTROL["busy"]:
                    send_message({"status": "error",
                                  "message": "strategy test in progress, stop it first"})
                    continue
                try:
                    stop_dpi_bypass()
                    send_message({"status": "dpi_stopped"})
                except Exception as e:
                    send_message({"status": "error", "message": f"DPI stop failed: {e}"})

            elif cmd == "dpi_status":
                running = False
                pid = None
                if dpi_process is not None:
                    running = dpi_process.poll() is None
                    pid = dpi_process.pid if running else None
                elif dpi_pid is not None:
                    real_pid = _find_winws_pid()
                    running = real_pid == dpi_pid
                    pid = dpi_pid if running else None
                else:
                    real_pid = _find_winws_pid()
                    running = real_pid is not None
                    pid = real_pid
                engine_exists = (ENGINE_BINS / "winws.exe").exists()
                send_message({
                    "status": "dpi_status",
                    "running": running,
                    "engineAvailable": engine_exists,
                    "pid": pid,
                    "strategy": dpi_strategy if running else None,
                    "verified": dpi_verified if running else False,
                    "cachedStrategy": _read_strategy_cache(),
                    "testRunning": DPI_TEST_CONTROL["busy"],
                })

            elif cmd == "dpi_list_strategies":
                send_message({
                    "status": "dpi_list",
                    "strategies": list(DPI_STRATEGY_ORDER),
                    "current": dpi_strategy,
                    "cached": _read_strategy_cache(),
                })

            elif cmd == "dpi_test":
                if DPI_TEST_CONTROL["busy"]:
                    send_message({"status": "error",
                                  "message": "strategy test already running"})
                    continue
                if dpi_process is not None or dpi_pid is not None:
                    send_message({"status": "error",
                                  "message": "stop DPI before running strategy tests"})
                    continue
                DPI_TEST_CONTROL["busy"] = True
                DPI_TEST_CONTROL["cancel"].clear()
                DPI_TEST_CONTROL["pause"].clear()
                threading.Thread(target=_dpi_test_worker,
                                 args=(dict(msg),), daemon=True).start()
                send_message({"status": "dpi_test_started"})

            elif cmd == "dpi_test_cancel":
                if DPI_TEST_CONTROL["busy"]:
                    DPI_TEST_CONTROL["cancel"].set()
                    DPI_TEST_CONTROL["pause"].clear()
                    send_message({"status": "dpi_test_cancelling"})
                else:
                    send_message({"status": "dpi_test_idle"})

            elif cmd == "dpi_test_pause":
                if DPI_TEST_CONTROL["busy"]:
                    DPI_TEST_CONTROL["pause"].set()
                    send_message({"status": "dpi_test_paused"})
                else:
                    send_message({"status": "dpi_test_idle"})

            elif cmd == "dpi_test_resume":
                if DPI_TEST_CONTROL["busy"]:
                    DPI_TEST_CONTROL["pause"].clear()
                    send_message({"status": "dpi_test_resumed"})
                else:
                    send_message({"status": "dpi_test_idle"})

            elif cmd == "diagnostics":
                try:
                    d = _collect_diagnostics(
                        progress_cb=lambda step, total, phase: send_message({
                            "status": "diag_progress",
                            "done": step,
                            "total": total,
                            "phase": phase,
                        }))
                    send_message({"status": "diagnostics",
                                  "diagnostics": d})
                except Exception as e:
                    send_message({"status": "error",
                                  "message": f"diagnostics failed: {e}"})

            else:
                send_message({"status": "error", "message": f"unknown cmd: {cmd}"})

        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            log("ERROR: " + tb)
            send_message({"status": "error", "message": str(e)})


if __name__ == "__main__":
    # CLI cleanup mode (used by uninstall.bat): restore the hosts file and
    # system DNS/DoH settings that a previous session may have left enabled,
    # without entering the native-messaging loop. Requires Administrator rights
    # for the registry parts; failures are logged, not fatal.
    if "--cleanup-filter" in sys.argv:
        log("CLI cleanup: restoring hosts file + DNS/DoH settings")
        try:
            _disable_hosts()
        except Exception as e:
            log(f"CLI cleanup: hosts restore failed: {e}")
        try:
            _configure_doh(enable=False)
        except Exception as e:
            log(f"CLI cleanup: DoH restore failed: {e}")
        sys.exit(0)

    main()
