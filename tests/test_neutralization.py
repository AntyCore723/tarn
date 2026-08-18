#!/usr/bin/env python3
"""Regression tests for the v1.8.0 neutralization changes.

Covers the behaviors changed in 1.8.0:
  * denylist-first semantics of _build_args (hostlist-exclude everywhere
    for safe strategies, dom.user allowlist only for aggressive ones)
  * HOSTS_ENTRIES no longer contains telegram/discord/etc. families
  * probe defaults are neutral hosts (no google/youtube/discord)
  * no google/4pda/max_ru fake payloads or ggl.lst anywhere in the engine
  * start_dpi_bypass writes dpiExcludedDomains to exc.user

Run:  python tests/test_neutralization.py   (or pytest tests/)
"""

import os
import sys

HOST_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HOST_DIR, "native-host"))

import tarn_host as w  # noqa: E402

# Domains that must not appear anywhere in the bypass payloads/lists.
BANNED_FAMILIES = ("telegram", "discord", "youtube", "ozon", "4pda",
                   "max_ru", "www_google_com", "googleusercontent",
                   "googlevideo", "google.com", "onetrust")
# The pinned identity of the "targeted" group list (renamed from ggl.lst).
BANNED_LIST_NAMES = ("ggl.lst",)


def _all_args(keys):
    out = []
    for k in keys:
        out.extend(w._build_args(k))
    return out


def test_hosts_entries_are_neutral():
    joined = w.HOSTS_ENTRIES.lower()
    for fam in BANNED_FAMILIES:
        assert fam not in joined, f"HOSTS_ENTRIES still mentions {fam}"
    assert "githubusercontent.com" in joined
    assert "wg" in w.HOSTS_ENTRIES[:64].lower()


def test_probe_defaults_are_neutral():
    joined = " ".join(w.DEFAULT_PROBE_HOSTS).lower()
    for fam in BANNED_FAMILIES:
        assert fam not in joined, f"probe defaults still mention {fam}"
    assert w.DEFAULT_PROBE_HOSTS == (
        "www.cloudflare.com", "www.wikipedia.org", "example.com", "www.example.org")
    assert w.PROBE_MIN_OK == 2


def test_safe_strategy_is_denylist_only():
    args = _all_args(("multisplit", "syndata_multidisorder"))
    hostlists = [a for a in args if "--hostlist" in a]
    assert hostlists, "safe strategies must pass hostlist flags"
    assert all("--hostlist-exclude" in a for a in hostlists), \
        "safe strategies must use hostlist-exclude only"
    assert any("dom.user" in a and "--hostlist-exclude" in a for a in hostlists)
    assert any("tgt.lst" in a and "--hostlist-exclude" in a for a in hostlists)
    assert any("exc.user" in a and "--hostlist-exclude" in a for a in hostlists)
    assert not any("--hostlist-domains=" in a for a in args), \
        "no service-specific hostlist-domains flags may remain"
    assert not any("discord.media" in a for a in args)


def test_aggressive_strategy_uses_allowlist_for_user_domains():
    args = w._build_args("fake_fakedsplit_ts")
    assert any("--hostlist=" in a and "dom.user" in a for a in args), \
        "aggressive strategies keep the dom.user allowlist"
    assert any("--hostlist-exclude" in a and "tgt.lst" in a for a in args), \
        "tgt.lst must stay excluded for aggressive strategies too"
    assert any("--ip-id=zero" in a for a in args)


def test_voice_and_media_blocks_are_port_scoped():
    args = _all_args(("multisplit", "fake_fakedsplit_ts"))
    assert any("--filter-udp=19294-19344,50000-50100" in a for a in args)
    assert any("--filter-tcp=2053,2083,2087,2096,8443" in a for a in args)
    assert not any("discord.media" in a for a in args)


def test_engine_payloads_are_neutral():
    for b in _repo_bin_names():
        for fam in BANNED_FAMILIES:
            assert fam not in b, f"stale payload in engine/bins: {b}"
    confs = _repo_conf_names()
    for c in confs:
        for name in BANNED_LIST_NAMES:
            assert c != name, f"stale list in engine/conf: {c}"
    assert "tgt.lst" in confs, "tgt.lst must exist in engine/conf"


def test_engine_pins_cover_fake_payloads():
    for name in ("fake_tls.bin", "fake_quic.bin"):
        assert name in w.ENGINE_SHA256, f"{name} must be pinned"
    payloads = [
        f for f in w.ENGINE_SHA256 if f.endswith(".bin")
    ]
    assert len(payloads) == 11, f"all 11 payload .bin files must be pinned (got {len(payloads)})"


def test_engine_bins_contain_no_service_sni():
    """All shipped .bin payloads must carry neutral SNI/hostnames only."""
    bins_dir = os.path.join(HOST_DIR, "engine", "bins")
    banned = ("cloudflare.com", "www.onetrust.com", "4pda.to", "google.",
              "youtube", "discord.")
    for f in _repo_bin_names():
        if not f.endswith(".bin"):
            continue
        data = open(os.path.join(bins_dir, f), "rb").read().decode(
            "latin-1", errors="ignore").lower()
        for bad in banned:
            assert bad not in data, f"{f} still contains SNI/hostname {bad}"


def test_engine_contains_no_google_sni():
    text = open(os.path.join(HOST_DIR, "native-host", "tarn_host.py"),
                encoding="utf-8").read()
    assert "www.google.com" not in text


def test_start_dpi_bypass_writes_exc_user():
    src = os.path.join(HOST_DIR, "native-host", "tarn_host.py")
    text = open(src, encoding="utf-8").read()
    assert 'dpi_settings.get("dpiExcludedDomains", [])' in text
    assert 'exc_user = ENGINE_CONF / "exc.user"' in text
    assert 'exc_user.write_text(' in text


def _repo_bin_names():
    d = os.path.join(HOST_DIR, "engine", "bins")
    return os.listdir(d)


def _repo_conf_names():
    d = os.path.join(HOST_DIR, "engine", "conf")
    return os.listdir(d)


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"ERROR {fn.__name__}: {e!r}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
