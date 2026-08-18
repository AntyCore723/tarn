// lib/parser.js — WG config parser & validator
// SPDX-License-Identifier: GPL-3.0-only
// Robust INI-style parser for [Interface] / [Peer] sections used by WG.

(function (global) {
  "use strict";

  const REQUIRED_INTERFACE_KEYS = ["PrivateKey"];
  const REQUIRED_PEER_KEYS = ["PublicKey", "Endpoint"];
  const ALLOWED_INTERFACE_KEYS = new Set([
    "PrivateKey", "Address", "DNS", "MTU", "ListenPort",
    "FwMark", "Table", "PreUp", "PostUp", "PreDown", "PostDown",
    "SaveConfig"
  ]);
  const ALLOWED_PEER_KEYS = new Set([
    "PublicKey", "PresharedKey", "AllowedIPs", "Endpoint",
    "PersistentKeepalive"
  ]);

  // Base64 url-safe alphabet used by WG keys
  const KEY_RE = /^[A-Za-z0-9+/]{43}=$/;

  function isIPv4(s) {
    const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return false;
    return m.slice(1).every((p) => +p >= 0 && +p <= 255);
  }
  function isIPv6(s) {
    return /^[0-9a-fA-F:]+$/.test(s) && s.includes(":");
  }
  function isCIDR(s) {
    const i = s.lastIndexOf("/");
    if (i < 0) return false;
    const addr = s.slice(0, i);
    const prefix = parseInt(s.slice(i + 1), 10);
    if (isNaN(prefix)) return false;
    if (isIPv4(addr)) return prefix >= 0 && prefix <= 32;
    if (isIPv6(addr)) return prefix >= 0 && prefix <= 128;
    return false;
  }
  function isHostPort(s) {
    // host:port or [ipv6]:port
    const m = s.match(/^(.+):(\d{1,5})$/);
    if (!m) return false;
    const port = parseInt(m[2], 10);
    return port > 0 && port <= 65535;
  }
  function extractHost(endpoint) {
    // Handles both IPv4 (1.2.3.4:51820) and IPv6 ([2001:db8::1]:51820)
    if (endpoint.startsWith("[")) {
      const close = endpoint.indexOf("]");
      return close > 1 ? endpoint.slice(1, close) : endpoint;
    }
    const idx = endpoint.lastIndexOf(":");
    return idx > 0 ? endpoint.slice(0, idx) : endpoint;
  }
  function isValidKey(k) {
    return KEY_RE.test(k.trim());
  }

  function derivePublicKey(privateKey) {
    // WG uses Curve25519 X25519. Public key = X25519 basepoint * private.
    // We use the WebCrypto-compatible approach via a bundled curve25519 implementation.
    // To keep the extension dependency-free we implement X25519 scalar-mult here.
    try {
      const pub = curve25519BasePoint(toBytes(privateKey));
      return toBase64(pub);
    } catch (e) {
      return null;
    }
  }

  // ---- Base64 helpers ----
  function toBytes(b64) {
    b64 = b64.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function toBase64(bytes) {
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/=+$/, "") + "=";
  }

  // ---- Curve25519 (TweetNaCl-derived) ----
  // Adapted from TweetNaCl.js (https://github.com/dchest/tweetnacl-js)
  // by Dmitry Chestnykh & Devolutions, public domain.
  // Original TweetNaCl: https://tweetnacl.cr.yp.to/
  const gf = function (init) {
    const r = new Float64Array(16);
    if (init) for (let i = 0; i < init.length; i++) r[i] = init[i];
    return r;
  };
  const _9 = new Uint8Array(32); _9[0] = 9;
  function car25519(o) {
    let c;
    for (let i = 0; i < 16; i++) {
      o[i] += 65536;
      c = Math.floor(o[i] / 65536);
      o[(i + 1) * (i < 15 ? 1 : 0)] += c - 1 + 37 * (c - 1) * (i === 15 ? 1 : 0);
      o[i] -= 65536 * c;
    }
  }
  function sel25519(p, q, b) {
    let c, t = ~b;
    for (let i = 0; i < 16; i++) {
      c = t & (p[i] ^ q[i]);
      q[i] ^= c; p[i] ^= c;
    }
  }
  function pack25519(o, n) {
    const m = gf(), t = gf();
    for (let i = 0; i < 16; i++) t[i] = n[i];
    car25519(t); car25519(t); car25519(t);
    for (let j = 0; j < 2; j++) {
      m[0] = t[0] - 0xffed;
      for (let i = 1; i < 15; i++) {
        m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
        m[i - 1] &= 0xffff;
      }
      m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
      const b = (m[15] >> 16) & 1;
      m[14] &= 0xffff;
      sel25519(t, m, 1 - b);
    }
    for (let i = 0; i < 16; i++) {
      o[2 * i] = t[i] & 0xff;
      o[2 * i + 1] = t[i] >> 8;
    }
  }
  function unpack25519(o, n) {
    for (let i = 0; i < 16; i++) {
      o[i] = n[2 * i] + (n[2 * i + 1] << 8);
    }
    o[15] &= 0x7fff;
  }
  function add(o, a, b) {
    for (let i = 0; i < 16; i++) o[i] = a[i] + b[i];
  }
  function sub(o, a, b) {
    for (let i = 0; i < 16; i++) o[i] = a[i] - b[i];
  }
  function mul(o, a, b) {
    const v = new Float64Array(31);
    for (let i = 0; i < 16; i++) v[i] = 0;
    for (let i = 0; i < 16; i++) {
      for (let j = 0; j < 16; j++) v[i + j] += a[i] * b[j];
    }
    for (let i = 0; i < 15; i++) v[i] += 38 * v[i + 16];
    for (let i = 0; i < 16; i++) o[i] = v[i];
    car25519(o);
    car25519(o);
  }
  function inv25519(o, i) {
    const c = gf();
    for (let a = 0; a < 16; a++) c[a] = i[a];
    for (let a = 253; a >= 0; a--) {
      const tmp = gf();
      for (let b = 0; b < 16; b++) tmp[b] = c[b];
      mul(c, c, c);
      if (a !== 2 && a !== 4) mul(c, c, i);
      if (a === 0) for (let b = 0; b < 16; b++) o[b] = tmp[b];
    }
  }
  function curve25519BasePoint(secret) {
    // clamp
    const e = new Uint8Array(32);
    for (let i = 0; i < 32; i++) e[i] = secret[i];
    e[0] &= 248; e[31] &= 127; e[31] |= 64;
    const x1 = gf(), x2 = gf(), z2 = gf(),
          x3 = gf(), z3 = gf();
    const tmp0 = gf(), tmp1 = gf();
    unpack25519(x1, _9);
    for (let i = 0; i < 16; i++) { x2[i] = x1[i]; }
    z2[0] = 1; for (let i = 0; i < 16; i++) x3[i] = 0; z3[0] = 1;
    let swap = 0;
    for (let t = 254; t >= 0; t--) {
      const k_t = (e[t >> 3] >> (t & 7)) & 1;
      swap ^= k_t;
      sel25519(x2, x3, swap);
      sel25519(z2, z3, swap);
      swap = k_t;
      add(tmp0, x3, z3);
      sub(tmp1, x2, z2);
      add(x2, x2, z2);
      sub(z2, x3, z3);
      mul(z3, tmp0, tmp0);
      mul(z2, x2, x2);
      mul(x3, z3, z2);
      sub(tmp0, x2, z3);
      mul(z2, tmp1, tmp0);
      inv25519(tmp1, z2);
      mul(x2, x2, tmp1);
      add(z3, x2, z3);
      mul(z3, z3, tmp1);
      mul(tmp1, tmp0, tmp0);
      sub(tmp0, z3, z2);
      mul(x3, x3, tmp1);
      add(z3, x2, z2);
      mul(x2, tmp0, tmp0);
    }
    sel25519(x2, x3, swap);
    sel25519(z2, z3, swap);
    inv25519(z2, z2);
    mul(x2, x2, z2);
    const out = new Uint8Array(32);
    pack25519(out, x2);
    return out;
  }

  // ---- main parser ----
  function parseConfig(rawText) {
    const errors = [];
    const warnings = [];
    if (typeof rawText !== "string") {
      return { ok: false, errors: ["Config is not text."], warnings, config: null };
    }
    const text = rawText.replace(/\r\n/g, "\n").trim();
    if (!text) {
      return { ok: false, errors: ["Config is empty."], warnings, config: null };
    }

    const lines = text.split("\n");
    const config = { interface: {}, peers: [] };
    let currentSection = null;
    let currentPeer = null;

    for (let i = 0; i < lines.length; i++) {
      const orig = lines[i];
      const lineNo = i + 1;
      let line = orig.trim();
      if (!line || line.startsWith("#") || line.startsWith(";")) continue;

      const sectionMatch = line.match(/^\[(.+)\]$/);
      if (sectionMatch) {
        const name = sectionMatch[1].trim();
        if (name === "Interface") {
          currentSection = "interface";
          currentPeer = null;
        } else if (name === "Peer") {
          currentSection = "peer";
          currentPeer = {};
          config.peers.push(currentPeer);
        } else {
          errors.push(`Line ${lineNo}: Unknown section [${name}] (expected [Interface] or [Peer]).`);
        }
        continue;
      }

      const eq = line.indexOf("=");
      if (eq < 0) {
        errors.push(`Line ${lineNo}: Expected "Key = value" but got "${orig}".`);
        continue;
      }
      const key = line.slice(0, eq).trim();
      const value = line.slice(eq + 1).trim();

      if (currentSection === "interface") {
        if (!ALLOWED_INTERFACE_KEYS.has(key)) {
          errors.push(`Line ${lineNo}: Unknown Interface key "${key}". Allowed: ${[...ALLOWED_INTERFACE_KEYS].join(", ")}.`);
          continue;
        }
        config.interface[key] = value;
      } else if (currentSection === "peer") {
        if (!currentPeer) {
          errors.push(`Line ${lineNo}: Key outside of any [Peer] section.`);
          continue;
        }
        if (!ALLOWED_PEER_KEYS.has(key)) {
          errors.push(`Line ${lineNo}: Unknown Peer key "${key}". Allowed: ${[...ALLOWED_PEER_KEYS].join(", ")}.`);
          continue;
        }
        currentPeer[key] = value;
      } else {
        errors.push(`Line ${lineNo}: Key "${key}" appears before any [Interface] section.`);
      }
    }

    // ---- validation ----
    const iface = config.interface;
    for (const k of REQUIRED_INTERFACE_KEYS) {
      if (!iface[k]) errors.push(`Missing required Interface key: ${k}.`);
    }
    if (iface.PrivateKey && !isValidKey(iface.PrivateKey)) {
      errors.push("Interface PrivateKey is not a valid WG key (must be 44 chars base64).");
    }
    if (iface.Address) {
      const addrs = iface.Address.split(",").map(s => s.trim()).filter(Boolean);
      for (const a of addrs) {
        if (!isCIDR(a) && !isIPv4(a) && !isIPv6(a)) {
          errors.push(`Interface Address "${a}" is not a valid IP/CIDR.`);
        }
      }
    }
    if (iface.DNS) {
      const dns = iface.DNS.split(",").map(s => s.trim()).filter(Boolean);
      for (const d of dns) {
        if (!isIPv4(d) && !isIPv6(d) && !/^[a-z0-9.-]+$/i.test(d)) {
          warnings.push(`Interface DNS "${d}" looks unusual (kept anyway).`);
        }
      }
    }
    if (iface.MTU && !/^\d+$/.test(iface.MTU)) {
      warnings.push(`Interface MTU "${iface.MTU}" should be numeric.`);
    }
    if (iface.ListenPort && !/^\d+$/.test(iface.ListenPort)) {
      warnings.push(`Interface ListenPort "${iface.ListenPort}" should be numeric.`);
    }

    if (config.peers.length === 0) {
      errors.push("Config has no [Peer] section. At least one peer is required.");
    }
    config.peers.forEach((p, idx) => {
      for (const k of REQUIRED_PEER_KEYS) {
        if (!p[k]) errors.push(`Peer ${idx + 1}: missing required key ${k}.`);
      }
      if (p.PublicKey && !isValidKey(p.PublicKey)) {
        errors.push(`Peer ${idx + 1}: PublicKey is not a valid WG key.`);
      }
      if (p.PresharedKey && !isValidKey(p.PresharedKey)) {
        errors.push(`Peer ${idx + 1}: PresharedKey is not a valid WG key.`);
      }
      if (p.Endpoint && !isHostPort(p.Endpoint)) {
        errors.push(`Peer ${idx + 1}: Endpoint "${p.Endpoint}" is not a valid host:port.`);
      }
      if (p.AllowedIPs) {
        const ips = p.AllowedIPs.split(",").map(s => s.trim()).filter(Boolean);
        for (const ip of ips) {
          if (!isCIDR(ip)) errors.push(`Peer ${idx + 1}: AllowedIPs entry "${ip}" is not valid CIDR.`);
        }
      }
      if (p.PersistentKeepalive && !/^\d+$/.test(p.PersistentKeepalive)) {
        warnings.push(`Peer ${idx + 1}: PersistentKeepalive should be numeric.`);
      }
    });

    // Derived info
    config.name = guessName(iface, config.peers[0]);
    config.publicKey = iface.PrivateKey && isValidKey(iface.PrivateKey)
      ? derivePublicKey(iface.PrivateKey) : null;
    config.allTraffic = !!(config.peers[0] && /0\.0\.0\.0\/0/.test(config.peers[0].AllowedIPs));
    config.host = config.peers[0] ? extractHost(config.peers[0].Endpoint) : null;

    const ok = errors.length === 0;
    return { ok, errors, warnings, config };
  }

  function guessName(iface, peer) {
    if (iface && iface.Address) {
      const a = iface.Address.split(",")[0].trim().split("/")[0];
      if (a) return "wg-" + a;
    }
    if (peer && peer.Endpoint) {
      return "wg-" + extractHost(peer.Endpoint);
    }
    return "wg-profile";
  }

  function serializeConfig(config) {
    const out = [];
    out.push("[Interface]");
    for (const [k, v] of Object.entries(config.interface)) {
      out.push(`${k} = ${v}`);
    }
    for (const p of config.peers) {
      out.push("");
      out.push("[Peer]");
      for (const [k, v] of Object.entries(p)) {
        out.push(`${k} = ${v}`);
      }
    }
    return out.join("\n") + "\n";
  }

  global.TarnParser = {
    parseConfig, serializeConfig, derivePublicKey,
    isValidKey, isCIDR, isHostPort, isIPv4, isIPv6
  };
})(typeof self !== "undefined" ? self : this);
