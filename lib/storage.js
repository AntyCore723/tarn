// lib/storage.js — profile storage, settings, stats, packet filter (chrome.storage.local)
// SPDX-License-Identifier: GPL-3.0-only

(function (global) {
  "use strict";

  const KEY_PROFILES = "tarn.profiles";
  const KEY_ACTIVE = "tarn.activeId";
  const KEY_SETTINGS = "tarn.settings";
  const KEY_STATS = "tarn.stats";
  const KEY_STATE = "tarn.state";
  const KEY_DPI_STATE = "tarn.dpiState";
  const KEY_DPI_SETTINGS = "tarn.dpiSettings";
  const KEY_MIGRATED = "tarn.migrated";

  const DEFAULT_SETTINGS = {
    theme: "dark",
    mode: "native",
    nativeHostName: "com.tarn.host",
    socksHost: "127.0.0.1",
    socksPort: 1080,
    autoConnect: false,
    killSwitch: false,
    webrtcProtection: true,
    disableQuic: true,
    verifyIp: true,
    // NOTE: chrome.proxy fixed_servers bypassList does NOT support CIDR and
    // <local> covers loopback + localhost; private ranges are bypassed via
    // PAC when split tunneling is on. CIDR entries here were dead weight.
    bypassList: ["localhost", "127.0.0.1", "::1", "<local>"],
    splitTunneling: false,
    splitMode: "include",
    splitDomains: [],
    statsEnabled: true
  };

  const DEFAULT_DPI_SETTINGS = {
    dpiEnabled: false,
    dpiStrategy: "auto",
    dpiCustomDomains: [],
    dpiExcludedDomains: [],
    dpiProbeHosts: [],
    dpiBlockQuic: true,
    dpiForceDoh: true,
    dpiStripHeaders: true,
    dpiStripHeadersList: ["alt-svc", "Alt-Svc", "server", "Server", "x-powered-by", "X-Powered-By"],
    dpiGameFilter: true,
    dpiAdBlock: true,
    dpiAdguardDns: true,
    dpiAntiTrack: true,
    dpiAutoStartWithWg: false
  };

  const DEFAULT_DPI_STATE = {
    dpiActive: false,
    dpiStarting: false,
    dpiStrategy: null,
    dpiVerified: false,
    dpiProcessPid: null,
    dpiDoHActive: false,
    dpiHeadersStripped: false,
    dpiError: null,
    dpiTimestamp: null,
    dpiFilesSetup: false,
    dpiCachedStrategy: null
  };

  function uid() {
    return "p_" + Date.now().toString(36) + "_" + Math.random().toString(36).slice(2, 8);
  }

  // ---- input sanitizers (used by save* and importAll) ----
  // Every value that crosses the storage boundary (UI fields, backup files,
  // message payloads) is whitelisted here: a crafted backup file must never
  // be able to inject HTML into the extension pages or redirect the proxy
  // (socksHost) to an attacker-controlled machine.

  const SAFE_PROFILE_ID = /^[a-z0-9_-]{1,64}$/;

  function _str(v, max) {
    return (typeof v === "string" ? v : v == null ? "" : String(v)).slice(0, max || 4096);
  }
  function _num(v, min, max, def) {
    const n = (typeof v === "number" && Number.isFinite(v)) ? v : (typeof v === "string" && v.trim() !== "" ? Number(v) : NaN);
    if (!Number.isFinite(n)) return def;
    return Math.min(max, Math.max(min, Math.round(n)));
  }
  function _bool(v) { return v === true || v === false ? v : Boolean(v); }
  function _strArray(v, maxItems, maxLen) {
    if (!Array.isArray(v)) return undefined;
    const out = v.filter(x => typeof x === "string" && x.length <= (maxLen || 256));
    return out.slice(0, maxItems || 100);
  }

  const SETTINGS_RULES = {
    theme: v => _str(v, 64),
    mode: v => _str(v, 64),
    // Fixed registered native-messaging host name only: a crafted backup
    // must never redirect the extension to a different preinstalled host.
    nativeHostName: v => (v === "com.tarn.host") ? v : undefined,
    // Loopback only: a backup/message must never point the proxy elsewhere.
    socksHost: v => (v === "localhost" || v === "127.0.0.1" || v === "::1") ? v : undefined,
    socksPort: v => _num(v, 1, 65535, undefined),
    autoConnect: _bool,
    killSwitch: _bool,
    webrtcProtection: _bool,
    disableQuic: _bool,
    verifyIp: _bool,
    bypassList: v => _strArray(v, 50, 256),
    splitTunneling: _bool,
    splitMode: v => (v === "include" || v === "exclude") ? v : undefined,
    splitDomains: v => _strArray(v, 100, 256),
    statsEnabled: _bool
  };

  const DPI_SETTINGS_RULES = {
    dpiEnabled: _bool,
    dpiStrategy: v => _str(v, 64),
    dpiCustomDomains: v => _strArray(v, 200, 256),
    // Domains the bypass must never touch: consumed by the native host as
    // --hostlist-exclude/--ipset-exclude. Same plain-hostname whitelist.
    dpiExcludedDomains: v => _strArray(v, 200, 256),
    // Probe targets for the strategy test battery. Whitelisted to plain DNS
    // hostnames only: no schemes, ports, paths or IDN (mirrors the native
    // side sanitizer). Empty = native defaults.
    dpiProbeHosts: v => {
      if (!Array.isArray(v)) return undefined;
      const out = [];
      for (const x of v) {
        if (typeof x !== "string") continue;
        const h = x.trim().toLowerCase().replace(/\.$/, "");
        if (h.length > 253 || !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(h)) continue;
        out.push(h);
      }
      return out.slice(0, 16);
    },
    dpiBlockQuic: _bool,
    dpiForceDoh: _bool,
    dpiStripHeaders: _bool,
    dpiStripHeadersList: v => _strArray(v, 50, 256),
    dpiGameFilter: _bool,
    dpiAdBlock: _bool,
    dpiAdguardDns: _bool,
    dpiAntiTrack: _bool,
    dpiAutoStartWithWg: _bool
  };

  function _sanitizeParsed(raw) {
    if (!raw || typeof raw !== "object") return undefined;
    const out = {};
    for (const k of ["name", "host", "publicKey"]) if (k in raw) out[k] = _str(raw[k], 4096);
    if (typeof raw.allTraffic === "boolean") out.allTraffic = raw.allTraffic;
    if (Array.isArray(raw.errors)) out.errors = raw.errors.filter(x => typeof x === "string").slice(0, 20).map(x => x.slice(0, 500));
    if (Array.isArray(raw.warnings)) out.warnings = raw.warnings.filter(x => typeof x === "string").slice(0, 20).map(x => x.slice(0, 500));
    if (raw.interface && typeof raw.interface === "object") {
      const itf = {};
      for (const [k, v] of Object.entries(raw.interface)) {
        if (typeof v === "string") itf[k] = v.slice(0, 4096);
        else if (typeof v === "number" && Number.isFinite(v)) itf[k] = v;
        else if (typeof v === "boolean") itf[k] = v;
      }
      out.interface = itf;
    }
    if (Array.isArray(raw.peers)) {
      out.peers = raw.peers.map(p => {
        if (!p || typeof p !== "object") return null;
        const peer = {};
        for (const [k, v] of Object.entries(p)) {
          if (typeof v === "string") peer[k] = v.slice(0, 4096);
          else if (typeof v === "number" && Number.isFinite(v)) peer[k] = v;
          else if (typeof v === "boolean") peer[k] = v;
        }
        return peer;
      }).filter(Boolean).slice(0, 10);
    }
    return out;
  }

  function _sanitizeProfile(raw) {
    if (!raw || typeof raw !== "object") return null;
    return {
      id: SAFE_PROFILE_ID.test(raw.id) ? raw.id : uid(),
      name: _str(raw.name, 200) || "WG profile",
      rawText: _str(raw.rawText, 1024 * 1024),
      parsed: _sanitizeParsed(raw.parsed),
      createdAt: _num(raw.createdAt, 0, Date.now(), Date.now()),
      updatedAt: _num(raw.updatedAt, 0, Date.now(), Date.now()),
      lastUsed: _num(raw.lastUsed, 0, Number.MAX_SAFE_INTEGER, 0),
      connects: _num(raw.connects, 0, Number.MAX_SAFE_INTEGER, 0)
    };
  }

  async function getProfiles() {
    const r = await chrome.storage.local.get(KEY_PROFILES);
    return r[KEY_PROFILES] || [];
  }
  async function saveProfiles(list) {
    await chrome.storage.local.set({ [KEY_PROFILES]: list });
  }
  async function getProfile(id) {
    const list = await getProfiles();
    return list.find(p => p.id === id) || null;
  }
  async function addProfile({ name, rawText, parsed }) {
    const list = await getProfiles();
    const profile = {
      id: uid(),
      name: name || (parsed && parsed.name) || "WG profile",
      rawText,
      parsed,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      lastUsed: 0,
      connects: 0
    };
    list.push(profile);
    await saveProfiles(list);
    return profile;
  }
  async function updateProfile(id, patch) {
    const list = await getProfiles();
    const idx = list.findIndex(p => p.id === id);
    if (idx < 0) return null;
    list[idx] = { ...list[idx], ...patch, updatedAt: Date.now() };
    await saveProfiles(list);
    return list[idx];
  }
  async function deleteProfile(id) {
    const list = await getProfiles();
    const next = list.filter(p => p.id !== id);
    await saveProfiles(next);
    const active = await getActiveId();
    if (active === id) await setActiveId(null);
    return next;
  }
  async function getActiveId() {
    const r = await chrome.storage.local.get(KEY_ACTIVE);
    return r[KEY_ACTIVE] || null;
  }
  async function setActiveId(id) {
    if (id) await chrome.storage.local.set({ [KEY_ACTIVE]: id });
    else await chrome.storage.local.remove(KEY_ACTIVE);
  }
  async function getSettings() {
    const r = await chrome.storage.local.get(KEY_SETTINGS);
    return { ...DEFAULT_SETTINGS, ...(r[KEY_SETTINGS] || {}) };
  }
  async function saveSettings(patch) {
    const cur = await getSettings();
    const next = { ...cur };
    if (patch && typeof patch === "object") {
      for (const [k, rule] of Object.entries(SETTINGS_RULES)) {
        if (k in patch) {
          const val = rule(patch[k]);
          if (val !== undefined) next[k] = val;
        }
      }
    }
    await chrome.storage.local.set({ [KEY_SETTINGS]: next });
    return next;
  }
  async function getStats() {
    const r = await chrome.storage.local.get(KEY_STATS);
    return r[KEY_STATS] || { up: 0, down: 0, connectedAt: 0, handshakes: 0, lastHandshake: 0, sessions: [] };
  }
  async function saveStats(stats) {
    await chrome.storage.local.set({ [KEY_STATS]: stats });
  }
  async function recordSession(start, end, up, down, profileId, profileName) {
    const stats = await getStats();
    stats.up += up || 0;
    stats.down += down || 0;
    stats.sessions = stats.sessions || [];
    stats.sessions.unshift({ start, end, up, down, profileId, profileName });
    stats.sessions = stats.sessions.slice(0, 50);
    await saveStats(stats);
  }
  async function resetStats() {
    await chrome.storage.local.set({ [KEY_STATS]: { up: 0, down: 0, connectedAt: 0, handshakes: 0, lastHandshake: 0, sessions: [] } });
  }
  async function getState() {
    const r = await chrome.storage.local.get(KEY_STATE);
    return r[KEY_STATE] || { status: "disconnected", profileId: null, error: "", socksAddr: "", since: 0 };
  }
  async function saveState(state) {
    await chrome.storage.local.set({ [KEY_STATE]: state });
  }

  async function getDpiSettings() {
    const r = await chrome.storage.local.get(KEY_DPI_SETTINGS);
    return { ...DEFAULT_DPI_SETTINGS, ...(r[KEY_DPI_SETTINGS] || {}) };
  }
  async function saveDpiSettings(patch) {
    const cur = await getDpiSettings();
    const next = { ...cur };
    if (patch && typeof patch === "object") {
      for (const [k, rule] of Object.entries(DPI_SETTINGS_RULES)) {
        if (k in patch) {
          const val = rule(patch[k]);
          if (val !== undefined) next[k] = val;
        }
      }
    }
    await chrome.storage.local.set({ [KEY_DPI_SETTINGS]: next });
    return next;
  }
  async function resetDpiSettings() {
    await chrome.storage.local.set({ [KEY_DPI_SETTINGS]: DEFAULT_DPI_SETTINGS });
    return DEFAULT_DPI_SETTINGS;
  }
  async function getDpiState() {
    const r = await chrome.storage.local.get(KEY_DPI_STATE);
    return { ...DEFAULT_DPI_STATE, ...(r[KEY_DPI_STATE] || {}) };
  }
  async function saveDpiState(patch) {
    const cur = await getDpiState();
    const next = { ...cur, ...patch };
    await chrome.storage.local.set({ [KEY_DPI_STATE]: next });
    return next;
  }
  async function resetDpiState() {
    await chrome.storage.local.set({ [KEY_DPI_STATE]: DEFAULT_DPI_STATE });
    return DEFAULT_DPI_STATE;
  }

  // ---- one-time legacy-key migration (WGG -> Tarn) ----
  // v1.10.0 renamed every storage key from the "wg.*" namespace to "tarn.*".
  // On first run after upgrade the old values are copied over so existing
  // profiles/settings/stats survive without user action. Idempotent and
  // gated by KEY_MIGRATED; safe to call from multiple entry points at once.

  const LEGACY_KEY_PAIRS = [
    ["wg.profiles", KEY_PROFILES],
    ["wg.activeId", KEY_ACTIVE],
    ["wg.settings", KEY_SETTINGS],
    ["wg.stats", KEY_STATS],
    ["wg.state", KEY_STATE],
    ["wg.dpiState", KEY_DPI_STATE],
    ["wg.dpiSettings", KEY_DPI_SETTINGS],
    ["wg.lang", "tarn.lang"],
    ["wg.gameStar", "tarn.gameStar"],
    ["wg.gameHighScore", "tarn.gameHighScore"],
    ["wg.dpiTestResult", "tarn.dpiTestResult"],
    ["wg.dpiTestLog", "tarn.dpiTestLog"],
    ["wg.lastNativeError", "tarn.lastNativeError"],
    ["wg.activeTab", "tarn.activeTab"],
    ["wg.welcomeSeen", "tarn.welcomeSeen"]
  ];

  async function migrateLegacy() {
    const flag = await chrome.storage.local.get(KEY_MIGRATED);
    if (flag[KEY_MIGRATED]) return;
    const legacyKeys = LEGACY_KEY_PAIRS.map(p => p[0]);
    const legacy = await chrome.storage.local.get(legacyKeys);
    const toSet = {};
    let found = false;
    for (const [oldK, newK] of LEGACY_KEY_PAIRS) {
      if (legacy[oldK] !== undefined && legacy[oldK] !== null) {
        toSet[newK] = legacy[oldK];
        found = true;
      }
    }
    if (found) {
      // Force the new registered host name: a migrated settings blob must
      // never keep pointing the extension at the old host.
      if (toSet[KEY_SETTINGS] && typeof toSet[KEY_SETTINGS] === "object") {
        toSet[KEY_SETTINGS].nativeHostName = "com.tarn.host";
      }
      await chrome.storage.local.set(toSet);
    }
    await chrome.storage.local.set({ [KEY_MIGRATED]: true });
  }

  async function exportAll() {
    const [profiles, settings, stats, dpiSettings, dpiState] = await Promise.all([
      getProfiles(), getSettings(), getStats(), getDpiSettings(), getDpiState()
    ]);
    return {
      app: "tarn-tunnel-manager",
      version: 2,
      exportedAt: new Date().toISOString(),
      profiles,
      settings,
      stats,
      dpiSettings,
      dpiState
    };
  }
  async function importAll(data) {
    if (!data || !["tarn-tunnel-manager", "wgg-tunnel-manager", "wireguard-tunnel-manager"].includes(data.app)) {
      throw new Error("Invalid backup file");
    }
    // One-time migration: normalize any legacy app key to the current name
    if (data.app !== "tarn-tunnel-manager") {
      data.app = "tarn-tunnel-manager";
    }
    if (Array.isArray(data.profiles)) {
      const profiles = data.profiles.map(_sanitizeProfile).filter(Boolean);
      await saveProfiles(profiles);
    }
    if (data.settings) await saveSettings(data.settings);
    if (data.stats && typeof data.stats === "object") {
      const stats = {
        up: _num(data.stats.up, 0, Number.MAX_SAFE_INTEGER, 0),
        down: _num(data.stats.down, 0, Number.MAX_SAFE_INTEGER, 0),
        connectedAt: _num(data.stats.connectedAt, 0, Date.now(), 0),
        handshakes: _num(data.stats.handshakes, 0, Number.MAX_SAFE_INTEGER, 0),
        lastHandshake: _num(data.stats.lastHandshake, 0, Date.now(), 0),
        sessions: []
      };
      if (Array.isArray(data.stats.sessions)) {
        stats.sessions = data.stats.sessions.map(s => {
          if (!s || typeof s !== "object") return null;
          return {
            start: _num(s.start, 0, Date.now(), 0),
            end: _num(s.end, 0, Date.now(), 0),
            up: _num(s.up, 0, Number.MAX_SAFE_INTEGER, 0),
            down: _num(s.down, 0, Number.MAX_SAFE_INTEGER, 0),
            profileId: _str(s.profileId, 128),
            profileName: _str(s.profileName, 200)
          };
        }).filter(Boolean).slice(0, 50);
      }
      await saveStats(stats);
    }
    if (data.dpiSettings) await saveDpiSettings(data.dpiSettings);
    if (data.dpiState && typeof data.dpiState === "object") {
      const st = {};
      for (const [k, v] of Object.entries(data.dpiState)) {
        if (typeof v === "boolean") st[k] = v;
        else if (typeof v === "string") st[k] = v.slice(0, 1024);
        else if (typeof v === "number" && Number.isFinite(v)) st[k] = v;
        else if (v === null) st[k] = null;
      }
      await saveDpiState(st);
    }
    return true;
  }

  global.TarnStorage = {
    DEFAULT_SETTINGS,
    DEFAULT_DPI_SETTINGS,
    DEFAULT_DPI_STATE,
    getProfiles, saveProfiles, getProfile, addProfile, updateProfile, deleteProfile,
    getActiveId, setActiveId,
    getSettings, saveSettings,
    getStats, saveStats, recordSession, resetStats,
    getState, saveState,
    getDpiSettings, saveDpiSettings, resetDpiSettings,
    getDpiState, saveDpiState, resetDpiState,
    migrateLegacy,
    exportAll, importAll
  };
})(typeof self !== "undefined" ? self : this);
