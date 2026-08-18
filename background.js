// background.js — service worker v3 (no simulation, real tunnel only)
// SPDX-License-Identifier: GPL-3.0-only
//
// ══════════════════════════════════════════════════════════════════════════════
// MV3 SERVICE WORKER LIFECYCLE — CRITICAL ARCHITECTURE NOTES
// ══════════════════════════════════════════════════════════════════════════════
//
// Chrome MV3 service workers (SW) are NOT persistent. Chrome can terminate and
// restart the SW at any time — typically after ~30 seconds of inactivity, but
// also under memory pressure, during updates, or unpredictably.
//
// IMPLICATIONS FOR Tarn:
// 1. All in-memory state (nativePort, stopping, activeProfile) is LOST on restart.
// 2. chrome.proxy.settings are RESET — the browser stops using the SOCKS5 proxy.
// 3. chrome.runtime.connectNative() port references become INVALID.
// 4. The native host process (tarn_host.py) is a SEPARATE OS process and
//    SURVIVES SW restart — but the SW loses its port reference to it.
// 5. Pending async operations (await ...) are KILLED mid-execution when the SW
//    terminates. Only code before the first await in any function has run
//    guaranteed to complete.
//
// This creates four critical race conditions that this file carefully guards:
//
// RACE 1: handleNativeError vs disconnect()
//   Tunnel drops → onDisconnect → handleNativeError() starts async work →
//   USER CLICKS DISCONNECT during async gap → disconnect() sets state to
//   "disconnected" → handleNativeError resumes and OVERWRITES with "error".
//   FIX: handleNativeError checks `if (stopping) return;` after every await.
//
// RACE 2: Startup IIFE phantom reconnect
//   Tunnel drops → onDisconnect starts async cleanup → SW is KILLED during
//   yield → state in storage is still "connected" → SW restarts → IIFE sees
//   "connected" → tries to reconnect to broken tunnel → PHANTOM CONNECTION
//   with real IP exposed.
//   FIX: On SW restart (not browser restart), IIFE ALWAYS forces state to
//   "disconnected". A _browserRestart flag distinguishes browser restart from
//   SW restart.
//
// RACE 3: onStartup vs IIFE (browser restart)
//   Browser restart → onStartup AND IIFE run concurrently. onStartup wants
//   to auto-reconnect if autoConnect is enabled. IIFE wants to force-disconnect
//   on SW restart. If IIFE runs before onStartup, it force-disconnects and
//   autoConnect fails to trigger.
//   FIX: onStartup sets _browserRestart=true first. IIFE checks this flag —
//   if true, it's a browser restart and IIFE skips the force-disconnect.
//   KNOWN LIMITATION: If IIFE's async work resolves before onStartup fires
//   (extremely rare), the flag won't be set yet and IIFE will force-disconnect.
//   This is a benign race — worst case is autoConnect doesn't trigger and
//   the user must manually reconnect. This is preferred over the alternative
//   (phantom reconnect on a broken tunnel, which is a SECURITY issue).
//
// RACE 4: onDisconnect stale handler vs new connect()
//   Tunnel drops → onDisconnect starts async cleanup (multiple awaits) →
//   User clicks Disconnect → then clicks Connect → connect() resets stopping,
//   creates new nativePort → onDisconnect RESUMES from yield → checks !stopping
//   → TRUE (reset by connect!) → calls handleNativeError(oldProfile) →
//   overwrites new "connecting" state with "error" for old profile.
//   FIX: onDisconnect checks port.__stale AND nativePort identity after EVERY
//   await. If nativePort has changed (new connection), handler bails out.
//
// RACE 5: Stale onMessage handler vs new connect()
//   Broken tunnel → old port onMessage("error") → settled=true → handleNativeError
//   → user clicks Disconnect → user clicks Connect (working) → stopping=false,
//   startNative() → nativePort=newPort → OLD port receives DELAYED "error" →
//   onMessage → settled=true → handleNativeError(oldProfile) → checks stopping
//   → false (reset by connect!) → setState("error") OVERWRITES "connecting"!
//   → user sees "error" flash for ~2 seconds → then "connected" arrives.
//   FIX: onMessage checks nativePort === port at entry. If port was replaced,
//   all messages from the old port are silently ignored.
//
// ══════════════════════════════════════════════════════════════════════════════
// GLOBAL STATE VARIABLES
// ══════════════════════════════════════════════════════════════════════════════
//
// nativePort — Chrome native messaging port. Set to the ACTIVE port in
//   startNative(). Set to null in onDisconnect and disconnect(). On SW restart
//   this is always null (in-memory reference lost). If non-null after a yield,
//   it means a new connection was established during that yield.
//
// stopping — boolean flag. Set to true by disconnect() and during old-port
//   cleanup in connect(). Reset to false at the start of connect(). Checked
//   by onDisconnect to decide whether to call handleNativeError, and by
//   handleNativeError itself (after async gap) to avoid overwriting user state.
//   LIFECYCLE: false → true (disconnect) → false (next connect)
//
// activeProfile — reference to the currently active TarnStorage profile object.
//   Set in connect(), cleared in disconnect(). Used for IP verification and
//   session recording.
//
// __stale (per-port) — set on old nativePort by connect() when replacing the
//   port. Checked at entry and after every yield in onDisconnect handler.
//   Ensures the old port's cleanup handler doesn't interfere with a new
//   connection. IMPORTANT: If the old onDisconnect has already STARTED before
//   connect() runs, the initial check has passed — which is why we re-check
//   __stale after every yield in onDisconnect.
//
// ══════════════════════════════════════════════════════════════════════════════

importScripts("lib/parser.js", "lib/storage.js", "lib/proxy.js", "lib/i18n.js", "lib/adblock.js");

const NATIVE_HOST_DEFAULT = "com.tarn.host";

let nativePort = null;
let stopping = false;
let _connectInFlight = false;
// DPI op guard: start/stop must not interleave native ports (a stacked
// start_dpi would launch a second winws instance). A stop CANCELS an
// in-flight start by disconnecting its port — the host kills the DPI
// process on stdin EOF.
let _dpiOpInFlight = false;
let _dpiStartPort = null;
let _dpiTestPort = null;
let lastNativeError = "";
let nativeAvailable = null;
let wireproxyAvailable = false;
let activeProfile = null;
let dpiProcessActive = false;

// ══════════════════════════════════════════════════════════════════════════════
// Native messaging error mapping & safe-connect wrapper.
//
// In MV3, chrome.runtime.connectNative() returns a Port synchronously, but
// the actual host startup is async. The error (host not found / origin
// forbidden / host crashed) arrives via port.onDisconnect, populated in
// chrome.runtime.lastError.message. IF your onDisconnect listener does not
// READ chrome.runtime.lastError.message, Chrome prints
//   "Unchecked runtime.lastError while running port.onDisconnect"
// to the SW console — this is the noisy warning users see in
// chrome://extensions "Errors" section.
//
// mapNativeError() converts Chrome's generic phrasing into a user-visible
// sentence so popup/options can display actionable guidance.
// ══════════════════════════════════════════════════════════════════════════════
const NATIVE_ERR_MAP = {
  "Access to the specified native messaging host is forbidden":
    "Native host installed but extension ID mismatch. Re-run install.bat from this folder.",
  "Specified native messaging host not found":
    "Native host not registered. Run install.bat from this folder (double-click).",
  "Native host has exited":
    "Native host crashed. See ~/.tarn-tunnel/host.log for details.",
  "Failed to start native messaging host":
    "Could not start Python host. Install Python 3 and add it to PATH.",
};

function mapNativeError(err) {
  if (!err) return "Native host disconnected (unknown reason).";
  for (const [k, v] of Object.entries(NATIVE_ERR_MAP)) {
    if (err.startsWith(k) || err.includes(k)) return v;
  }
  return err;
}

// Wrap chrome.runtime.connectNative() to consistently read lastError on
// disconnect, persisting it to chrome.storage.local so the popup can
// surface actionable guidance even after a SW restart.
// ── chrome.runtime.onInstalled ──
// Fires on: first install ("install") or extension update ("update").
// On "install": initialize clean state, clear all proxy rules, open welcome page.
// On "update": DO NOT reset connected state — the tunnel may be active.
//   Only clear stale kill switch rules if not connected (they shouldn't exist
//   if the tunnel was properly disconnected, but crashes can leave them).
chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === "install") {
    await TarnStorage.saveState({
      status: "disconnected", profileId: null, error: "",
      socksAddr: "", since: 0, backend: "none", publicIp: null
    });
    await clearAllProxies();
    await TarnProxy.clearQuicBlock();
    await TarnProxy.clearKillSwitch();
    await chrome.tabs.create({ url: chrome.runtime.getURL("options.html?welcome=1") });
  } else if (details.reason === "update") {
    // On extension update: don't reset connected state — just ensure DPI badge is correct
    const state = await TarnStorage.getState();
    if (state.status !== "connected") {
      await TarnProxy.clearKillSwitch();
    }
  }
});

// ── chrome.runtime.onStartup ──
// Fires ONLY on BROWSER restart (not on SW restart within the same session).
// This is the only place where autoConnect is handled.
//
// RACE WITH STARTUP IIFE (RACE 3 from module header):
// Both onStartup and the startup IIFE run when the browser restarts.
// They execute concurrently with no guaranteed order:
//
// SCENARIO A (normal): onStartup fires first
//   1. onStartup: sets _browserRestart=true → reads state → autoConnect → connect()
//   2. IIFE: reads _browserRestart → true → clears flag → skips force-disconnect ✓
//
// SCENARIO B (rare): IIFE fires first, onStartup fires during IIFE's await
//   1. IIFE: await pingNative() → YIELDS
//   2. onStartup: sets _browserRestart=true → autoConnect → connect()
//   3. IIFE resumes: reads _browserRestart → true → skips force-disconnect ✓
//
// SCENARIO C (extremely rare pathological case):
//   1. IIFE: await pingNative() resolves before onStartup fires
//   2. IIFE: reads _browserRestart → FALSE (not set yet!) → force-disconnects
//   3. onStartup fires: state is now "disconnected" → autoConnect check:
//      state.status === "connected" → false → DOES NOT reconnect
//   Result: tunnel is disconnected, user must manually reconnect.
//   This is a BENIGN race — preferred over the alternative (phantom reconnect
//   on a broken tunnel = SECURITY issue). In practice, pingNative() involves
//   native messaging I/O that always yields long enough for onStartup to fire.
//
// autoConnect logic:
//   Only reconnects if state was "connected" before browser restart. This means
//   the tunnel was working when Chrome was closed. The native host is dead
//   (killed with Chrome), so we need to reconnect from scratch. We do NOT
//   reconnect if state was "error" or "disconnected" — the user intentionally
//   disconnected or the tunnel was broken.
chrome.runtime.onStartup.addListener(async () => {
  // Set flag so the startup IIFE knows this is a browser restart (not just SW
  // restart) and should NOT force-disconnect the tunnel. This flag is the ONLY
  // mechanism that distinguishes browser restart from SW restart in the IIFE.
  // It is set before any async work to maximize the chance the IIFE sees it.
  await chrome.storage.local.set({ _browserRestart: true });
  await TarnProxy.clearQuicBlock();
  await TarnProxy.clearKillSwitch();
  const settings = await TarnStorage.getSettings();
  const state = await TarnStorage.getState();
  if (settings.autoConnect) {
    // Only reconnect if tunnel was WORKING (status="connected") before restart.
    // If status was "error" or "disconnected", don't auto-reconnect —
    // the tunnel was broken or user had manually disconnected.
    if (state.status === "connected" && state.profileId) {
      try { await connect(state.profileId); } catch (e) {/* ignore */}
    } else if (state.status === "connected" || state.status === "reconnecting") {
      // autoConnect is on but there is nothing to reconnect to. The native
      // host is dead (killed with Chrome) — clear the phantom state so the
      // badge/UI never claim "ON" with a dead tunnel.
      await setState({
        status: "disconnected", profileId: null, error: "",
        socksAddr: "", since: 0, backend: "none", publicIp: null
      });
    }
  } else if (state.status === "connected" || state.status === "reconnecting") {
    // autoConnect is off: the tunnel cannot survive a browser restart, so the
    // stored "connected" is stale. Reset it — otherwise the badge shows "ON"
    // while the user browses with a real IP (phantom connected state).
    await setState({
      status: "disconnected", profileId: null, error: "",
      socksAddr: "", since: 0, backend: "none", publicIp: null
    });
  }
});

// ---- keyboard commands ----
// Manifest "commands": Ctrl+Shift+G opens the popup, Ctrl+Shift+D toggles
// the tunnel for the most recently used profile (no popup needed).
chrome.commands.onCommand.addListener(async (command) => {
  try {
    if (command === "open-popup") {
      await chrome.action.openPopup();
    } else if (command === "toggle-connect") {
      const st = await TarnStorage.getState();
      if (st.status === "connected" || st.status === "connecting") {
        await disconnect();
      } else {
        const profiles = await TarnStorage.getProfiles();
        if (profiles && profiles.length) {
          const last = [...profiles].sort((a, b) => (b.lastUsed || 0) - (a.lastUsed || 0))[0];
          await connect(last.id);
        }
      }
    }
  } catch (e) {
    // Best-effort (e.g. openPopup() can be denied without a user gesture).
  }
});

// ---- message router ----
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.type) return false;
  // Only accept messages from our own extension pages / content scripts.
  // External pages and third-party extensions can never reach us: no
  // externally_connectable, no onMessageExternal/onConnectExternal. This
  // check is defense-in-depth on top of that.
  if (sender.id && sender.id !== chrome.runtime.id) return false;
  // NOTE: ANTITRACK_SYNC from content script is acknowledged but NOT acted on.
  // The background's own storage.onChanged listener (inside the antitrack IIFE)
  // handles the sync. This avoids a scoping bug where antitrackSyncTabs() would
  // not be accessible from here (it's defined inside the IIFE).
  if (msg.type === "ANTITRACK_SYNC") {
    sendResponse({ ok: true });
    return;
  }
  (async () => {
    try {
      switch (msg.type) {
        case "GET_STATE": {
          // Re-ping whenever the host is not CONFIRMED available (never just
          // when nativeAvailable === null). A single failed ping - e.g. the
          // popup/extension loaded while install.bat was still writing the
          // registry, or Chrome restarted mid-install - must not poison the
          // SW's state for its whole lifetime. Every popup open re-verifies,
          // so "tunnel unavailable" self-heals seconds after the install
          // completes, regardless of install/load order.
          if (nativeAvailable !== true) {
            try {
              const r = await pingNative();
              nativeAvailable = r.available;
              wireproxyAvailable = r.wireproxyAvailable;
            } catch (e) {}
          }
          const state = await TarnStorage.getState();
          // Self-heal the badge on every popup open: recompute it from
          // persisted state so any update missed while the SW was dead or
          // racing is repaired immediately.
          updateBadge(state.status, state._tunnelAlive);
          try {
            const dpi = await TarnStorage.getDpiState();
            updateDpiBadge(dpi.dpiStarting ? "starting" : (dpi.dpiActive ? "active" : "off"));
          } catch (e) {}
          sendResponse({ ok: true, state, nativeAvailable, wireproxyAvailable });
          break;
        }
        case "CONNECT": {
          const r = await connect(msg.profileId);
          sendResponse(r);
          break;
        }
        case "DISCONNECT": {
          const r = await disconnect();
          sendResponse(r);
          break;
        }
        case "PING_NATIVE": {
          const r = await pingNative();
          sendResponse(r);
          break;
        }
        case "CHECK_WIREPROXY": {
          const r = await checkWireproxy();
          sendResponse(r);
          break;
        }
        case "GET_PROFILES": {
          const profiles = await TarnStorage.getProfiles();
          const activeId = await TarnStorage.getActiveId();
          sendResponse({ ok: true, profiles, activeId });
          break;
        }
        case "GET_STATS": {
          const stats = await TarnStorage.getStats();
          sendResponse({ ok: true, stats });
          break;
        }
        case "RESET_STATS": {
          await TarnStorage.resetStats();
          sendResponse({ ok: true });
          break;
        }
        case "GET_SETTINGS": {
          const settings = await TarnStorage.getSettings();
          sendResponse({ ok: true, settings });
          break;
        }
        case "SAVE_SETTINGS": {
          const settings = await TarnStorage.saveSettings(msg.patch || {});
          sendResponse({ ok: true, settings });
          break;
        }
        case "CHECK_IP": {
          const ip = await fetchPublicIp();
          sendResponse({ ok: true, ip });
          break;
        }
        case "DPI_START": {
          const r = await dpiStart();
          sendResponse(r);
          break;
        }
        case "DPI_STOP": {
          const r = await dpiStop();
          sendResponse(r);
          break;
        }
        case "DPI_STATUS": {
          const r = await dpiQueryStatus();
          sendResponse(r);
          break;
        }
        case "DPI_LIST_STRATEGIES": {
          const r = await dpiListStrategies();
          sendResponse(r);
          break;
        }
        case "DPI_TEST_STRATEGIES": {
          const r = await dpiTestStrategies(msg.opts || {});
          sendResponse(r);
          break;
        }
        case "DPI_TEST_CONTROL": {
          const r = await dpiTestControl(msg.action || "cancel");
          sendResponse(r);
          break;
        }
        case "DPI_DIAGNOSTICS": {
          const r = await dpiDiagnostics();
          sendResponse(r);
          break;
        }
        case "ADBLOCK_SET": {
          // (Re)apply the ad blocker from the saved DPI settings. Also used
          // by the options page right after saving the toggle.
          await applyAdBlockSetting();
          sendResponse({ ok: true });
          break;
        }
        default:
          sendResponse({ ok: false, error: "unknown message type" });
      }
    } catch (e) {
      sendResponse({ ok: false, error: String(e && e.message || e) });
    }
  })();
  return true;
});

// ── Keepalive alarm (MV3) ──
// Chrome kills idle MV3 service workers after ~30 seconds. These alarms
// keep the SW alive while the tunnel is active, and provide periodic
// data collection:
//
// tarn-keepalive (every 30s): Sends "ping" to native host to keep both the
//   native messaging channel and the SW alive. Also triggers IP check.
//   Only sends if nativePort exists AND is in "connected" state.
//
// tarn-stats (every 3s): Requests tx/rx bytes, latency, handshake info
//   from native host. Only sends if connected.
//
// tarn-ipcheck (every 1 min): Checks public IP through the tunnel to verify
//   the tunnel is actually routing traffic (not just connected).
//
// All postMessage calls are wrapped in try/catch because nativePort may
// become null between the check and the send (RACE: SW killed and restarted,
// or native host crashes).
// Alarm lifecycle: alarms are created ONLY while a connection is in flight
// (connecting/connected) and cleared on disconnect/failure. Without this the
// 3 s stats poll wakes the service worker every few seconds forever, even
// when the tunnel is down. If the SW is recreated mid-connection (MV3 idle
// kill), the IIFE below re-creates them from persisted state.
function ensureActiveAlarms() {
  chrome.alarms.create("tarn-keepalive", { periodInMinutes: 0.5 });
  chrome.alarms.create("tarn-stats", { periodInMinutes: 0.05 });
  chrome.alarms.create("tarn-ipcheck", { periodInMinutes: 1 });
}

function stopAlarms() {
  chrome.alarms.clearAll().catch(() => {});
}

TarnStorage.getState()
  .then(s => {
    if (s.status === "connecting" || s.status === "connected") ensureActiveAlarms();
  })
  .catch(() => {});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "tarn-keepalive") {
    if (nativePort && nativePort._tarnState === "connected") {
      try { nativePort.postMessage({ cmd: "ping" }); } catch (e) {}
    }
    checkIpIfConnected();
    // Self-heal the badge every 30s from persisted state. Composite
    // refreshBadge() makes this recompute BOTH sources, repairing any stale
    // or missing badge (e.g. after a SW/browser restart, tunnel disconnect
    // while DPI active, or an update missed while the SW was dead).
    TarnStorage.getState().then(s => updateBadge(s.status, s._tunnelAlive)).catch(() => {});
    TarnStorage.getDpiState().then(d => updateDpiBadge(d.dpiStarting ? "starting" : (d.dpiActive ? "active" : "off"))).catch(() => {});
  } else if (alarm.name === "tarn-stats") {
    if (nativePort && nativePort._tarnState === "connected") {
      try { nativePort.postMessage({ cmd: "stats" }); } catch (e) {}
    }
  } else if (alarm.name === "tarn-ipcheck") {
    checkIpIfConnected();
  }
});

// ── connect ──
// Initiates a WG tunnel connection. Called from:
//   - User clicking "Connect" in popup (message "CONNECT")
//   - Keyboard shortcut Ctrl+Shift+D (toggle-connection)
//   - onStartup autoConnect (browser restart with autoConnect enabled)
//   - NEVER called by handleNativeError or the startup IIFE (auto-reconnect
//     was removed to prevent phantom connections — see RACE 2)
//
// STALE PORT HANDLING (mechanism shared with onDisconnect — RACE 4):
// If a previous nativePort exists (from a prior connection that hasn't
// cleaned up yet), we must:
//   1. Set stopping=true to prevent the old port's onDisconnect from
//      calling handleNativeError during cleanup
//   2. Disconnect the old port and null nativePort
//   3. Set oldPort.__stale=true so the old onDisconnect handler bails out
//   4. Reset stopping=false before starting the new connection
//
// The __stale flag is the PRIMARY defense against RACE 4. The onDisconnect
// handler checks it both at entry AND after every yield. This covers:
//   - Case A: onDisconnect hasn't fired yet → it will see __stale at entry
//   - Case B: onDisconnect already started but is between yields → it will
//     see __stale or changed nativePort after the next yield
//
// CONNECTING STATE:
// setState("connecting") is set BEFORE startNative() to ensure the popup
// shows a connecting state immediately. startNative() returns a promise
// that resolves when the native host responds with "ready" or rejects on
// error/timeout. The promise includes all proxy configuration logic.
async function connect(profileId) {
  // Re-entrancy guard: a second CONNECT while one is in flight would start
  // a second wireproxy and leak the first native port. The popup disables
  // the button, but a hostile/racy caller must not be able to stack
  // connections either.
  if (_connectInFlight) return { ok: false, error: "connection already in progress" };
  _connectInFlight = true;
  try {
    return await _connect(profileId);
  } finally {
    _connectInFlight = false;
  }
}

async function _connect(profileId) {
  const profile = await TarnStorage.getProfile(profileId);
  if (!profile) throw new Error("Profile not found");
  activeProfile = profile;
  stopping = false;

  const settings = await TarnStorage.getSettings();
  await TarnStorage.updateProfile(profileId, { lastUsed: Date.now(), connects: (profile.connects || 0) + 1 });

  // ── Old port cleanup (RACE 4 defense) ──
  // If a previous nativePort exists, it may be from:
  //   (a) A prior connection that the user is replacing
  //   (b) A stale port where onDisconnect is still pending from a crash
  //
  // We must clean it up safely without triggering handleNativeError:
  //   1. stopping=true: prevents onDisconnect from calling handleNativeError
  //   2. postMessage("disconnect"): tells native host to stop wireproxy
  //   3. port.disconnect(): closes Chrome-side port, may trigger onDisconnect
  //   4. nativePort=null: prevents alarms/keepalives from using the old port
  //   5. __stale=true: the onDisconnect handler (fires from step 3 or pending
  //      from a crash) checks this flag AFTER EVERY YIELD and bails out
  //   6. stopping=false: safe to reset because we're creating a new connection.
  //      The old onDisconnect handler will see __stale or changed nativePort.
  if (nativePort) {
    stopping = true;
    const oldPort = nativePort;
    try { oldPort.postMessage({ cmd: "disconnect" }); } catch (e) {}
    try { oldPort.disconnect(); } catch (e) {}
    nativePort = null;
    // Guard: if old port's onDisconnect fires late, don't overwrite new connection
    oldPort.__stale = true;
    stopping = false;
  }
  await clearAllProxies();
  await TarnProxy.clearKillSwitch();
  await TarnProxy.clearQuicBlock();
  await TarnProxy.setWebRTCProtection(false);

  await setState({ status: "connecting", profileId, error: "", socksAddr: "", since: Date.now(), backend: "none", publicIp: null });
  ensureActiveAlarms();

  try {
    await startNative(profile, settings);
    nativeAvailable = true;
    return { ok: true, mode: "native" };
  } catch (e) {
    lastNativeError = String(e && e.message || e);
    nativeAvailable = false;
    // If the user disconnected while startNative() was in flight,
    // disconnect() already wrote "disconnected" — do not overwrite it
    // with "error" and do not spam a failure notification.
    if (stopping) return { ok: false, error: "canceled" };
    await setState({
      status: "error", profileId, error: lastNativeError,
      socksAddr: "", since: Date.now(), backend: "none", publicIp: null
    });
    notify(TarnI18n.t(getLang(), "notifErrorTitle"), lastNativeError);
    return { ok: false, error: lastNativeError };
  }
}

// ── disconnect ──
// User-initiated tunnel disconnect. Clears all proxy settings, kill switch,
// QUIC block, and WebRTC protection. Records the session if stats are enabled.
//
// STOPPING FLAG LIFECYCLE:
// stopping is set to true FIRST and NEVER reset here. This is critical:
//   1. Setting stopping=true first ensures that if onDisconnect fires
//      concurrently (from the port.disconnect() below or from a native host
//      crash), the handler sees stopping=true and skips handleNativeError.
//   2. stopping is only reset to false at the START of connect(). This means
//      it stays true from disconnect() all the way until the next connect()
//      call. Any stale onDisconnect handlers from the old connection will
//      see stopping=true and bail out.
//
// KILL SWITCH:
// Kill switch is explicitly CLEARED here (not applied). When the user
// intentionally disconnects, they should be able to browse freely. Kill
// switch is only applied by handleNativeError (unexpected tunnel drops).
//
// SESSION RECORDING:
// Sessions are recorded only if the tunnel was "connected" or "connecting"
// (i.e., not already "error" which was already recorded by a previous drop).
async function disconnect() {
  stopping = true;
  stopAlarms();
  const state = await TarnStorage.getState();
  const settings = await TarnStorage.getSettings();

  // Disconnect the native port if it exists. Unlike connect(), we don't set
  // __stale here because we're not creating a new port — we're shutting down.
  // The onDisconnect handler will see stopping=true and skip handleNativeError.
  // If nativePort is already null (e.g., onDisconnect from a crash already ran),
  // this block is skipped entirely — the crash handler already did cleanup.
  if (nativePort) {
    try { nativePort.postMessage({ cmd: "disconnect" }); } catch (e) {}
    try { nativePort.disconnect(); } catch (e) {}
    nativePort = null;
  }
  await clearAllProxies();
  await TarnProxy.clearQuicBlock();
  await TarnProxy.setWebRTCProtection(false);

  // Kill switch: only apply on unexpected tunnel drops (handleNativeError), NOT on explicit user disconnect.
  // When user clicks disconnect, they should be able to browse freely.
  await TarnProxy.clearKillSwitch();

  if (settings.statsEnabled !== false && (state.status === "connected" || state.status === "connecting")) {
    await TarnStorage.recordSession(state.since, Date.now(), state._up || 0, state._down || 0, state.profileId, activeProfile ? activeProfile.name : "");
  }

  await setState({ status: "disconnected", profileId: null, error: "", socksAddr: "", since: 0, backend: "none", publicIp: null });
  activeProfile = null;
  // stopping stays true — prevents onDisconnect from calling handleNativeError
  // stopping is reset at the start of connect()
  return { ok: true };
}

// ── startNative ──
// Establishes a native messaging connection to tarn_host.py.
// Returns a Promise that resolves when the native host confirms "ready"
// (wireproxy SOCKS5 proxy is listening) or rejects on error/timeout.
//
// NATIVE MESSAGING ARCHITECTURE:
// Chrome communicates with the native host via a single port (nativePort).
// Messages are JSON. The lifecycle is:
//   SW sends: { cmd: "connect", config, socksAddr, disableQuic }
//   Host sends: { status: "ready", socksAddr, backend } — tunnel is up
//   Host sends: { status: "stats", txBytes, rxBytes, ... } — periodic stats
//   Host sends: { status: "alive", wireproxyAvailable } — keepalive response
//   Host sends: { status: "error", message } — tunnel failed
//   Host sends: { status: "stopped" } — host stopped wireproxy gracefully
//
// SETTLED FLAG:
// The `settled` boolean prevents double-resolve/reject of the promise.
// Once the promise settles (ready, error, or timeout), subsequent messages
// from the native host are handled differently:
//   - "ready" after settled: just re-apply proxy (host restarted wireproxy)
//   - "error" after settled: call handleNativeError (tunnel dropped post-connect)
//   - "stats" / "alive": always handled regardless of settled state
//
// TIMEOUT:
// 15 seconds for the initial "ready" response. If the native host doesn't
// respond, the promise rejects and connect() sets state to "error".
async function startNative(profile, settings) {
  const hostName = settings.nativeHostName || NATIVE_HOST_DEFAULT;
  const dpiSettings = await TarnStorage.getDpiSettings();
  const dpiAdguardDns = dpiSettings.dpiAdguardDns !== false;
  const port = chrome.runtime.connectNative(hostName);
  nativePort = port;
  nativePort._tarnState = "connecting";

  return new Promise((resolve, reject) => {
    let settled = false;
    const timeout = setTimeout(() => {
      if (!settled) {
        settled = true;
        try { port.disconnect(); } catch (e) {}
        nativePort = null;
        reject(new Error(TarnI18n.t(getLang(), "notifHostTimeout")));
      }
    }, 15000);

    port.onMessage.addListener(async (msg) => {
      if (!msg) return;

      // ── STALE PORT GUARD (RACE 5) ──
      // When a broken tunnel is followed by a working one, the OLD port may
      // receive delayed messages (error, stats, etc.) after the NEW connection
      // is established. Without this guard:
      //
      // Timeline:
      //   1. Broken tunnel → old port → onMessage("error") → settled=true → handleNativeError
      //   2. User clicks Disconnect → stopping=true → setState("disconnected")
      //   3. User clicks Connect (working) → stopping=false → startNative() → nativePort=newPort
      //   4. OLD port receives DELAYED "error" → onMessage → settled=true → handleNativeError
      //   5. handleNativeError checks stopping → false (reset by connect!) → proceeds
      //   6. setState({ status: "error", profileId: OLD }) → OVERWRITES "connecting"!
      //   7. User sees "error" flash for ~2 seconds
      //   8. New port receives "ready" → setState("connected") → correct state
      //
      // Fix: check nativePort === port before processing any message. If nativePort
      // has changed, this port is stale and all its messages must be silently ignored.
      if (nativePort !== port) return;

      if (msg.status === "ready") {
        // "ready" = native host started wireproxy SOCKS5 proxy successfully.
        // If settled is already true, this is a re-connection (host restarted
        // wireproxy after the initial connection). Just re-apply proxy settings.
        if (settled) {
          applyProxy(msg.socksAddr, settings).catch(() => {});
          return;
        }
        // First "ready" — resolve the startNative() promise IMMEDIATELY,
        // before any side effects, so connect()'s _connectInFlight guard can
        // never be stuck even if a side effect (applyProxy etc.) rejects.
        settled = true;
        clearTimeout(timeout);
        nativePort._tarnState = "connected";
        wireproxyAvailable = true;
        // H1 FIX: resolve before awaiting side effects — an applyProxy /
        // clearKillSwitch failure must never leave _connectInFlight=true
        // (which would block every future connect until SW reload).
        resolve({ ok: true, mode: "native", socksAddr: msg.socksAddr });
        try {
          // Configure Chrome to route traffic through the SOCKS5 proxy
          await applyProxy(msg.socksAddr, settings);

          // Clear any stale kill switch rules from a previous tunnel drop.
          // The tunnel is now working, so kill switch is not needed.
          await TarnProxy.clearKillSwitch();

          // Apply optional browser-level countermeasures
          if (settings.disableQuic) await TarnProxy.applyQuicBlock();
          if (settings.webrtcProtection) await TarnProxy.setWebRTCProtection(true);

          // Auto-start packet filter if enabled in settings
          const dpiSettings = await TarnStorage.getDpiSettings();
          if (dpiSettings.dpiAutoStartWithWg) {
            dpiStart().catch(() => {});
          }

          // M1 FIX: re-check port identity + stopping AFTER the awaits. If the
          // user disconnected (or a new connect started) while we were applying
          // proxy settings, this "ready" belongs to a dead connection and must
          // NOT overwrite the newer state.
          if (nativePort !== port || stopping) return;

          // Update state to "connected" — popup will show connected UI.
          // IMPORTANT: Explicitly clear ALL internal state fields (_tunnelAlive,
          // _latency, etc.) because setState() does a merge ({ ...cur, ...patch })
          // and stale values from a previous connection would persist otherwise.
          //
          // BUG EXAMPLE: Broken tunnel sets _tunnelAlive=false via updateStats().
          // User disconnects → setState("disconnected") doesn't clear _tunnelAlive.
          // User connects working tunnel → setState("connected") inherits
          // _tunnelAlive=false from storage → popup shows "not active" warning
          // for 2-3 seconds until health check sets _tunnelAlive=true.
          //
          // HEALTH GATE: we do NOT switch to "connected" immediately. wireproxy
          // listening locally does not prove the tunnel works — the native host
          // verifies the full chain (SOCKS5 → WG → internet) via an active
          // health check that reports `healthCheckOk`. Until that arrives (or the
          // health wait timer fires), the state stays "connecting" so the popup
          // shows "Подключение..." and the broken-tunnel case can never flash a
          // false "Подключено".
          await setState({
            status: "connecting", profileId: profile.id, error: "",
            socksAddr: msg.socksAddr, since: Date.now(),
            backend: msg.backend || "wireproxy", publicIp: null,
            _tunnelAlive: null, _latency: 0, _handshake: 0,
            _up: 0, _down: 0, _uptime: 0, _awaitingHealth: true
          });
          // Request the first "stats" immediately — do NOT wait up to 3s for the
          // tarn-stats alarm. The native host already ran its initial health check
          // during startup, so the first stats reply arrives within ~100ms and
          // carries healthCheckOk/healthChecked. This is what makes a healthy
          // tunnel flip to "connected" in ~1-2s and a broken one fail fast.
          try { nativePort.postMessage({ cmd: "stats" }); } catch (e) {}
          // Start async IP verification (2s delay to let tunnel stabilize)
          startIpVerification();
          startHealthWaitTimer(profile.id);
          notify(TarnI18n.t(getLang(), "notifConnectedTitle"), `${profile.name} — via ${msg.socksAddr}`);
        } catch (e) {
          // A side effect failed but the tunnel itself is up (ready already
          // resolved above). Surface it without blocking connect().
          console.error("post-ready side effect failed:", e);
        }

      } else if (msg.status === "stopped") {
        // Host stopped wireproxy gracefully (e.g., user ran stop command on CLI).
        // Full cleanup — this is an unexpected stop from the user's perspective.
        await clearAllProxies();
        await TarnProxy.clearKillSwitch();
        await TarnProxy.clearQuicBlock();
        await TarnProxy.setWebRTCProtection(false);
        await setState({ status: "disconnected", profileId: null, error: "", socksAddr: "", since: 0, backend: "none", publicIp: null });
      } else if (msg.status === "error") {
        // "error" from native host means the WG tunnel failed.
        // If settled=false: tunnel never came up — reject the startNative() promise.
        //   connect() catches this and sets state to "error" directly.
        // If settled=true: tunnel WAS up but dropped — call handleNativeError.
        //   This is the RACE 1 scenario: handleNativeError is async and checks
        //   `stopping` before writing state (see handleNativeError comments).
        if (!settled) {
          settled = true; clearTimeout(timeout);
          reject(new Error(msg.message || "native host error"));
        } else {
          await handleNativeError(profile, msg.message);
        }
      } else if (msg.status === "stats") {
        // Periodic stats from native host (txBytes, rxBytes, latency, etc.)
        // Always processed regardless of settled state.
        await updateStats(profile.id, msg);
      } else if (msg.status === "alive") {
        if (typeof msg.wireproxyAvailable === "boolean") {
          wireproxyAvailable = msg.wireproxyAvailable;
        }
      }
    });

    // ── onDisconnect handler ──
    // Fires when: (a) native host crashes/exits, (b) we call port.disconnect(),
    // (c) Chrome kills the native process, (d) SW is about to terminate.
    //
    // This handler is the CENTRAL point of RACE CONDITIONS in this file.
    // It is async and contains 4 yield points (await ...). Between any two
    // yields, the SW can be killed by Chrome (MV3 timeout/memory pressure),
    // and the user can perform actions (Disconnect/Connect).
    //
    // RACE 2: If SW is killed during any yield, handleNativeError never runs,
    //   leaving state as "connected" in storage. Startup IIFE handles this.
    //
    // RACE 4 (the most complex):
    //   1. Tunnel drops → this handler fires → passes __stale check at entry
    //   2. nativePort = null → await clearAllProxies() → YIELDS
    //   3. User clicks Disconnect → stopping=true → setState("disconnected")
    //   4. User clicks Connect → stopping=false → startNative() → nativePort = newPort
    //   5. This handler RESUMES from yield → if we only checked __stale at entry,
    //      we'd now check !stopping → TRUE → call handleNativeError(oldProfile)
    //      → overwrites "connecting" state with "error" for OLD profile!
    //
    // RACE 5 is handled in the onMessage listener (not here), but the mechanism
    // is the same: nativePort identity check after every async gap.
    //
    // PREVENTION: We re-check BOTH port.__stale AND nativePort identity after
    // EVERY await. If nativePort has changed (connect() created a new one), we
    // bail out immediately. The nativePort identity check is the key safeguard
    // — even if stopping was reset by connect(), the changed nativePort tells
    // us a new connection exists and we must not interfere.
    port.onDisconnect.addListener(async () => {
      // First check: __stale catches the easy case (onDisconnect fires AFTER
      // connect() has already set __stale on this port)
      if (port.__stale) return;
      const err = chrome.runtime.lastError && chrome.runtime.lastError.message;

      // Snapshot nativePort identity BEFORE setting it to null.
      // If connect() later assigns a new port, nativePort !== portAtStart.
      const portAtStart = nativePort;
      nativePort = null;

      await clearAllProxies();
      // ── GUARD: After every yield, verify nothing changed ──
      // port.__stale: connect() marked this port as superseded
      // nativePort !== null && !== portAtStart: connect() created a new port
      // Either condition means a new connection exists — we must not interfere.
      if (port.__stale || (nativePort !== null && nativePort !== portAtStart)) return;
      await TarnProxy.clearKillSwitch();
      if (port.__stale || (nativePort !== null && nativePort !== portAtStart)) return;
      await TarnProxy.clearQuicBlock();
      if (port.__stale || (nativePort !== null && nativePort !== portAtStart)) return;
      await TarnProxy.setWebRTCProtection(false);
      if (port.__stale || (nativePort !== null && nativePort !== portAtStart)) return;

      if (!settled) {
        // Connection never completed — reject the startNative() promise
        settled = true; clearTimeout(timeout);
        reject(new Error(mapNativeError(err) || TarnI18n.t(getLang(), "notifHostDisconnected")));
      } else if (!stopping) {
        // Connection WAS established but has now dropped unexpectedly.
        // stopping=false means the user did NOT initiate this disconnect.
        // Final safety check: nativePort guard above already confirmed no new
        // connection exists, so it's safe to report the error.
        await handleNativeError(profile, mapNativeError(err) || "native host disconnected");
      }
      // If stopping=true: user explicitly disconnected. disconnect() already
      // handled state updates. We do nothing — no state write, no notification.
    });

    port.postMessage({
      cmd: "connect",
      config: profile.rawText,
      socksAddr: `${settings.socksHost}:${settings.socksPort}`,
      disableQuic: !!settings.disableQuic,
      dpiAdguardDns
    });
  });
}

// ---- applyProxy ----
async function applyProxy(socksAddr, settings) {
  const m = socksAddr.match(/^(.+):(\d+)$/);
  if (!m) throw new Error("bad socks addr: " + socksAddr);
  let host = m[1]; const port = parseInt(m[2], 10);
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  if (host === "::1") host = "127.0.0.1";
  // Defense-in-depth: wireproxy always listens on loopback; never send
  // browser traffic to a non-loopback proxy address. The native host binds
  // only loopback and settings.socksHost is sanitized to loopback, but this
  // guards against a crafted message or a future code path.
  if (host !== "127.0.0.1" && host !== "localhost") {
    throw new Error("refusing to proxy to non-loopback address: " + host);
  }
  await TarnProxy.setProxy({
    host, port,
    bypassList: settings.bypassList,
    splitTunneling: settings.splitTunneling,
    splitMode: settings.splitMode,
    splitDomains: settings.splitDomains
  });
}

async function clearAllProxies() {
  await TarnProxy.clearProxy();
}

// ── handleNativeError ──
// Called when the native host reports an error or disconnects unexpectedly.
//
// RACE CONDITION (RACE 1 from module header):
// This function is called from onDisconnect's async handler. Between the
// await TarnStorage.getSettings() and the setState() call, there is an async
// gap. During this gap, the user may click "Disconnect" which calls
// disconnect() → setState("disconnected"). If we don't check, we would
// overwrite the user's "disconnected" state with "error".
//
// Timeline:
//   1. Tunnel drops → onDisconnect → handleNativeError(profile, msg) starts
//   2. handleNativeError: await TarnStorage.getSettings() → YIELDS to event loop
//   3. User clicks Disconnect → disconnect() → setState({ status: "disconnected" })
//   4. handleNativeError resumes → WITHOUT the guard, setState("error") would run
//      → OVERWRITES "disconnected" with "error" → user sees error reappear
//
// The `if (stopping) return;` guard after the async gap prevents this.
// `stopping` is set to true by disconnect() before any state writes.
//
// KILL SWITCH interaction:
// Kill switch is intentionally applied BEFORE the stopping check. If the tunnel
// drops unexpectedly (not user-initiated), the kill switch should activate
// immediately to prevent IP leaks, regardless of what happens next. The stopping
// check only guards the setState/notify portion — the network protection is always
// applied.
async function handleNativeError(profile, message) {
  lastNativeError = message;
  stopAlarms();
  const settings = await TarnStorage.getSettings();

  // Apply kill switch on tunnel drop (if enabled)
  if (settings.killSwitch) {
    await TarnProxy.applyKillSwitch(settings.socksHost + ":" + settings.socksPort);
  }

  // CRITICAL RACE GUARD: Check if user disconnected while we were doing async
  // work above (reading settings, applying kill switch). Between those awaits,
  // disconnect() may have run and set stopping=true. If so, the user's
  // "disconnected" state is already correct — we must NOT overwrite it with "error".
  if (stopping) return;

  await setState({
    status: "error", profileId: profile.id, error: message,
    socksAddr: "", since: Date.now(), backend: "none", publicIp: null
  });
  notify(TarnI18n.t(getLang(), "notifDisconnectedTitle"), message);
}

async function updateStats(profileId, msg) {
  // Health data is processed BEFORE the stats-display guard: the fail-fast
  // abort and the connecting→connected gate must run even when the user
  // disabled the stats display, otherwise a broken tunnel never aborts and
  // a healthy one stays "connecting" until the health timer kills it.
  const state = await TarnStorage.getState();

  // FAIL-FAST: never-verified tunnel. The native host runs an active HTTP
  // check through the whole WG chain; after 2+ REAL consecutive failures it
  // reports healthChecked=true + healthCheckOk=false — a definitive dead
  // verdict. We additionally require ~8s elapsed so that a slow-but-alive
  // tunnel (WG handshake can take several seconds) gets a chance to pass its
  // 3rd check before we abort — no false positives.
  //
  // Timing for a broken tunnel: eager check during startup (~0.3-3s), 2nd
  // check +3s later → healthChecked=true lands ~3-6s; the 8s floor then
  // triggers the abort on the next stats poll (~8-10s total, vs 45s before).
  if (state.status === "connecting" && state._awaitingHealth) {
    const elapsed = Date.now() - (state.since || Date.now());
    if (msg.healthChecked === true && msg.healthCheckOk === false && elapsed > 8000) {
      await abortBrokenTunnel(
        state.profileId || profileId,
        TarnI18n.t(getLang(), "tunnelNotVerified")
      );
      return;
    }
  }

  // Once the tunnel is in a terminal state ("error"/"disconnected"), do NOT
  // keep refreshing stats — otherwise the uptime keeps ticking after an error
  // and the popup shows stale numbers.
  if (state.status === "error" || state.status === "disconnected") {
    return;
  }

  state._up = msg.txBytes || 0;
  state._down = msg.rxBytes || 0;
  state._handshake = msg.lastHandshake || 0;
  state._latency = msg.latency || 0;
  state._uptime = msg.uptime || 0;
  state._tunnelAlive = msg.tunnelAlive;
  state._handshakeStale = msg.handshakeStale;
  if (msg.healthCheckOk !== undefined) state._healthCheckOk = msg.healthCheckOk;

  // HEALTH GATE: promote "connecting" → "connected" only when the native host
  // confirms the full tunnel chain works (healthCheckOk=true). Fixes the
  // broken-tunnel case where "Подключено" flashed for a few seconds while the
  // IP row still said "проверяем...".
  if (msg.healthCheckOk === true && state.status === "connecting") {
    state.status = "connected";
    state._awaitingHealth = false;
  }
  if (state.status === "connected") {
    state._awaitingHealth = false;
  }
  await TarnStorage.saveState(state);

  // Update badge when tunnel alive status changes
  updateBadge(state.status, state._tunnelAlive);

  // If health check got a public IP and we don't have one yet, use it
  if (msg.healthCheckIp && !state.publicIp) {
    state.publicIp = msg.healthCheckIp;
    state.ipVerifiedAt = Date.now();
    await TarnStorage.saveState(state);
    chrome.runtime.sendMessage({ type: "STATE", state }).catch(() => {});
  }

  // Stats display is optional (Settings → "Collect session stats"); the
  // health work above always runs. Only the counter broadcast is skipped.
  const settings = await TarnStorage.getSettings();
  if (settings.statsEnabled === false) return;

  chrome.runtime.sendMessage({ type: "STATS", stats: msg, profileId }).catch(() => {});
}

// ---- IP verification ----
function _isPrivateIpv4(oct) {
  const [a, b] = oct;
  if (a === 10) return true;                    // 10.0.0.0/8 RFC1918
  if (a === 127) return true;                   // 127.0.0.0/8 loopback
  if (a === 169 && b === 254) return true;      // 169.254.0.0/16 link-local
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 RFC1918
  if (a === 192 && b === 168) return true;      // 192.168.0.0/16 RFC1918
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  return false;
}

function _isPrivateIpv6(v) {
  const lower = v.toLowerCase();
  if (lower === "::1") return true;                    // loopback
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // fc00::/7 ULA
  if (lower.startsWith("fe8") || lower.startsWith("fe9") ||
      lower.startsWith("fea") || lower.startsWith("feb")) return true; // fe80::/10 link-local
  if (lower.startsWith("ff")) return true;              // ff00::/8 multicast
  return false;
}

function _isPublicIp(v) {
  if (typeof v !== "string" || v.length < 7 || v.length > 45) return false;
  if (/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(v)) {
    const oct = v.split(".").map(Number);
    if (oct.some(o => o > 255)) return false;
    if (_isPrivateIpv4(oct)) return false;
    return true;
  }
  // IPv6: hex digits + colons, at most one "::", no ".." artifacts.
  if (!v.includes(":") || !/^[0-9a-fA-F:]+$/.test(v) ||
      v.includes(":::") || v.split("::").length > 2) return false;
  if (_isPrivateIpv6(v)) return false;
  return true;
}

async function fetchPublicIp() {
  const services = [
    "https://api.ipify.org?format=json",
    "https://ifconfig.me/all.json",
    "https://api.myip.com"
  ];
  for (const url of services) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      const r = await fetch(url, { cache: "no-store", signal: controller.signal });
      clearTimeout(timeoutId);
      const j = await r.json();
      const raw = j && typeof j === "object" ? (j.ip || j.IP || j.query) : null;
      if (_isPublicIp(raw)) return raw;
    } catch (e) { /* try next */ }
  }
  return null;
}

let _lastIpCheckFail = 0;

// HEALTH GATE TIMER: if the native host never confirms the tunnel (no
// healthCheckOk=true within 25s of "ready"), fail the connection instead of
// showing a false "Подключено". Broken wireproxy/WG setups time out here.
let _healthWaitTimer = null;

// Aborts a never-verified tunnel: stops the native host (wireproxy keeps
// running otherwise and the uptime keeps ticking), clears proxies and writes
// the error state. Used by both the health-wait timer and the updateStats()
// fail-fast path.
async function abortBrokenTunnel(profileId, message) {
  if (_healthWaitTimer) { clearTimeout(_healthWaitTimer); _healthWaitTimer = null; }
  stopAlarms();
  // Tell the host to stop wireproxy so it doesn't keep running in the
  // background after the error (stats would keep flowing and the uptime
  // would keep ticking).
  if (nativePort) {
    // Mark the port stale BEFORE disconnecting so the onDisconnect handler
    // bails out at entry — otherwise it would run handleNativeError(), apply
    // the kill switch (bad for a tunnel that never worked) and double-notify.
    nativePort.__stale = true;
    try { nativePort.postMessage({ cmd: "disconnect" }); } catch (e) {}
    try { nativePort.disconnect(); } catch (e) {}
    nativePort = null;
  }
  await clearAllProxies();
  await TarnProxy.clearKillSwitch();
  await TarnProxy.clearQuicBlock();
  await TarnProxy.setWebRTCProtection(false);
  if (stopping) return;
  await setState({
    status: "error", profileId: profileId || null,
    error: message, socksAddr: "", since: Date.now(),
    backend: "none", publicIp: null,
    _tunnelAlive: false, _awaitingHealth: false, _uptime: 0, _up: 0, _down: 0
  });
  notify(TarnI18n.t(getLang(), "notifErrorTitle"), message);
}

function startHealthWaitTimer(profileId) {
  if (_healthWaitTimer) clearTimeout(_healthWaitTimer);
  _healthWaitTimer = setTimeout(async () => {
    _healthWaitTimer = null;
    const state = await TarnStorage.getState();
    if (state.status !== "connecting") return;
    if (state._healthCheckOk === true) return;
    // Tunnel never verified — report a clear error and STOP the native host
    // so wireproxy does not keep running in the background.
    await abortBrokenTunnel(state.profileId || profileId, TarnI18n.t(getLang(), "tunnelNotVerified"));
  }, 25000);
}

function startIpVerification() {
  setTimeout(() => checkIpIfConnected(), 2000);
}

async function checkIpIfConnected() {
  const state = await TarnStorage.getState();
  if (state.status !== "connected") return;
  // If tunnel is dead, don't keep hammering IP checks
  if (state._tunnelAlive === false) return;
  // Don't retry more often than every 30 seconds after failures
  const now = Date.now();
  if (_lastIpCheckFail > 0 && (now - _lastIpCheckFail) < 30000) return;

  const settings = await TarnStorage.getSettings();
  if (settings.verifyIp === false) return;
  try {
    const ip = await fetchPublicIp();
    if (!ip) {
      _lastIpCheckFail = now;
      return;
    }
    _lastIpCheckFail = 0;
    const updated = { ...state, publicIp: ip, ipVerifiedAt: Date.now() };
    await TarnStorage.saveState(updated);
    chrome.runtime.sendMessage({ type: "STATE", state: updated }).catch(() => {});
    chrome.runtime.sendMessage({ type: "IP_CHECK", ip }).catch(() => {});
  } catch (e) { _lastIpCheckFail = now; }
}

// ---- native ping ----
async function pingNative() {
  const settings = await TarnStorage.getSettings();
  return new Promise((resolve) => {
    let port;
    try {
      port = chrome.runtime.connectNative(settings.nativeHostName || NATIVE_HOST_DEFAULT);
      void chrome.runtime.lastError;
    } catch (e) {
      nativeAvailable = false;
      return resolve({ ok: false, available: false, error: String(e && e.message || e) });
    }
    const timeout = setTimeout(() => {
      try { port.disconnect(); } catch (e) {}
      nativeAvailable = false;
      resolve({ ok: false, available: false, error: "timeout", wireproxyAvailable: false });
    }, 3000);
    port.onMessage.addListener((msg) => {
      clearTimeout(timeout);
      nativeAvailable = !!(msg && (msg.status === "alive" || msg.status === "ready"));
      wireproxyAvailable = !!(msg && msg.wireproxyAvailable);
      try { port.disconnect(); } catch (e) {}
      resolve({ ok: true, available: nativeAvailable, wireproxyAvailable, version: msg?.version });
    });
    port.onDisconnect.addListener(() => {
      clearTimeout(timeout);
      const err = chrome.runtime.lastError && chrome.runtime.lastError.message;
      nativeAvailable = false;
      const mapped = mapNativeError(err);
      lastNativeError = mapped;
      chrome.storage.local.set({ "tarn.lastNativeError": mapped });
      resolve({ ok: false, available: false, error: mapped, wireproxyAvailable: false });
    });
    try { port.postMessage({ cmd: "ping" }); } catch (e) {
      clearTimeout(timeout);
      nativeAvailable = false;
      resolve({ ok: false, available: false, error: String(e && e.message || e), wireproxyAvailable: false });
    }
  });
}

async function checkWireproxy() {
  const settings = await TarnStorage.getSettings();
  return new Promise((resolve) => {
    let port;
    try {
      port = chrome.runtime.connectNative(settings.nativeHostName || NATIVE_HOST_DEFAULT);
    } catch (e) {
      return resolve({ ok: false, error: String(e && e.message || e) });
    }
    const timeout = setTimeout(() => {
      try { port.disconnect(); } catch (e) {}
      resolve({ ok: false, error: "timeout" });
    }, 10000);
    let resolved = false;
    port.onMessage.addListener((msg) => {
      if (resolved) return;
      if (msg.status === "alive" || msg.status === "error") {
        resolved = true;
        clearTimeout(timeout);
        try { port.disconnect(); } catch (e) {}
        resolve({
          ok: !!msg.wireproxyAvailable,
          wireproxyAvailable: !!msg.wireproxyAvailable,
          wireproxyPath: msg.wireproxyPath || "",
          error: msg.message
        });
      }
    });
    port.onDisconnect.addListener(() => {
      if (resolved) return;
      resolved = true;
      clearTimeout(timeout);
      const err = chrome.runtime.lastError && chrome.runtime.lastError.message;
      const mapped = mapNativeError(err);
      lastNativeError = mapped;
      chrome.storage.local.set({ "tarn.lastNativeError": mapped });
      resolve({ ok: false, error: mapped });
    });
    try { port.postMessage({ cmd: "check_wireproxy" }); } catch (e) {
      clearTimeout(timeout);
      resolve({ ok: false, error: String(e && e.message || e) });
    }
  });
}

// ── setState ──
// Atomic state update: merges patch into current state, persists to
// chrome.storage.local, notifies popup, and updates badge.
// This is the ONLY function that should write to tarn.state in storage.
// It does a read-merge-write (not atomic at the storage level), which means
// concurrent callers could lose updates. In practice, this is safe because:
//   - Only one "connected" transition happens at a time
//   - "disconnected" writes are idempotent (same value regardless of order)
//   - "error" writes are guarded by stopping flag (RACE 1)
async function setState(patch) {
  const cur = await TarnStorage.getState();
  const next = { ...cur, ...patch };
  await TarnStorage.saveState(next);
  chrome.runtime.sendMessage({ type: "STATE", state: next }).catch(() => {});
  updateBadge(next.status, next._tunnelAlive);
}

// One badge, one writer — composite model. The old design had updateBadge
// (tunnel) and updateDpiBadge (DPI) fight over chrome.action: the DPI badge
// was only painted when the tunnel badge was empty, and updateBadge cleared
// the badge (text="") without re-asserting the DPI state. Result: after any
// tunnel disconnect or SW restart the badge stayed empty while the filter was
// still running, or showed a stale status. Now all badge state lives in two
// module vars below and a single refreshBadge() recomputes the badge from BOTH
// sources on every update. This makes the badge:
//   - correct: tunnel states win; DPI shows only while the tunnel shows nothing
//   - self-healing: any update repaints from both sources, so a stale or
//     missing badge cannot persist (keepalive + popup-open also force refresh)
//   - race-free: synchronous, no async state reads
// setBadge stays idempotent (identical writes are skipped — repeated
// setBadgeText can flicker on scaled displays).
let lastBadgeWrite = { text: null, color: null };
let dpiBadgeState = "off";        // "off" | "starting" | "active"
let tunnelBadgeStatus = "disconnected";
let tunnelBadgeAlive = null;

function setBadge(text, color) {
  if (lastBadgeWrite.text === text && lastBadgeWrite.color === color) return;
  lastBadgeWrite = { text, color };
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
}

function badgeTextFor(status, alive) {
  if (status === "connected" && alive === false) {
    return { text: "ERR", color: "#ef4444" };
  }
  const map = {
    connected: { text: "ON", color: "#10b981" },
    connecting: { text: "..", color: "#fbbf24" },
    reconnecting: { text: "R", color: "#fbbf24" },
    disconnected: { text: "", color: "#64748b" },
    error: { text: "!", color: "#ef4444" }
  };
  return map[status] || map.disconnected;
}

// Single source of truth for the toolbar badge. Tunnel takes precedence;
// the DPI (filter) badge claims the badge only while the tunnel shows nothing.
function refreshBadge() {
  const m = badgeTextFor(tunnelBadgeStatus, tunnelBadgeAlive);
  if (!m.text) {
    if (dpiBadgeState === "starting") setBadge("DPI", "#fbbf24");
    else if (dpiBadgeState === "active") setBadge("DPI", "#10b981");
    else setBadge("", "#64748b");
  } else {
    setBadge(m.text, m.color);
  }
  refreshTitle();
}

function updateBadge(status, tunnelAlive) {
  tunnelBadgeStatus = status;
  if (tunnelAlive !== undefined) tunnelBadgeAlive = tunnelAlive;
  refreshBadge();
}

// The hover tooltip (also the "маленькая надпись" in the extensions list)
// follows the same composite state, so the status is visible even where the
// badge itself is not rendered.
function refreshTitle() {
  try {
    const lang = getLang();
    let key = tunnelBadgeStatus;
    if (tunnelBadgeStatus === "connected" && tunnelBadgeAlive === false) key = "error";
    const parts = ["Tarn", TarnI18n.t(lang, key) || key];
    if (dpiBadgeState === "starting") {
      parts.push(TarnI18n.t(lang, "dpiStarting") || "dpiStarting");
    } else if (dpiBadgeState === "active") {
      parts.push(TarnI18n.t(lang, "dpiOn") || "dpiOn");
    }
    chrome.action.setTitle({ title: parts.join(" · ") });
  } catch (e) {}
}

function notify(title, message) {
  try {
    chrome.notifications.create({
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/icon128.png"),
      title, message
    });
  } catch (e) {}
}

function getLang() {
  return TarnI18n.detectSystemLang();
}

// ══════════════════════════════════════════════════════════════════════════════
// STARTUP IIFE — Runs immediately when the service worker loads
// ══════════════════════════════════════════════════════════════════════════════
//
// This self-invoking async function runs EVERY TIME the SW starts — both on
// browser restart and on SW restart within the same session. Its purposes:
//
// 1. Detect native host availability (pingNative)
// 2. Push self-update to native host if available
// 3. Clean up stale kill switch rules
// 4. CRITICAL: SW restart recovery — detect and handle phantom "connected" state
//
// ── WHY SW RESTART RECOVERY IS NECESSARY ──
//
// When Chrome kills the SW (MV3 timeout ~30s, memory pressure, etc.):
//   - All in-memory state is lost (nativePort = null, stopping = false, etc.)
//   - chrome.proxy.settings are RESET (browser stops using SOCKS5 proxy)
//   - The native host process continues running (separate OS process)
//
// If the SW was killed DURING onDisconnect cleanup (between async yields),
// the cleanup handler never completed. Specifically, handleNativeError may
// never have run, leaving state as "connected" in chrome.storage.local.
//
// On SW restart:
//   - chrome.proxy.settings are clear → browser uses direct connection
//   - State in storage says "connected" → popup shows "connected"
//   - User browses with REAL IP thinking they're protected!
//
// This is a SECURITY ISSUE. The startup IIFE detects this by checking if
// state is "connected" and forcing it to "disconnected".
//
// ── BROWSER RESTART vs SW RESTART ──
//
// We can't directly distinguish browser restart from SW restart in the IIFE.
// The solution uses a _browserRestart flag set by chrome.runtime.onStartup:
//   - onStartup fires ONLY on browser restart → sets _browserRestart = true
//   - IIFE checks this flag → if true, this is browser restart, skip reset
//   - If false, this is SW restart → force disconnect
//
// RACE CONDITION (RACE 3 — see module header):
// onStartup and IIFE run concurrently. If IIFE's first async operation
// (pingNative) resolves before onStartup fires, the flag won't be set yet.
// This is extremely rare because pingNative involves native messaging I/O
// that always yields for multiple event loop turns. In the pathological case,
// the tunnel is force-disconnected and autoConnect doesn't trigger — the user
// must manually reconnect. This is preferred over phantom reconnect (security).
// ══════════════════════════════════════════════════════════════════════════════
(async () => {
  // Phase -1: One-time legacy-key migration (WGG -> Tarn). Runs before any
  // storage read so upgraded installs keep their profiles/settings/stats.
  try { await TarnStorage.migrateLegacy(); } catch (e) { /* non-fatal */ }

  // Phase 0: Seed the badge from persisted state BEFORE any async work.
  // Module vars start with defaults, so without this the DPI badge would be
  // lost on every SW restart until the async dpiQueryStatus resolves — and
  // that resolution used to race with Phase 3's force-disconnect, which then
  // cleared the freshly painted DPI badge again. Composite refreshBadge()
  // makes the repaint below immune to that race.
  try {
    const boot = await Promise.all([TarnStorage.getState(), TarnStorage.getDpiState()]);
    tunnelBadgeStatus = boot[0].status || "disconnected";
    tunnelBadgeAlive = boot[0]._tunnelAlive || null;
    if (boot[1].dpiStarting) dpiBadgeState = "starting";
    else if (boot[1].dpiActive) dpiBadgeState = "active";
    else dpiBadgeState = "off";
    refreshBadge();
  } catch (e) { /* ignore */ }

  // Phase 1: Detect native host.
  // This involves native messaging I/O (always yields to event loop),
  // giving onStartup time to fire and set _browserRestart.
  try {
    const r = await pingNative();
    nativeAvailable = r.available;
    wireproxyAvailable = r.wireproxyAvailable;
    if (nativeAvailable) {
      // Phase 1b: Restore the DPI badge after a browser/SW restart.
      // winws.exe keeps running outside Chrome, so the stored dpiState can be
      // stale-but-accurate; ask the host what is actually running and repaint
      // the badge ("DPI" pink) so the indicator reappears without a toggle.
      // On a failed query keep the Phase 0 seeded state instead of assuming
      // "off" — stored dpiState is stale-but-accurate and must not be wiped.
      dpiQueryStatus().then(res => {
        if (res?.dpiState?.dpiActive) updateDpiBadge("active");
        else if (res?.ok) updateDpiBadge("off");
        else refreshBadge();
      }).catch(() => {});
    } else {
      refreshBadge();
    }
  } catch (e) {
    nativeAvailable = false;
    refreshBadge();
  }

  // Phase 1c: self-heal if the first ping failed. install.bat can still be
  // finishing when the extension loads (registry is written a few seconds
  // into the install, the 25MB engine copy runs after it) - a fresh
  // extension loaded BEFORE/DURING the install must flip to "available" on
  // its own, without a manual re-open of the popup or re-run of install.bat.
  if (!nativeAvailable) {
    let retries = 0;
    const maxRetries = 4;
    const scheduleRetry = () => {
      if (retries >= maxRetries || nativeAvailable) return;
      retries += 1;
      setTimeout(async () => {
        if (nativeAvailable) return;
        try {
          const r = await pingNative();
          nativeAvailable = r.available;
          wireproxyAvailable = r.wireproxyAvailable;
          if (nativeAvailable) {
            dpiQueryStatus().then(res => {
              updateDpiBadge(res?.ok && res.dpiState?.dpiActive ? "active" : "off");
            }).catch(() => updateDpiBadge("off"));
          } else {
            scheduleRetry();
          }
        } catch (e) {
          scheduleRetry();
        }
      }, 2000 * retries);
    };
    scheduleRetry();
  }

  // Phase 2: Defensive cleanup of stale kill switch rules.
  // If state is "disconnected" but kill switch rules exist (from a crash
  // where cleanup didn't complete), clear them. This allows normal browsing
  // when the tunnel is not active.
  try {
    const state = await TarnStorage.getState();
    if (state.status !== "connected") {
      await TarnProxy.clearKillSwitch();
    }
  } catch (e) { /* ignore */ }

  // Phase 2b: Re-apply the ad blocker. DNR dynamic rules are lost when the
  // service worker restarts, so restore them from the saved DPI settings.
  await applyAdBlockSetting();

  // Phase 3: SW restart recovery (RACE 2 defense).
  // If state is "connected" or "reconnecting" but this is a SW restart
  // (not a browser restart), force the state to "disconnected" because:
  //   (a) chrome.proxy.settings were reset — browser is already using
  //       direct connection regardless of what state says
  //   (b) The native host may be dead or the tunnel broken
  //   (c) If SW was killed during onDisconnect cleanup, state is stale
  //
  // On browser restart, onStartup handles autoConnect separately. We skip
  // the force-disconnect by checking the _browserRestart flag.
  //
  // Why "disconnected" and not "error"? Because the user didn't see an error
  // notification — the SW just silently restarted. "disconnected" is the most
  // neutral state and prompts the user to reconnect if they want.
  try {
    const state = await TarnStorage.getState();
    const isBrowserRestart = await chrome.storage.local.get("_browserRestart");
    if (isBrowserRestart._browserRestart) {
      // Browser restart: onStartup handles reconnection. Clear the flag so
      // the NEXT SW restart (within the same session) is correctly identified.
      await chrome.storage.local.remove("_browserRestart");
    } else if (state.status === "connected" || state.status === "reconnecting"
               || state.status === "connecting") {
      // SW restart with stale "connected"/"connecting"/"reconnecting" state —
      // FORCE DISCONNECT. ("connecting" is included: if the SW was killed
      // mid-connect, the native port is gone and _connectInFlight was lost, so
      // the state would otherwise stay "connecting" forever.)
      // This prevents the user from browsing with a real IP while the UI
      // falsely shows "connected". All proxy/kill-switch/QUIC rules are
      // cleared because chrome.proxy.settings were already reset by Chrome.
      await clearAllProxies().catch(() => {});
      await TarnProxy.clearKillSwitch().catch(() => {});
      await TarnProxy.clearQuicBlock().catch(() => {});
      await setState({
        status: "disconnected", profileId: null, error: "",
        socksAddr: "", since: 0, backend: "none", publicIp: null
      });
      notify("Tarn", TarnI18n.t(getLang(), "notifHostDisconnected") || "Tunnel lost — SW restarted");
    }
  } catch (e) { /* ignore */ }
})();

// ---- packet filter functions ----
// Strategy keys understood by the native host (mirrors tarn_host.py).
// Order = selection priority used by the host's auto-select.
const DPI_STRATEGIES = [
  "fake_fakedsplit_ts",
  "simple_fake_ts",
  "fake_multisplit",
  "hostfakesplit",
  "exp",
  "fake_tls_auto_ts",
  "fake_tls_auto",
  "multisplit",
  "syndata_multidisorder",
  "fake_badseq",
  "hybrid_tlsauto_hostfakesplit",
  "hybrid_badseq_hostfakesplit"
];

async function applyAdBlockSetting() {
  try {
    const dpiSettings = await TarnStorage.getDpiSettings();
    await TarnBlockAds.apply(dpiSettings.dpiAdBlock !== false);
  } catch (e) { /* non-critical */ }
}

async function dpiStart() {
  // Re-entrancy guard: a second start_dpi while one is in flight (the auto
  // strategy probe can take up to 240 s) would launch a second winws.
  if (_dpiOpInFlight) return { ok: false, error: "DPI operation already in progress" };
  _dpiOpInFlight = true;
  try {
    return await _dpiStart();
  } finally {
    _dpiOpInFlight = false;
    _dpiStartPort = null;
  }
}

async function _dpiStart() {
  try {
    const settings = await TarnStorage.getSettings();
    const hostName = settings.nativeHostName || NATIVE_HOST_DEFAULT;
    const port = chrome.runtime.connectNative(hostName);
    _dpiStartPort = port;
    const dpiSettings = await TarnStorage.getDpiSettings();

    // Sanitize strategy: auto-selection by default; ignore stale values
    // from older versions (e.g. "multisplit_default").
    let strategy = dpiSettings.dpiStrategy || "auto";
    if (strategy !== "auto" && !DPI_STRATEGIES.includes(strategy)) {
      strategy = "auto";
    }

    return new Promise((resolve) => {
      let resolved = false;
      const done = (fn) => { if (!resolved) { resolved = true; fn(); } };

      // Auto-selection probes several strategies (each ~3-9 s), so be generous.
      const timeout = setTimeout(() => {
        done(() => { try { port.disconnect(); } catch (e) {} resolve({ ok: false, error: "Native host timeout" }); });
      }, 240000);

      port.onMessage.addListener((msg) => {
        // Auto-selection streams progress messages while probing strategies.
        // Clearing the watchdog on every one of them would silently disable
        // the 240 s hang protection (the timer is never re-armed). Only
        // terminal statuses end the conversation.
        if (msg && (msg.status === "dpi_started" || msg.status === "error")) {
          clearTimeout(timeout);
        }
        if (msg.status === "dpi_started") {
          dpiProcessActive = true;

          // Apply browser-level DPI countermeasures
          if (dpiSettings.dpiStripHeaders) {
            TarnProxy.applyStripHeaders({ headers: dpiSettings.dpiStripHeadersList || ["alt-svc", "Alt-Svc", "server", "Server", "x-powered-by", "X-Powered-By"] }).catch(() => {});
          }
          if (dpiSettings.dpiBlockQuic) {
            TarnProxy.applyQuicBlock().catch(() => {});
          }

          const cachedStrategy = msg.cachedStrategy !== undefined ? msg.cachedStrategy : null;
          const warnings = msg.warnings || [];
          TarnStorage.saveDpiState({
            dpiActive: true, dpiStarting: false,
            dpiProcessPid: msg.pid || null,
            dpiStrategy: msg.strategy || strategy,
            dpiVerified: !!msg.verified,
            dpiCachedStrategy: cachedStrategy,
            dpiWarnings: warnings,
            dpiError: null, dpiTimestamp: Date.now()
          }).then(() => {
            chrome.runtime.sendMessage({ type: "DPI_STATE", dpiState: { dpiActive: true, dpiStrategy: msg.strategy || strategy, dpiVerified: !!msg.verified, dpiCachedStrategy: cachedStrategy, dpiWarnings: warnings } }).catch(() => {});
            updateDpiBadge("active");
            // Intentional: end the start conversation. The native host is
            // designed to leave the bypass running after EOF - it must
            // survive this disconnect (and the service-worker suspension
            // that follows when the popup closes). Stopping happens only
            // via an explicit stop_dpi over a fresh port.
            done(() => { try { port.disconnect(); } catch (e) {} resolve({ ok: true, strategy: msg.strategy || strategy, verified: !!msg.verified }); });
          });
        } else if (msg.status === "error") {
          updateDpiBadge("off");
          TarnStorage.saveDpiState({
            dpiActive: false, dpiStarting: false,
            dpiError: msg.message, dpiTimestamp: Date.now()
          }).then(() => {
            done(() => { try { port.disconnect(); } catch (e) {} resolve({ ok: false, error: msg.message }); });
          });
        }
      });

      port.onDisconnect.addListener(() => {
        clearTimeout(timeout);
        // Guard with done(): the disconnect we caused ourselves right after
        // "dpi_started" is a success, not a failure - it must not flip the
        // badge to "off" or record a fake "native port closed" error in
        // storage (both used to happen on every successful start).
        done(() => {
          updateDpiBadge("off");
          const err = chrome.runtime.lastError && chrome.runtime.lastError.message;
          const mapped = mapNativeError(err);
          lastNativeError = mapped;
          chrome.storage.local.set({ "tarn.lastNativeError": mapped });
          resolve({ ok: false, error: mapped });
        });
      });

      port.postMessage({ cmd: "start_dpi", dpiSettings: { ...dpiSettings, dpiStrategy: strategy } });
      updateDpiBadge("starting");
      // Broadcast the starting phase so the popup paints the yellow
      // "connecting" animation (mascot run + pulsing dot) instead of
      // waiting for the (up to 240 s) auto-probe to finish.
      TarnStorage.saveDpiState({ dpiActive: false, dpiStarting: true, dpiError: null, dpiTimestamp: Date.now() }).then(() => {
        chrome.runtime.sendMessage({ type: "DPI_STATE", dpiState: { dpiActive: false, dpiStarting: true, dpiStrategy: null, dpiVerified: false } }).catch(() => {});
      });
    });
  } catch (e) {
    return { ok: false, error: String(e && e.message || e) };
  }
}

async function dpiStop() {
  // Cancel an in-flight dpiStart instead of refusing: the popup offers a
  // Stop button during "starting", and the strategy probe can take minutes.
  const sp = _dpiStartPort;
  if (sp) { try { sp.disconnect(); } catch (e) {} }
  return _dpiStopImpl();
}

async function _dpiStopImpl() {
  try {
    const settings = await TarnStorage.getSettings();
    const hostName = settings.nativeHostName || NATIVE_HOST_DEFAULT;
    const port = chrome.runtime.connectNative(hostName);

    return new Promise((resolve) => {
      let resolved = false;
      const done = (fn) => { if (!resolved) { resolved = true; fn(); } };

      const timeout = setTimeout(() => {
        done(() => { try { port.disconnect(); } catch (e) {} resolve({ ok: false, error: "timeout" }); });
      }, 5000);

      port.onMessage.addListener((msg) => {
        clearTimeout(timeout);
        if (msg.status === "error") {
          // The stop genuinely failed (e.g. an elevated winws.exe could not
          // be killed). Never pretend the bypass is off.
          updateDpiBadge("active");
          done(() => { try { port.disconnect(); } catch (e) {} resolve({ ok: false, error: msg.message || "DPI stop failed" }); });
          return;
        }
        dpiProcessActive = false;

        // Clear browser-level DPI countermeasures
        TarnProxy.clearStripHeaders().catch(() => {});
        // Don't clear QUIC block if tunnel's disableQuic is also enabled
        TarnStorage.getSettings().then(s => {
          if (!s.disableQuic) TarnProxy.clearQuicBlock();
        }).catch(() => {});

        TarnStorage.saveDpiState({
          dpiActive: false, dpiStarting: false,
          dpiProcessPid: null, dpiError: null, dpiTimestamp: Date.now()
        }).then(async () => {
          const stored = await TarnStorage.getDpiState();
          chrome.runtime.sendMessage({ type: "DPI_STATE", dpiState: { dpiActive: false, dpiStrategy: null, dpiVerified: false, dpiCachedStrategy: stored.dpiCachedStrategy || null } }).catch(() => {});
          updateDpiBadge("off");
          done(() => { try { port.disconnect(); } catch (e) {} resolve({ ok: true }); });
        });
      });

      port.onDisconnect.addListener(() => {
        clearTimeout(timeout);
        dpiProcessActive = false;
        // Read lastError to suppress the "Unchecked runtime.lastError"
        // console warning that Chrome otherwise prints.
        const err = chrome.runtime.lastError && chrome.runtime.lastError.message;
        // Host unreachable (e.g. it already exited after a cancelled start):
        // make sure no stale "starting" state survives.
        TarnStorage.saveDpiState({
          dpiActive: false, dpiStarting: false,
          dpiProcessPid: null, dpiError: null, dpiTimestamp: Date.now()
        }).then(() => {
          chrome.runtime.sendMessage({ type: "DPI_STATE", dpiState: { dpiActive: false, dpiStarting: false, dpiStrategy: null, dpiVerified: false, dpiCachedStrategy: null } }).catch(() => {});
          done(() => resolve({ ok: true, _warn: err }));
        });
      });

      port.postMessage({ cmd: "stop_dpi" });
    });
  } catch (e) {
    return { ok: false, error: String(e && e.message || e) };
  }
}

async function dpiQueryStatus() {
  try {
    const settings = await TarnStorage.getSettings();
    const hostName = settings.nativeHostName || NATIVE_HOST_DEFAULT;
    const port = chrome.runtime.connectNative(hostName);

    const result = await new Promise((resolve) => {
      const timeout = setTimeout(() => {
        try { port.disconnect(); } catch (e) {}
        resolve({ ok: false, error: "timeout" });
      }, 5000);

      port.onMessage.addListener(async (msg) => {
        clearTimeout(timeout);
        if (!msg) { resolve({ ok: false, error: "empty_reply" }); return; }
        if (msg.status === "dpi_status") {
          const running = msg.running === true;
          const stored = await TarnStorage.getDpiState();
          const state = {
            dpiActive: running,
            dpiStarting: false,
            dpiProcessPid: msg.pid || null,
            dpiStrategy: running ? (msg.strategy || stored.dpiStrategy) : null,
            dpiVerified: running ? !!msg.verified : false,
            dpiCachedStrategy: msg.cachedStrategy || null,
            dpiError: running ? null : stored.dpiError,
            dpiTimestamp: running ? (stored.dpiTimestamp || Date.now()) : null,
            engineAvailable: msg.engineAvailable !== false,
          };
          await TarnStorage.saveDpiState(state);
          resolve({ ok: true, dpiState: state });
        } else if (msg.status === "error") {
          resolve({ ok: false, error: msg.message });
        } else {
          resolve({ ok: false, error: "unexpected response" });
        }
      });

      port.onDisconnect.addListener(() => {
        clearTimeout(timeout);
        // CRITICAL: read lastError.message — otherwise Chrome prints
        // "Unchecked runtime.lastError while running port.onDisconnect"
        const err = chrome.runtime.lastError && chrome.runtime.lastError.message;
        const mapped = mapNativeError(err);
        lastNativeError = mapped;
        chrome.storage.local.set({ "tarn.lastNativeError": mapped });
        resolve({ ok: false, error: mapped });
      });

      port.postMessage({ cmd: "dpi_status" });
    });

    return result;
  } catch (e) {
    const fallback = await TarnStorage.getDpiState();
    return { ok: true, dpiState: fallback };
  }
}

function updateDpiBadge(state) {
  if (state === "starting") dpiBadgeState = "starting";
  else if (state === "active" || state === true) dpiBadgeState = "active";
  else dpiBadgeState = "off";
  refreshBadge();
}

// ---- DPI strategy introspection / testing ----
async function dpiListStrategies() {
  try {
    const settings = await TarnStorage.getSettings();
    const port = chrome.runtime.connectNative(settings.nativeHostName || NATIVE_HOST_DEFAULT);
    const result = await new Promise((resolve) => {
      const timeout = setTimeout(() => {
        try { port.disconnect(); } catch (e) {}
        resolve({ ok: false, error: "timeout" });
      }, 5000);
      port.onMessage.addListener((msg) => {
        clearTimeout(timeout);
        if (msg.status === "dpi_list") {
          resolve({ ok: true, strategies: msg.strategies || [], current: msg.current || null, cached: msg.cached || null });
        } else if (msg.status === "error") {
          resolve({ ok: false, error: msg.message });
        }
      });
      port.onDisconnect.addListener(() => {
        clearTimeout(timeout);
        const err = chrome.runtime.lastError && chrome.runtime.lastError.message;
        resolve({ ok: false, error: mapNativeError(err) });
      });
      port.postMessage({ cmd: "dpi_list_strategies" });
    });
    return result;
  } catch (e) {
    return { ok: false, error: String(e && e.message || e) };
  }
}

async function dpiTestStrategies(opts = {}) {
  try {
    const settings = await TarnStorage.getSettings();
    const dpiSettings = await TarnStorage.getDpiSettings();
    const port = chrome.runtime.connectNative(settings.nativeHostName || NATIVE_HOST_DEFAULT);
    // Store the port so dpiTestControl can send cancel/pause/resume on the
    // SAME native-messaging connection (same OS process). A fresh connectNative
    // would launch a second host process whose DPI_TEST_CONTROL is idle and
    // would ignore the cancel.
    _dpiTestPort = port;
    // Whitelist-shaped inputs: the options page UI always sends well-formed
    // values, but a hostile caller must not be able to inject commands or
    // huge workloads through this message.
    opts = opts && typeof opts === "object" ? opts : {};
    const strategies = Array.isArray(opts.strategies)
      ? opts.strategies.filter(s => typeof s === "string" && s.length <= 128).slice(0, 20)
      : [];
    const passes = Math.min(10, Math.max(1, Math.floor(Number(opts.passes) || 2)));
    const probeTimeout = Math.min(60, Math.max(1, Math.floor(Number(opts.probeTimeout) || 4)));
    const minOk = Math.min(10, Math.max(1, Math.floor(Number(opts.minOk) || 3)));
    // Probe-target override: pass the user's list through; the native side
    // whitelist-validates it again (hostnames only, max 16).
    const probeHosts = Array.isArray(dpiSettings.dpiProbeHosts) && dpiSettings.dpiProbeHosts.length
      ? dpiSettings.dpiProbeHosts
      : [];
    const result = await new Promise((resolve) => {
      let timeout = null;
      const resetTimeout = () => {
        if (timeout) clearTimeout(timeout);
        timeout = setTimeout(() => {
          try { port.disconnect(); } catch (e) {}
          resolve({ ok: false, error: "Native host timeout" });
        }, 900000);
      };
      resetTimeout();
      port.onMessage.addListener((msg) => {
        if (msg.status === "dpi_test_progress") {
          resetTimeout();
          // Stream progress to the options page (any open window).
          chrome.runtime.sendMessage({ type: "DPI_TEST_PROGRESS", progress: msg }).catch(() => {});
          return;
        }
        clearTimeout(timeout);
        if (msg.status === "dpi_test_started") {
          chrome.runtime.sendMessage({ type: "DPI_TEST_PROGRESS", progress: { phase: "started" } }).catch(() => {});
        } else if (msg.status === "dpi_test") {
          const result = {
            ok: true,
            results: msg.results || {},
            ranking: msg.ranking || [],
            winner: msg.winner || null,
            cancelled: !!msg.cancelled,
            cleanup: msg.cleanup !== false,
          };
          // Persist the last test outcome so the options page can show it
          // again after a reload/reopen (not just right after the run).
          chrome.storage.local.set({ "tarn.dpiTestResult": {
            winner: result.winner,
            ranking: result.ranking,
            cancelled: result.cancelled,
            ts: Date.now()
          } }).catch(() => {});
          // Auto-apply the winner: the tested network is the one in use, so
          // the saved strategy must reflect the result (and the popup/options
          // UI should not stay on "auto" after a completed test).
          if (result.winner && !result.cancelled) {
            TarnStorage.saveDpiSettings({ dpiStrategy: result.winner }).catch(() => {});
          }
          _dpiTestPort = null;
          resolve(result);
        } else if (msg.status === "error") {
          _dpiTestPort = null;
          resolve({ ok: false, error: msg.message });
        }
      });
      port.onDisconnect.addListener(() => {
        clearTimeout(timeout);
        _dpiTestPort = null;
        const err = chrome.runtime.lastError && chrome.runtime.lastError.message;
        resolve({ ok: false, error: mapNativeError(err) });
      });
      port.postMessage({
        cmd: "dpi_test",
        strategies,
        passes,
        probeTimeout,
        minOk,
        probeHosts,
      });
    });
    return result;
  } catch (e) {
    return { ok: false, error: String(e && e.message || e) };
  }
}

async function dpiTestControl(action) {
  try {
    // CRITICAL: reuse the test port if a test is running. A fresh
    // connectNative() may launch a SECOND native-host process whose
    // DPI_TEST_CONTROL is idle — cancel/pause would be silently ignored.
    const port = _dpiTestPort || chrome.runtime.connectNative((await TarnStorage.getSettings()).nativeHostName || NATIVE_HOST_DEFAULT);
    const result = await new Promise((resolve) => {
      const timeout = setTimeout(() => {
        try { port.disconnect(); } catch (e) {}
        resolve({ ok: false, error: "timeout" });
      }, 5000);
      port.onMessage.addListener((msg) => {
        clearTimeout(timeout);
        if (["dpi_test_paused", "dpi_test_resumed", "dpi_test_cancelling", "dpi_test_idle"].includes(msg.status)) {
          resolve({ ok: true, status: msg.status });
        } else if (msg.status === "error") {
          resolve({ ok: false, error: msg.message });
        }
      });
      port.onDisconnect.addListener(() => {
        clearTimeout(timeout);
        const err = chrome.runtime.lastError && chrome.runtime.lastError.message;
        resolve({ ok: false, error: mapNativeError(err) });
      });
      // Only these three control verbs exist; anything else is rejected
      // instead of being concatenated into the cmd string.
      if (!["pause", "resume", "cancel"].includes(action)) {
        resolve({ ok: false, error: "invalid action" });
        return;
      }
      port.postMessage({ cmd: "dpi_test_" + action });
    });
    return result;
  } catch (e) {
    return { ok: false, error: String(e && e.message || e) };
  }
}

async function dpiDiagnostics() {
  try {
    const settings = await TarnStorage.getSettings();
    const port = chrome.runtime.connectNative(settings.nativeHostName || NATIVE_HOST_DEFAULT);
    const result = await new Promise((resolve) => {
      const timeout = setTimeout(() => {
        try { port.disconnect(); } catch (e) {}
        resolve({ ok: false, error: "timeout" });
      }, 60000);
      port.onMessage.addListener((msg) => {
        clearTimeout(timeout);
        if (msg.status === "diag_progress") {
          // Stream diagnostics progress to the options page (any open window).
          chrome.runtime.sendMessage({
            type: "DPI_DIAG_PROGRESS",
            done: msg.done || 0,
            total: msg.total || 1,
            phase: msg.phase || "",
          }).catch(() => {});
          return;
        }
        if (msg.status === "diagnostics") {
          resolve({ ok: true, diagnostics: msg.diagnostics || {} });
        } else if (msg.status === "error") {
          resolve({ ok: false, error: msg.message });
        }
      });
      port.onDisconnect.addListener(() => {
        clearTimeout(timeout);
        const err = chrome.runtime.lastError && chrome.runtime.lastError.message;
        resolve({ ok: false, error: mapNativeError(err) });
      });
      port.postMessage({ cmd: "diagnostics" });
    });
    return result;
  } catch (e) {
    return { ok: false, error: String(e && e.message || e) };
  }
}

// ---- antitrack: inject prototype patches into MAIN world ----
// Canonical MV3 pattern: chrome.scripting.executeScript from service worker
// with files: parameter (loads verbatim, closures preserved, no toString loss).
//
// CRITICAL FIX v1.9.20: Previous versions used func: parameter which serializes
// the function via toString(), destroying all closure references. This rewrite
// uses files: parameter instead — Chrome loads the script verbatim, preserving
// closures, "use strict", and all local state.
//
// Architecture:
//   - lib/antitrack-injected.js: applies patches (idempotent — checks window marker)
//   - lib/antitrack-remove.js: restores originals (reads from non-enumerable props)
//   - Originals stored as non-enumerable properties on patched functions
//   - Re-injection is safe (idempotent check prevents corruption)

(function () {
  "use strict";

  function shouldActivate(state, dpiSettings) {
    if (!state || state.status !== "connected") return false;
    return !dpiSettings || dpiSettings.dpiAntiTrack !== false;
  }

  // Sync patches across all tabs
  const _ANTITRACK_EXCLUDE = (() => {
    try {
      const cs = chrome.runtime.getManifest().content_scripts || [];
      const pats = [];
      for (const c of cs) for (const p of c.exclude_matches || []) pats.push(p);
      return pats;
    } catch (_) { return []; }
  })();

  function _urlExcluded(url) {
    if (!url) return true;
    for (const pat of _ANTITRACK_EXCLUDE) {
      if (!pat) continue;
      if (pat === "<all_urls>") continue;
      const m = /^(\*|https?):\/\/(\*|(?:[A-Za-z0-9.-]+|\*\.[A-Za-z0-9.-]+))(?::(\d+))?(\/.*)?$/.exec(pat);
      if (!m) continue;
      let u;
      try { u = new URL(url); } catch (_) { continue; }
      if (m[1] !== "*" && u.protocol.replace(":", "") !== m[1]) continue;
      const hostPat = m[2];
      if (hostPat.startsWith("*.")) {
        const bare = hostPat.slice(2);
        if (!u.hostname.endsWith(bare) && u.hostname !== bare) continue;
      } else if (hostPat !== "*" && u.hostname !== hostPat) {
        continue;
      }
      return true;
    }
    return false;
  }

  async function antitrackSyncTabs() {
    let result;
    try {
      result = await chrome.storage.local.get(["tarn.state", "tarn.dpiSettings"]);
    } catch (_) { return; }

    const state = result["tarn.state"];
    const dpiSettings = result["tarn.dpiSettings"];
    const wanted = shouldActivate(state, dpiSettings);

    // files: parameter — load verbatim (no toString serialization)
    const files = wanted ? ["lib/antitrack-injected.js"] : ["lib/antitrack-remove.js"];

    let tabs;
    try {
      tabs = await chrome.tabs.query({});
    } catch (_) { return; }

    for (const tab of tabs) {
      if (!tab.id || tab.id < 0) continue;
      if (!tab.url || tab.url.startsWith("chrome://") || tab.url.startsWith("chrome-extension://") || tab.url.startsWith("devtools://")) continue;
      // Honor the manifest content-script exclusion list (banks, payments,
      // stores) for MAIN-world injections too: these pages must not receive
      // anti-fingerprint patches, exactly like the isolated-world shim.
      if (_urlExcluded(tab.url)) continue;
      try {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id, allFrames: true },
          world: "MAIN",
          files: files,
          injectImmediately: true  // inject at document_start (before page scripts)
        });
      } catch (_) {}
    }
  }

  // Listeners
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    if (changes["tarn.state"] || changes["tarn.dpiSettings"]) antitrackSyncTabs();
  });

  // Re-inject on tab navigation (SPA support).
  // changeInfo.url is set on BOTH full navigation AND SPA route changes
  // (pushState/replaceState fire {url: "..."} without status change).
  // We don't check changeInfo.status — only that the URL changed.
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (!changeInfo.url) return;
    if (changeInfo.url.startsWith("chrome://") || changeInfo.url.startsWith("chrome-extension://") || changeInfo.url.startsWith("devtools://")) return;
    antitrackSyncTabs();
  });

  chrome.runtime.onInstalled.addListener(() => antitrackSyncTabs());
  chrome.runtime.onStartup.addListener(() => antitrackSyncTabs());

  // Initial sync
  antitrackSyncTabs();
})();
