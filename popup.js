// popup.js — popup UI with i18n, real tunnel only
// SPDX-License-Identifier: GPL-3.0-only

const $ = (id) => document.getElementById(id);

let currentStatus = "disconnected";
let nativeHostAvailable = false;
let hostInstallWatch = null;
let lang = "ru";

function t(key) { return TarnI18n.t(lang, key); }

function applyLang() {
  TarnI18n.applyI18n(lang);
}

document.addEventListener("DOMContentLoaded", init);

async function init() {
  await TarnStorage.migrateLegacy();
  const s = await chrome.storage.local.get("tarn.lang");
  const stored = s["tarn.lang"];
  lang = (stored && stored !== "auto") ? stored : TarnI18n.detectSystemLang();

  $("optionsBtn").addEventListener("click", () => chrome.runtime.openOptionsPage());
  $("addProfile").addEventListener("click", () => chrome.runtime.openOptionsPage());
  $("checkIp").addEventListener("click", () => chrome.tabs.create({ url: "https://ifconfig.me" }));
  $("leakTest").addEventListener("click", () => chrome.tabs.create({ url: "https://browserleaks.com/dns" }));
  $("autoSettingsBtn").addEventListener("click", () => {
    // spotlight=test makes the "Full strategy test" button blink once in
    // the options page (attention cue, never repeats on later visits).
    chrome.tabs.create({ url: chrome.runtime.getURL("options.html?tab=dpi&spotlight=test") });
  });

  $("connectBtn").addEventListener("click", onConnect);
  $("disconnectBtn").addEventListener("click", onDisconnect);
  $("dpiToggleBtn").addEventListener("click", onDpiToggle);
  $("profileSelect").addEventListener("change", async (e) => {
    const id = e.target.value;
    await TarnStorage.setActiveId(id || null);
    updateConnectBtn();
  });

  // Star badge: show if earned in game
  chrome.storage.local.get("tarn.gameStar", (d) => {
    if (d["tarn.gameStar"]) $("starBadge").style.display = "inline-flex";
  });

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.type === "STATE") renderState(msg.state);
    if (msg?.type === "GAME_STAR") {
      $("starBadge").style.display = "inline-flex";
    }
    if (msg?.type === "STATS") {
      renderStats(msg.stats);
      // Update mascot directly from stats — storage.onChanged can be unreliable in MV3
      chrome.storage.local.get(["tarn.state", "tarn.dpiState"], (data) => {
        const state = data["tarn.state"];
        const dpi = data["tarn.dpiState"];
        if (state) {
          lastDpiActive = !!(dpi && dpi.dpiActive);
          updateMascot(state, lastDpiActive, lastDpiStarting);
        }
      });
    }
    if (msg?.type === "IP_CHECK") {
      $("publicIp").textContent = msg.ip || "—";
    }
    if (msg?.type === "DPI_STATE") renderDpiState(msg.dpiState);
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    if (changes["tarn.state"]) {
      renderState(changes["tarn.state"].newValue || { status: "disconnected" });
    }
    if (changes["tarn.dpiState"] || changes["tarn.dpiSettings"]) {
      // Committed writes only - safe to re-evaluate the banner here
      // (no transient gap, no flicker).
      refreshAutoBanner();
    }
    if (changes["tarn.lang"]) {
      const v = changes["tarn.lang"].newValue;
      lang = (v && v !== "auto") ? v : TarnI18n.detectSystemLang();
      applyLang();
      refreshState();
    }
  });

  applyLang();
  await refreshProfiles();
  await refreshState();
  await refreshDpiState();
  // refreshDpiState resolved => background already committed the fresh
  // DPI state to storage (dpiQueryStatus saves before resolving), so a
  // storage read here is authoritative - no banner flicker on open.
  refreshAutoBanner();
}

async function refreshProfiles() {
  let resp;
  try {
    resp = await Promise.race([
      chrome.runtime.sendMessage({ type: "GET_PROFILES" }),
      new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 4000))
    ]);
  } catch (e) {
    const profiles = await TarnStorage.getProfiles();
    const activeId = await TarnStorage.getActiveId();
    resp = { ok: true, profiles, activeId };
  }
  const sel = $("profileSelect");
  const profiles = resp?.profiles || [];
  const activeId = resp?.activeId;

  if (!profiles.length) {
    sel.innerHTML = `<option value="">${t("noProfiles")}</option>`;
    $("connectBtn").disabled = true;
    return;
  }
  sel.innerHTML = profiles.map(p =>
    `<option value="${escapeHtml(p.id)}" ${p.id === activeId ? "selected" : ""}>${escapeHtml(p.name)}</option>`
  ).join("");
  updateConnectBtn();
}

async function refreshState() {
  let resp;
  try {
    resp = await Promise.race([
      chrome.runtime.sendMessage({ type: "GET_STATE" }),
      new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 4000))
    ]);
  } catch (e) {
    const state = await TarnStorage.getState();
    resp = { ok: true, state, nativeAvailable: false };
  }
  nativeHostAvailable = resp?.nativeAvailable === true;
  const state = resp?.state || { status: "disconnected" };
  renderState(state);
  if (!nativeHostAvailable) {
    // The native host may still be registering (install.bat running right
    // now). GET_STATE re-pings on every open, but the host only appears
    // mid-install — poll until it does, so the banner flips to "available"
    // without closing/reopening the popup.
    startHostInstallWatch();
  }
}

function startHostInstallWatch() {
  // install.bat can take a minute (25MB engine copy + UAC service
  // creation), so a single re-check isn't enough: poll the native host
  // until it registers, then re-render. Polling dies with the popup;
  // while no host exists each tick is a fast-failing connectNative.
  if (hostInstallWatch) return;
  let busy = false;
  hostInstallWatch = setInterval(async () => {
    if (busy) return;
    busy = true;
    try {
      const r = await chrome.runtime.sendMessage({ type: "PING_NATIVE" });
      if (r?.available === true) {
        clearInterval(hostInstallWatch);
        hostInstallWatch = null;
        await refreshState();
      }
    } catch (e) { /* popup closed — ignore */ }
    finally { busy = false; }
  }, 3000);
}

async function onConnect() {
  const id = $("profileSelect").value;
  if (!id) return;
  $("connectBtn").disabled = true;
  const r = await chrome.runtime.sendMessage({ type: "CONNECT", profileId: id });
  if (!r?.ok) {
    renderState({ status: "error", error: r?.error || t("connectErr") });
  }
}

async function onDisconnect() {
  $("disconnectBtn").disabled = true;
  await chrome.runtime.sendMessage({ type: "DISCONNECT" });
}

function updateConnectBtn() {
  $("connectBtn").disabled = !$("profileSelect").value ||
    currentStatus === "connected" ||
    currentStatus === "connecting" ||
    currentStatus === "reconnecting";
}

function renderState(state) {
  currentStatus = state.status;

  // Update mascot based on state
  updateMascot(state, lastDpiActive, lastDpiStarting);

  const el = $("status");
  el.className = "status " + state.status;
  const dot = el.querySelector(".dot");
  dot.classList.toggle("pulse", state.status === "connecting" || state.status === "reconnecting");

  const map = {
    disconnected: t("disconnected"),
    connecting: t("connecting"),
    connected: t("connected"),
    reconnecting: t("reconnecting"),
    error: t("error")
  };
  $("statusText").textContent = state.status === "error" && state.error
    ? state.error
    : (map[state.status] || state.status);

  // Combined status card: while connected the grey status bar is hidden and the
  // green real-banner shows "Подключено" + traffic + IP instead — no duplicate
  // cards taking vertical space. All other states keep the status bar.
  const installBanner = $("installBanner");
  const realBanner = $("realBanner");
  const tunnelWarning = $("tunnelWarning");

  if (state.status === "connected") {
    el.style.display = "none";
    installBanner.style.display = "none";
    if (tunnelWarning) tunnelWarning.style.display = state._tunnelAlive === false ? "" : "none";
    realBanner.style.display = state._tunnelAlive === false ? "none" : "flex";
    if (state.publicIp) {
      $("publicIp").textContent = state.publicIp;
    } else if (state._tunnelAlive === false) {
      $("publicIp").textContent = "—";
    } else {
      $("publicIp").textContent = t("checking");
    }
  } else {
    el.style.display = "";
    installBanner.style.display = (!nativeHostAvailable && state.status !== "connected") ? "flex" : "none";
    realBanner.style.display = "none";
    if (tunnelWarning) tunnelWarning.style.display = "none";
  }

  updateConnectBtn();
  // Disconnect must work in "error" state too — it stops the (possibly still
  // running) native host and resets the UI.
  $("disconnectBtn").disabled = !["connected", "connecting", "reconnecting", "error"].includes(state.status);

  if (state.status === "connected" && state._uptime) {
    $("uptimeVal").textContent = formatDuration(state._uptime);
  } else if (state.since && state.status === "connected") {
    $("uptimeVal").textContent = formatDuration(Math.floor((Date.now() - state.since) / 1000));
  } else {
    $("uptimeVal").textContent = "—";
  }

  if (state.status !== "connected") {
    $("statPing").innerHTML = '— <small>ms</small>';
  } else {
    // Only show ping if tunnel is alive and latency is meaningful (>2ms)
    const lat = Number(state._latency);
    if (state._tunnelAlive === false || !Number.isFinite(lat) || lat < 2) {
      $("statPing").innerHTML = '— <small>ms</small>';
    } else {
      $("statPing").innerHTML = Math.round(lat) + ' <small>ms</small>';
    }
  }
}

function formatDuration(s) {
  if (!s || s < 0) return "—";
  s = Math.floor(s);
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m " + (s % 60) + "s";
  return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m";
}

function renderStats(stats) {
  if (!stats) return;
  // Ignore stats while in error/disconnected — the background already froze
  // the uptime there, and rendering late stats would show a stale value.
  if (currentStatus === "error" || currentStatus === "disconnected") return;
  // Only show ping if tunnel is alive and latency is meaningful
  const lat = Number(stats.latency);
  if (stats.tunnelAlive === false || !Number.isFinite(lat) || lat < 2) {
    $("statPing").innerHTML = '— <small>ms</small>';
  } else {
    $("statPing").innerHTML = Math.round(lat) + ' <small>ms</small>';
  }
  if (stats.uptime != null) $("uptimeVal").textContent = formatDuration(stats.uptime);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ---- Mascot state management ----
let mascotAnimFrame = 0;
let mascotAnimInterval = null;
let lastDpiActive = false;
let lastDpiStarting = false;

function updateMascot(state, dpiActive, dpiStarting) {
  const img = $("mascotImg");
  if (!img) return;

  // Clear any running animation
  if (mascotAnimInterval) {
    clearInterval(mascotAnimInterval);
    mascotAnimInterval = null;
  }

  const status = state.status || "disconnected";

  // Helper: start frame animation
  function startAnim(prefix, count, speed) {
    mascotAnimFrame = 0;
    img.src = `mascot/${prefix}1.png`;
    img.style.animation = "mascotBounce 0.4s ease-in-out infinite";
    mascotAnimInterval = setInterval(() => {
      mascotAnimFrame = (mascotAnimFrame + 1) % count;
      img.src = `mascot/${prefix}${mascotAnimFrame + 1}.png`;
    }, speed);
  }

  switch (status) {
    case "disconnected":
      if (dpiStarting) {
        startAnim("run", 4, 150);
      } else if (dpiActive) {
        startAnim("shield", 4, 250);
      } else {
        img.src = "mascot/sit.png";
        img.style.animation = "";
      }
      break;
    case "connecting":
    case "reconnecting":
      startAnim("run", 4, 150);
      break;
    case "connected":
      if (state._tunnelAlive === false) {
        img.src = "mascot/sad.png";
        img.style.animation = "";
      } else if (dpiStarting || !state.publicIp) {
        startAnim("run", 4, 150);
      } else if (dpiActive) {
        startAnim("shield", 4, 250);
      } else {
        img.src = "mascot/joy.png";
        img.style.animation = "mascotBounce 0.6s ease-in-out infinite";
      }
      break;
    case "error":
      img.src = "mascot/angry.png";
      img.style.animation = "";
      break;
    default:
      img.src = "mascot/sit.png";
      img.style.animation = "";
  }
}

// ---- DPI functions ----

async function refreshDpiState() {
  let resp;
  try {
    resp = await Promise.race([
      chrome.runtime.sendMessage({ type: "DPI_STATUS" }),
      new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 4000))
    ]);
  } catch (e) {
    const dpiState = await TarnStorage.getDpiState();
    resp = { ok: true, dpiState };
  }
  renderDpiState(resp?.dpiState || { dpiActive: false });
}

// First-run guidance banner: "auto may silently pick a strategy that
// fails on this network (e.g. fake-based over high-jitter WiFi)".
// Deliberately derived ONLY from committed storage (settings + saved
// DPI state) - never from transient DPI_STATE push payloads, which may
// lack dpiCachedStrategy and caused a flicker on every enable/disable.
// Hidden while the bypass is active or starting (a probe is literally
// testing strategies right now, no guidance needed).
async function refreshAutoBanner() {
  if (!nativeHostAvailable) {
    $("autoBanner").style.display = "none";
    return;
  }
  const [settings, dpiState] = await Promise.all([
    TarnStorage.getDpiSettings(),
    TarnStorage.getDpiState()
  ]);
  const strategy = settings.dpiStrategy || "auto";
  const cached = dpiState.dpiCachedStrategy || null;
  const busy = !!(dpiState.dpiActive || dpiState.dpiStarting);
  const show = strategy === "auto" && !cached && !busy;
  $("autoBanner").style.display = show ? "flex" : "none";
}

function renderDpiState(dpiState) {
  const statusEl = $("dpiStatus");
  const toggleBtn = $("dpiToggleBtn");

  // NOTE: the auto-strategy banner is NOT derived here. Transient
  // DPI_STATE pushes may omit dpiCachedStrategy (falsy = "no cache"),
  // which flickered the banner on every enable/disable. It is now
  // computed in refreshAutoBanner() from committed storage only.

  if (dpiState.dpiStarting) {
    statusEl.textContent = t("dpiStarting");
    statusEl.className = "dpi-status busy";
    $("dpiDot").className = "dot dpi-dot busy";
    toggleBtn.querySelector("span").textContent = t("dpiDisable");
    toggleBtn.classList.add("active");
  } else if (dpiState.dpiActive) {
    statusEl.textContent = t("dpiOn");
    statusEl.className = "dpi-status active";
    $("dpiDot").className = "dot dpi-dot active";
    if (dpiState.dpiStrategy) {
      const name = TarnI18n.t(lang, "dpiStrategyName_" + dpiState.dpiStrategy);
      statusEl.textContent = t("dpiOn") + " · " + name;
    }
    toggleBtn.querySelector("span").textContent = t("dpiDisable");
    toggleBtn.classList.add("active");
  } else {
    statusEl.textContent = t("dpiOff");
    statusEl.className = "dpi-status";
    $("dpiDot").className = "dot dpi-dot";
    toggleBtn.querySelector("span").textContent = t("dpiEnable");
    toggleBtn.classList.remove("active");
  }

  // Update mascot when DPI state changes (any tunnel status)
  lastDpiActive = !!dpiState.dpiActive;
  lastDpiStarting = !!dpiState.dpiStarting;
  chrome.storage.local.get("tarn.state", (data) => {
    const state = data["tarn.state"];
    if (state) updateMascot(state, lastDpiActive, lastDpiStarting);
  });

  // Display DPI warnings (e.g. DoH requires admin)
  renderDpiWarnings(dpiState.dpiWarnings);
}

function renderDpiWarnings(warnings) {
  const existing = document.getElementById("dpiWarnings");
  if (!warnings || !warnings.length) {
    if (existing) existing.remove();
    return;
  }
  let el = existing;
  if (!el) {
    el = document.createElement("div");
    el.id = "dpiWarnings";
    el.className = "dpi-warn-banner";
    const statusEl = document.getElementById("dpiStatus");
    if (statusEl && statusEl.parentNode) {
      statusEl.parentNode.insertBefore(el, statusEl.nextSibling);
    }
  }
  el.innerHTML = "&#9888; " + warnings.map(escapeHtml).join("<br>&#9888; ");
}

async function onDpiToggle() {
  const toggleBtn = $("dpiToggleBtn");
  // Determine the REAL DPI state from the latest query, NOT from the button's
  // CSS class. The class can drift out of sync (e.g. after a native host crash
  // or a start that is still probing), and using it would make the toggle do
  // the opposite of what the user expects.
  let current = { dpiActive: false, dpiStarting: false };
  try {
    const resp = await chrome.runtime.sendMessage({ type: "DPI_STATUS" });
    if (resp?.ok && resp.dpiState) current = resp.dpiState;
  } catch (e) {
    // Fall back to the button's visual state only if the query itself fails.
    current = { dpiActive: toggleBtn.classList.contains("active"), dpiStarting: false };
  }

  if (current.dpiActive || current.dpiStarting) {
    // STOP (or cancel an in-flight start)
    toggleBtn.disabled = true;
    const r = await chrome.runtime.sendMessage({ type: "DPI_STOP" });
    toggleBtn.disabled = false;
    if (r && !r.ok) {
      // The stop failed (elevated winws could not be killed) - keep the
      // button in the active state and surface the real error.
      $("dpiStatus").textContent = r.error || t("dpiOff");
      $("dpiStatus").className = "dpi-status error";
      $("dpiDot").className = "dot dpi-dot";
      toggleBtn.querySelector("span").textContent = t("dpiDisable");
      toggleBtn.classList.add("active");
    } else {
      $("dpiStatus").textContent = t("dpiOff");
      $("dpiStatus").className = "dpi-status";
      $("dpiDot").className = "dot dpi-dot";
      toggleBtn.querySelector("span").textContent = t("dpiEnable");
      toggleBtn.classList.remove("active");
    }
  } else {
    // START
    toggleBtn.disabled = true;
    $("dpiStatus").textContent = t("dpiStarting");
    $("dpiStatus").className = "dpi-status busy";
    $("dpiDot").className = "dot dpi-dot busy";
    // A probe is about to run - the banner ("run the full test") would
    // contradict the auto-probe already in progress, and the state is
    // mid-transition. Hide now; storage onChanged re-evaluates after
    // the start commits (or on failure, when it will come back).
    $("autoBanner").style.display = "none";
    const r = await chrome.runtime.sendMessage({ type: "DPI_START" });
    toggleBtn.disabled = false;
    if (r && !r.ok) {
      $("dpiStatus").textContent = r.error || "error";
      $("dpiStatus").className = "dpi-status error";
      $("dpiDot").className = "dot dpi-dot";
      toggleBtn.querySelector("span").textContent = t("dpiEnable");
      toggleBtn.classList.remove("active");
    }
  }
  await refreshDpiState();
}
