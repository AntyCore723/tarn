// options.js — full options page: profiles, settings, stats, install, i18n
// SPDX-License-Identifier: GPL-3.0-only

const $ = (id) => document.getElementById(id);

let lastValidation = null;
let currentSettings = null;
let editingProfileId = null;
let savingInProgress = false;
let optionsLang = "ru";

function ot(key) { return TarnI18n.t(optionsLang, key); }

function applyLangToOptions(langCode) {
  optionsLang = langCode;
  TarnI18n.applyI18n(langCode);

  // Re-apply dynamic text that was set directly via textContent (these bypass
  // the data-i18n system and won't update automatically on language switch).
  updateHealthBadge();
  const nativeOk = $("nativeCard")?.classList.contains("ok");
  const wpOk = $("wireproxyCard")?.classList.contains("ok");
  if (!nativeOk) {
    const el = $("nativeStatusText");
    if (el) el.textContent = ot("healthCheck");
  }
  if (!wpOk) {
    const el = $("wireproxyStatusText");
    if (el) el.textContent = ot("healthCheck");
  }
  // Re-render stats table (uses ot() for "no data" message)
  refreshStats();

  // Update dynamically created tag input placeholders
  document.querySelectorAll(".tag-input").forEach(input => {
    input.placeholder = ot("tagPH");
  });
}

document.addEventListener("DOMContentLoaded", init);

async function init() {
  await TarnStorage.migrateLegacy();
  document.querySelectorAll(".tab").forEach(t => {
    t.addEventListener("click", () => switchTab(t.dataset.tab));
  });

  const params = new URLSearchParams(location.search);
  if (params.get("welcome") === "1") {
    $("welcomeAlert").innerHTML = `
      <div class="alert info">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
        <div><strong data-i18n="welcomeTitle">Добро пожаловать!</strong> <span data-i18n="welcomeDesc">Добавь свой WG конфиг во вкладке «Добавить». Для РЕАЛЬНОГО туннеля установи native host + wireproxy — см. вкладку «Установка». Без них работает только симуляция (парсинг, QR, хранилище).</span></div>
      </div>`;
    switchTab("add");
  }
  // Deep link from the popup banner: land directly on the DPI tab.
  if (params.get("tab") === "dpi") {
    switchTab("dpi");
  }
  // One-shot attention cue: when the user is redirected here from the
  // popup banner, the "Full strategy test" button blinks once (it stops
  // on hover/click and never comes back on later visits).
  if (params.get("spotlight") === "test" && !sessionStorage.getItem("tarn.spotlightTest")) {
    sessionStorage.setItem("tarn.spotlightTest", "1");
    const testBtn = $("dpiTestBtn");
    if (testBtn) {
      testBtn.classList.add("test-blink");
      // The CSS :hover rule makes it burn solid while hovered; the cue
      // permanently disappears on click or after 25 s.
      const stopBlink = () => {
        testBtn.classList.remove("test-blink");
        testBtn.removeEventListener("click", stopBlink);
      };
      testBtn.addEventListener("click", stopBlink);
      setTimeout(stopBlink, 25000);
      // Center the blinking button in the viewport regardless of screen
      // size. Fonts/mascots load after first paint, so repeat the scroll
      // a few times to compensate for late layout shifts.
      const centerTestBtn = () => {
        if (testBtn.scrollIntoView) testBtn.scrollIntoView({ behavior: "smooth", block: "center" });
      };
      requestAnimationFrame(centerTestBtn);
      setTimeout(centerTestBtn, 650);
      setTimeout(centerTestBtn, 1500);
    }
  }

  maybeShowWelcome();

  $("validateBtn").addEventListener("click", validateConfig);
  $("genKeyBtn").addEventListener("click", generateKeys);
  $("clearBtn").addEventListener("click", clearForm);
  $("saveProfileBtn").addEventListener("click", () => saveProfile(false));
  $("saveAndConnectBtn").addEventListener("click", () => saveProfile(true));

  const dz = $("dropzone"), fileInput = $("fileInput");
  dz.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", async (e) => {
    const f = e.target.files?.[0]; if (!f) return;
    $("configInput").value = await f.text();
    if (!$("nameInput").value) $("nameInput").value = f.name.replace(/\.conf$/i, "");
    validateConfig();
  });
  ["dragenter", "dragover"].forEach(ev => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("drag"); }));
  ["dragleave", "drop"].forEach(ev => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("drag"); }));
  dz.addEventListener("drop", async (e) => {
    const f = e.dataTransfer?.files?.[0]; if (!f) return;
    $("configInput").value = await f.text();
    if (!$("nameInput").value) $("nameInput").value = f.name.replace(/\.conf$/i, "");
    validateConfig();
  });

  $("goAddBtn").addEventListener("click", () => switchTab("add"));
  $("exportBtn").addEventListener("click", exportBackup);
  $("importBtn").addEventListener("click", () => $("importFile").click());
  $("importFile").addEventListener("change", importBackup);

  // game
  initGame();

  // star badge
  chrome.storage.local.get("tarn.gameStar", (d) => {
    if (d["tarn.gameStar"]) $("starBadge").style.display = "inline-flex";
  });
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.type === "GAME_STAR") $("starBadge").style.display = "inline-flex";
    if (msg?.type === "DPI_TEST_PROGRESS" && dpiTestActive) renderDpiTestProgress(msg.progress);
    if (msg?.type === "DPI_DIAG_PROGRESS" && dpiDiagActive) updateDiagProgress(msg);
  });

  // settings
  $("setLang").addEventListener("change", async () => {
    const val = $("setLang").value;
    await chrome.storage.local.set({ "tarn.lang": val });
    // Reload the page so every element (including dynamic ones) picks up the
    // new language. The stored lang is read back on load and applied fully.
    location.reload();
  });
  $("setMode").addEventListener("change", () => saveSetting("mode", $("setMode").value));
  $("setHostName").addEventListener("change", () => saveSetting("nativeHostName", $("setHostName").value));
  $("setSocksHost").addEventListener("change", () => saveSetting("socksHost", $("setSocksHost").value));
  $("setSocksPort").addEventListener("change", () => saveSetting("socksPort", parseInt($("setSocksPort").value, 10) || 1080));
  $("setAutoConnect").addEventListener("change", () => saveSetting("autoConnect", $("setAutoConnect").checked));
  $("setKillSwitch").addEventListener("change", () => saveSetting("killSwitch", $("setKillSwitch").checked));
  $("setWebrtc").addEventListener("change", () => saveSetting("webrtcProtection", $("setWebrtc").checked));
  $("setDisableQuic").addEventListener("change", () => saveSetting("disableQuic", $("setDisableQuic").checked));
  $("setVerifyIp").addEventListener("change", () => saveSetting("verifyIp", $("setVerifyIp").checked));
  $("setStatsEnabled").addEventListener("change", () => {
    saveSetting("statsEnabled", $("setStatsEnabled").checked);
    updateStatsVisibility();
  });
  $("setSplit").addEventListener("change", () => saveSetting("splitTunneling", $("setSplit").checked));
  $("setSplitMode").addEventListener("change", () => saveSetting("splitMode", $("setSplitMode").value));

  $("pingNativeBtn").addEventListener("click", pingNative);
  $("checkWpBtn").addEventListener("click", checkWireproxy);

  $("resetStatsBtn").addEventListener("click", resetStats);

  // DPI handlers
  $("dpiStartBtn").addEventListener("click", dpiStart);
  $("dpiStopBtn").addEventListener("click", dpiStop);
  $("dpiForceDoh").addEventListener("change", () => saveDpiSetting("dpiForceDoh", $("dpiForceDoh").checked));
  $("dpiBlockQuic").addEventListener("change", () => saveDpiSetting("dpiBlockQuic", $("dpiBlockQuic").checked));
  $("dpiStripHeaders").addEventListener("change", () => saveDpiSetting("dpiStripHeaders", $("dpiStripHeaders").checked));
  $("dpiGameFilter").addEventListener("change", () => saveDpiSetting("dpiGameFilter", $("dpiGameFilter").checked));
  $("dpiAdBlock").addEventListener("change", async () => {
    const on = $("dpiAdBlock").checked;
    await saveDpiSetting("dpiAdBlock", on);
    try { await TarnBlockAds.apply(on); } catch (e) {}
  });
  $("dpiAntiTrack").addEventListener("change", () => saveDpiSetting("dpiAntiTrack", $("dpiAntiTrack").checked));
  $("dpiAutoStart").addEventListener("change", () => saveDpiSetting("dpiAutoStartWithWg", $("dpiAutoStart").checked));
  $("dpiStrategy").addEventListener("change", () => saveDpiSetting("dpiStrategy", $("dpiStrategy").value));
  $("dpiSaveStrategyBtn").addEventListener("click", async () => {
    await saveDpiSetting("dpiStrategy", $("dpiStrategy").value);
    $("dpiTestResults").textContent = TarnI18n.t(optionsLang, "dpiStrategySaved");
  });
  $("dpiTestBtn").addEventListener("click", dpiTestStrategies);
  $("dpiTestPauseBtn").addEventListener("click", dpiTestPauseToggle);
  $("dpiTestStopBtn").addEventListener("click", dpiTestStop);
  $("dpiDiagBtn").addEventListener("click", dpiDiagnostics);
  $("dpiDiagCopyBtn").addEventListener("click", () => {
    const txt = $("dpiDiagOutput").innerText || "";
    navigator.clipboard.writeText(txt).catch(() => {});
  });

  // Apply language
  const langSetting = await chrome.storage.local.get("tarn.lang");
  const storedLang = langSetting["tarn.lang"] || "auto";
  $("setLang").value = storedLang;
  applyLangToOptions(storedLang === "auto" ? TarnI18n.detectSystemLang() : storedLang);

  await loadSettings();
  await loadDpiSettings();
  renderLastDpiTestResult();
  await refreshProfiles();
  await refreshStats();
  updateStatsVisibility();

  // Real-time DPI state sync from the background service worker.
  // When the popup toggles the filter (or the filter crashes), the background
  // broadcasts DPI_STATE — update the options-page UI without a reload.
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.type === "DPI_STATE") {
      renderDpiStatus(msg.dpiState);
    }
    if (msg?.type === "DPI_TEST_PROGRESS" && dpiTestActive) {
      renderDpiTestProgress(msg.progress);
    }
  });

  // Restore the last active tab (survives page reload / reopen).
  try {
    const savedTab = await chrome.storage.local.get("tarn.activeTab");
    if (savedTab["tarn.activeTab"]) switchTab(savedTab["tarn.activeTab"]);
  } catch (e) {}

  // Health self-heal: the very first ping can lose a race with the host's
  // self-update (the extension pushes a newer host script right after the
  // SW's startup ping; a host instance starting during the atomic file
  // replace can briefly fail). Retry with backoff until stable, then keep a
  // slow periodic re-check so a stale "tunnel unavailable" never sticks
  // until a manual reload / re-run of install.bat.
  let healthRetries = 0;
  const healthMaxRetries = 6;
  const runHealthCheck = async () => {
    await Promise.all([pingNative(), checkWireproxy()]);
    const nativeOk = $("nativeCard").classList.contains("ok");
    const wpOk = $("wireproxyCard").classList.contains("ok");
    if (nativeOk && wpOk) {
      healthRetries = 0;
      setTimeout(runHealthCheck, 30000);
    } else if (healthRetries < healthMaxRetries) {
      healthRetries++;
      setTimeout(runHealthCheck, 1500);
    } else {
      healthRetries = 0;
      setTimeout(runHealthCheck, 30000);
    }
  };
  runHealthCheck();
}

function switchTab(name) {
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".panel").forEach(p => p.classList.toggle("active", p.id === "panel-" + name));
  if (name === "profiles") refreshProfiles();
  if (name === "stats") refreshStats();
  if (name === "add" && !editingProfileId) {
    const heading = $("addHeading");
    if (heading) heading.textContent = ot("addHeading");
  }
  if (name === "install") {
    const extId = chrome.runtime.id;
    const el = $("extIdDisplay");
    if (el && extId) {
      el.innerHTML = `${ot("extId")} <code style="background:var(--card-2);padding:2px 6px;border-radius:2px;border:1px solid var(--border);color:var(--accent);font-family:var(--font-mono);font-size:12px">${escapeHtml(extId)}</code> <button class="btn" style="padding:2px 8px;font-size:10px;margin-left:6px" id="copyExtIdBtn">${ot("copyBtn")}</button>`;
      $("copyExtIdBtn").addEventListener("click", function() {
        navigator.clipboard.writeText(extId);
        this.textContent = ot("copied");
      });
    }
  }
  // Persist the active tab so a page reload lands the user back here.
  chrome.storage.local.set({ "tarn.activeTab": name }).catch(() => {});
}

// First-run welcome: explains what the extension does and how to use it.
// Shown over the page on a fresh install (?welcome=1 from onInstalled) and
// on the very first visit otherwise; the OK button confirms the user read
// it and stores a one-time flag so it never shows again.
async function maybeShowWelcome() {
  const modal = $("welcomeModal");
  if (!modal) return;
  const forced = new URLSearchParams(location.search).get("welcome") === "1";
  let seen = false;
  try {
    const d = await chrome.storage.local.get("tarn.welcomeSeen");
    seen = !!d["tarn.welcomeSeen"];
  } catch (e) {}
  if (!forced && seen) return;
  modal.style.display = "grid";
  $("welcomeModalOk").addEventListener("click", async () => {
    try { await chrome.storage.local.set({ "tarn.welcomeSeen": true }); } catch (e) {}
    modal.style.display = "none";
    if (forced) {
      const clean = location.search.replace(/([?&])welcome=1(&|$)/, "$1").replace(/[?&]$/, "");
      history.replaceState(null, "", location.pathname + clean);
    }
  });
}

// ---- config validation ----
function validateConfig() {
  const text = $("configInput").value;
  const result = TarnParser.parseConfig(text);
  const el = $("validationResult");
  const prev = $("preview");

  if (!text.trim()) {
    el.innerHTML = "";
    prev.innerHTML = "";
    lastValidation = null;
    $("saveProfileBtn").disabled = true;
    $("saveAndConnectBtn").disabled = true;
    return;
  }

  if (result.ok) {
    const pubKey = result.config.publicKey ? result.config.publicKey.slice(0, 12) + "…" : "—";
    el.innerHTML = `
      <div class="vresult ok">
        <div class="title">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>
          ${ot("valid")}
        </div>
        ${result.warnings.length ? `<div style="color:var(--warn);margin-bottom:4px">${ot("warnings")}</div><ul>${result.warnings.map(w => `<li>${escapeHtml(w)}</li>`).join("")}</ul>` : ""}
        <div style="margin-top:6px;color:var(--muted)">${ot("derivedKey")} <code style="color:var(--accent)">${escapeHtml(pubKey)}</code></div>
      </div>`;
    prev.innerHTML = renderPreview(result.config);
    lastValidation = result;
    $("saveProfileBtn").disabled = false;
    $("saveAndConnectBtn").disabled = false;
  } else {
    el.innerHTML = `
      <div class="vresult err">
        <div class="title">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>
          ${ot("validationErrors")}
        </div>
        <ul>${result.errors.map(e => `<li>${escapeHtml(e)}</li>`).join("")}</ul>
        ${result.warnings.length ? `<div style="color:var(--warn);margin-top:6px">${ot("warnings")}</div><ul>${result.warnings.map(w => `<li>${escapeHtml(w)}</li>`).join("")}</ul>` : ""}
      </div>`;
    prev.innerHTML = "";
    lastValidation = null;
    $("saveProfileBtn").disabled = true;
    $("saveAndConnectBtn").disabled = true;
  }
}

function renderPreview(cfg) {
  const i = cfg.interface, p = cfg.peers[0] || {};
  const lang = optionsLang;
  const rows = [
    [TarnI18n.t(lang, "previewProfileName"), cfg.name, false],
    ["Interface.Address", i.Address, true],
    ["Interface.DNS", i.DNS, true],
    ["Interface.MTU", i.MTU || "—", true],
    ["Peer.Endpoint", p.Endpoint, true],
    ["Peer.AllowedIPs", p.AllowedIPs, true],
    ["Peer.Keepalive", p.PersistentKeepalive || "—", true],
    [TarnI18n.t(lang, "previewAllTraffic"), cfg.allTraffic ? TarnI18n.t(lang, "previewYes") : TarnI18n.t(lang, "previewNo"), false]
  ];
  return `<div class="preview">${rows.map(r => `<div class="row"><div class="k">${escapeHtml(r[0])}</div><div class="v ${r[2] ? "mono" : ""}">${escapeHtml(r[1] || "—")}</div></div>`).join("")}</div>`;
}

function clearForm() {
  editingProfileId = null;
  savingInProgress = false;
  $("configInput").value = "";
  $("nameInput").value = "";
  $("validationResult").innerHTML = "";
  $("preview").innerHTML = "";
  lastValidation = null;
  $("saveProfileBtn").disabled = true;
  $("saveAndConnectBtn").disabled = true;
}

function generateKeys() {
  const priv = new Uint8Array(32);
  crypto.getRandomValues(priv);
  priv[0] &= 248; priv[31] &= 127; priv[31] |= 64;
  const privB64 = TarnParser.toBase64(priv);
  const pubB64 = TarnParser.derivePublicKey(privB64);
  const tmpl = `[Interface]
PrivateKey = ${privB64}
Address = 10.7.0.42/32
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = ${pubB64}
AllowedIPs = 0.0.0.0/0
Endpoint = your-server.example:51820
`;
  $("configInput").value = tmpl;
  if (!$("nameInput").value) $("nameInput").value = "New keypair";
  validateConfig();
}

// ---- save profile ----
async function saveProfile(andConnect) {
  if (!lastValidation) return;
  if (savingInProgress) return;
  savingInProgress = true;
  $("saveProfileBtn").disabled = true;
  $("saveAndConnectBtn").disabled = true;

  try {
    const name = $("nameInput").value.trim() || lastValidation.config.name;
    const rawText = $("configInput").value;
    const parsed = lastValidation.config;

    if (editingProfileId) {
      await TarnStorage.updateProfile(editingProfileId, { name, rawText, parsed });
      const updatedId = editingProfileId;
      editingProfileId = null;
      clearForm();
      switchTab("profiles");
      await refreshProfiles();
      if (andConnect) {
        const r = await chrome.runtime.sendMessage({ type: "CONNECT", profileId: updatedId });
        if (!r?.ok) alert(ot("connectError") + ": " + (r?.error || "unknown"));
      }
      return;
    }

    const profile = await TarnStorage.addProfile({ name, rawText, parsed });
    await TarnStorage.setActiveId(profile.id);
    clearForm();
    switchTab("profiles");
    await refreshProfiles();
    if (andConnect) {
      const r = await chrome.runtime.sendMessage({ type: "CONNECT", profileId: profile.id });
      if (!r?.ok) alert(ot("connectError") + ": " + (r?.error || "unknown"));
    }
  } catch (e) {
    alert(ot("saveError") + ": " + (e?.message || String(e)));
  } finally {
    savingInProgress = false;
  }
}

// ---- profiles list ----
async function refreshProfiles() {
  let resp;
  try {
    resp = await Promise.race([
      chrome.runtime.sendMessage({ type: "GET_PROFILES" }),
      new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 4000))
    ]);
  } catch (e) {
    const list = await TarnStorage.getProfiles();
    const activeId = await TarnStorage.getActiveId();
    resp = { ok: true, profiles: list, activeId };
  }
  const list = resp?.profiles || [];
  const activeId = resp?.activeId;
  const el = $("profileList");

  if (!list.length) {
    el.innerHTML = `
      <div class="empty-state">
        <img src="mascot/sit.png" alt="" width="64" height="64" style="image-rendering:pixelated;margin-bottom:12px;filter:drop-shadow(0 0 8px rgba(0,255,0,.3))">
        <h3 data-i18n="noProfilesTitle">${ot("noProfilesTitle")}</h3>
        <div data-i18n="noProfilesDesc">${ot("noProfilesDesc")}</div>
      </div>`;
    return;
  }

  el.innerHTML = list.map(p => `
    <div class="profile-item ${p.id === activeId ? "active" : ""}" data-id="${escapeHtml(p.id)}">
      <div class="picon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5z"/></svg>
      </div>
      <div class="info">
        <div class="name">${escapeHtml(p.name)}</div>
        <div class="meta">${escapeHtml(p.parsed?.host || "—")} · ${ot("profileMeta")} ${escapeHtml(String(p.connects || 0))} · ${p.lastUsed ? escapeHtml(new Date(p.lastUsed).toLocaleDateString()) : ot("profileNeverUsed")}</div>
      </div>
      <div class="actions-mini">
        <button class="icon-btn-sm" data-act="activate" data-i18n-title="activateTitle" title="Сделать активным">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg>
        </button>
        <button class="icon-btn-sm" data-act="connect" data-i18n-title="connectTitle" title="Подключить">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg>
        </button>
        <button class="icon-btn-sm" data-act="qr" data-i18n-title="qrTitle" title="QR-код">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h7v7"/></svg>
        </button>
        <button class="icon-btn-sm" data-act="edit" data-i18n-title="editTitle" title="Редактировать">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4z"/></svg>
        </button>
        <button class="icon-btn-sm danger" data-act="delete" data-i18n-title="deleteTitle" title="Удалить">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
        </button>
      </div>
    </div>`).join("");

  // Apply i18n to dynamically generated elements
  const lang = optionsLang;
  TarnI18n.applyI18n(lang, el);

  el.querySelectorAll(".profile-item").forEach(item => {
    const id = item.dataset.id;
    item.querySelectorAll("button").forEach(btn => {
      btn.addEventListener("click", () => profileAction(id, btn.dataset.act));
    });
  });
}

async function profileAction(id, act) {
  const profile = await TarnStorage.getProfile(id);
  if (!profile) return;
  if (act === "activate") {
    await TarnStorage.setActiveId(id);
    await refreshProfiles();
  } else if (act === "connect") {
    await TarnStorage.setActiveId(id);
    const r = await chrome.runtime.sendMessage({ type: "CONNECT", profileId: id });
    if (!r?.ok) alert(ot("connectError") + ": " + (r?.error || "unknown"));
  } else if (act === "qr") {
    showQR(profile);
  } else if (act === "edit") {
    editProfile(profile);
  } else if (act === "delete") {
    if (confirm(ot("confirmDeleteMsg") + " «" + profile.name + "»?")) {
      await TarnStorage.deleteProfile(id);
      await refreshProfiles();
    }
  }
}

function showQR(profile) {
  const dlg = document.createElement("div");
  dlg.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,.6);display:grid;place-items:center;z-index:9999;padding:20px";
  dlg.innerHTML = `
    <div style="background:var(--card);border:1px solid var(--border);border-radius:14px;padding:20px;max-width:340px;width:100%">
      <h3 style="margin:0 0 4px;font-size:15px">${ot("qrTitle")}: ${escapeHtml(profile.name)}</h3>
      <p style="color:var(--muted);font-size:12px;margin:0 0 12px">${ot("qrDesc")}</p>
      <div class="qr-wrap"><canvas id="qrCanvas"></canvas></div>
      <button class="btn" style="width:100%;justify-content:center" id="qrClose">${ot("qrClose")}</button>
    </div>`;
  document.body.appendChild(dlg);
  const canvas = dlg.querySelector("#qrCanvas");
  try {
    TarnQR.generate(profile.rawText, "M", 6, canvas);
  } catch (e) {
    canvas.replaceWith(Object.assign(document.createElement("div"), { textContent: ot("qrTooBig"), style: "padding:20px;color:var(--muted)" }));
  }
  dlg.querySelector("#qrClose").addEventListener("click", () => dlg.remove());
  dlg.addEventListener("click", (e) => { if (e.target === dlg) dlg.remove(); });
}

function editProfile(profile) {
  editingProfileId = profile.id;
  switchTab("add");
  $("nameInput").value = profile.name;
  $("configInput").value = profile.rawText;
  validateConfig();
  const heading = $("addHeading");
  if (heading) heading.textContent = ot("editHeading");
}

// ---- settings ----
async function loadSettings() {
  currentSettings = await TarnStorage.getSettings();
  $("setMode").value = currentSettings.mode;
  $("setHostName").value = currentSettings.nativeHostName;
  $("setSocksHost").value = currentSettings.socksHost;
  $("setSocksPort").value = currentSettings.socksPort;
  $("setAutoConnect").checked = currentSettings.autoConnect;
  $("setKillSwitch").checked = currentSettings.killSwitch;
  $("setWebrtc").checked = currentSettings.webrtcProtection;
  $("setDisableQuic").checked = currentSettings.disableQuic;
  $("setVerifyIp").checked = currentSettings.verifyIp !== false;
  $("setStatsEnabled").checked = currentSettings.statsEnabled !== false;
  $("setSplit").checked = currentSettings.splitTunneling;
  $("setSplitMode").value = currentSettings.splitMode;
  renderTagList($("bypassList"), currentSettings.bypassList, updateBypass);
  renderTagList($("splitDomains"), currentSettings.splitDomains, updateSplitDomains);
}

async function saveSetting(key, value) {
  const resp = await chrome.runtime.sendMessage({ type: "SAVE_SETTINGS", patch: { [key]: value } });
  if (resp?.ok) currentSettings = resp.settings;
}

function renderTagList(container, items, onChange) {
  container.innerHTML = "";
  items.forEach(item => addTag(container, item, onChange));
  const input = document.createElement("input");
  input.className = "tag-input";
  input.placeholder = ot("tagPH");
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && input.value.trim()) {
      addTag(container, input.value.trim(), onChange);
      input.value = "";
      onChange();
    }
  });
  container.appendChild(input);
}
function addTag(container, value, onChange) {
  const tag = document.createElement("span");
  tag.className = "tag";
  tag.innerHTML = `<span>${escapeHtml(value)}</span>`;
  const btn = document.createElement("button");
  btn.textContent = "×";
  btn.addEventListener("click", () => { tag.remove(); onChange(); });
  tag.appendChild(btn);
  container.insertBefore(tag, container.lastChild);
}
function collectTags(container) {
  return Array.from(container.querySelectorAll(".tag span")).map(s => s.textContent);
}
async function updateBypass() { await saveSetting("bypassList", collectTags($("bypassList"))); }
async function updateSplitDomains() { await saveSetting("splitDomains", collectTags($("splitDomains"))); }

// ---- native host / wireproxy checks ----
async function pingNative() {
  $("nativeStatusText").textContent = ot("healthCheck");
  $("nativeCard").classList.remove("ok", "fail");
  const r = await chrome.runtime.sendMessage({ type: "PING_NATIVE" });
  if (r?.available) {
    $("nativeStatusText").innerHTML = `<span style="color:var(--accent)">${ot("nativeAvail")}</span>`;
    $("nativeDetail").textContent = r.version ? `v${r.version}` : "";
    $("nativeCard").classList.add("ok");
  } else {
    $("nativeStatusText").innerHTML = `<span style="color:var(--danger)">${ot("nativeUnavail")}</span>`;
    $("nativeDetail").textContent = r?.error || ot("nativeNotInstalled");
    $("nativeCard").classList.add("fail");
  }
  updateHealthBadge();
}

async function checkWireproxy() {
  $("wireproxyStatusText").textContent = ot("healthCheck");
  $("wireproxyCard").classList.remove("ok", "fail");
  const r = await chrome.runtime.sendMessage({ type: "CHECK_WIREPROXY" });
  if (r?.wireproxyAvailable) {
    $("wireproxyStatusText").innerHTML = `<span style="color:var(--accent)">${ot("wpInstalled")}</span>`;
    $("wireproxyDetail").textContent = r.wireproxyPath || "";
    $("wireproxyCard").classList.add("ok");
  } else {
    $("wireproxyStatusText").innerHTML = `<span style="color:var(--danger)">${ot("wpNotFound")}</span>`;
    $("wireproxyDetail").textContent = r?.error || ot("wpRunInstall");
    $("wireproxyCard").classList.add("fail");
  }
  updateHealthBadge();
}

function updateHealthBadge() {
  const nativeOk = $("nativeCard").classList.contains("ok");
  const wpOk = $("wireproxyCard").classList.contains("ok");
  const badge = $("healthBadge");
  const text = $("healthText");
  const warn = $("noTunnelWarn");
  badge.classList.remove("unknown", "ok", "partial", "fail");
  if (nativeOk && wpOk) {
    badge.classList.add("ok");
    text.textContent = ot("healthOk");
    warn.style.display = "none";
  } else if (nativeOk && !wpOk) {
    badge.classList.add("partial");
    text.textContent = ot("healthPartial");
    warn.style.display = "flex";
  } else {
    badge.classList.add("fail");
    text.textContent = ot("healthFail");
    warn.style.display = "flex";
  }
}

// ---- stats ----
function updateStatsVisibility() {
  const enabled = currentSettings?.statsEnabled !== false;
  $("statsContent").style.display = enabled ? "" : "none";
  $("statsDisabled").style.display = enabled ? "none" : "";
}

async function refreshStats() {
  const resp = await chrome.runtime.sendMessage({ type: "GET_STATS" });
  const stats = resp?.stats || { sessions: [] };
  const profilesResp = await chrome.runtime.sendMessage({ type: "GET_PROFILES" });
  $("totalSessions").textContent = (stats.sessions || []).length;
  $("totalProfiles").textContent = (profilesResp?.profiles || []).length;
  const tbody = $("sessionsTable").querySelector("tbody");
  tbody.innerHTML = (stats.sessions || []).slice(0, 20).map(s => `
    <tr>
      <td>${escapeHtml(s.profileName || "—")}</td>
      <td>${s.start ? new Date(s.start).toLocaleString() : "—"}</td>
      <td>${s.end && s.start ? Math.round((s.end - s.start) / 1000) + "s" : "—"}</td>
    </tr>`).join("") || `<tr><td colspan="3" style="color:var(--muted);text-align:center;padding:20px">${ot("noData")}</td></tr>`;
}

async function resetStats() {
  if (!confirm(ot("confirmReset"))) return;
  await chrome.runtime.sendMessage({ type: "RESET_STATS" });
  await refreshStats();
}

// ---- backup ----
async function exportBackup() {
  const data = await TarnStorage.exportAll();
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;   a.download = `tarn-backup-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

async function importBackup(e) {
  const f = e.target.files?.[0]; if (!f) return;
  try {
    const data = JSON.parse(await f.text());
    await TarnStorage.importAll(data);
    await refreshProfiles();
    await loadSettings();
    alert(ot("backupImported"));
  } catch (err) {
    alert(ot("backupImportError") + ": " + err.message);
  }
}

// ---- utils ----
function escapeHtml(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/**
 * Extract a bare hostname from anything the user might type:
 *   "example.com"                           → "example.com"
 *   "https://www.youtube.com/watch?v=..."  → "www.youtube.com"
 *   "http://example.com:8080/path"          → "example.com"
 *   "  EXAMPLE.com  "                       → "example.com"
 * Returns null if the result is not a valid hostname.
 */
function extractHostname(input) {
  if (!input || typeof input !== "string") return null;
  let s = input.trim().toLowerCase();
  if (!s) return null;
  // Strip scheme (http://, https://, etc.)
  const schemeMatch = s.match(/^([a-z][a-z0-9+.-]*:\/\/)?(.+)$/);
  if (schemeMatch) s = schemeMatch[2];
  // Strip userinfo (user@host)
  const atIdx = s.indexOf("@");
  if (atIdx >= 0) s = s.slice(atIdx + 1);
  // Strip path FIRST (/watch?v=...), THEN port (:8080) — order matters for
  // "host:port/path" where the trailing digits belong to the path, not a port.
  const slashIdx = s.indexOf("/");
  if (slashIdx >= 0) s = s.slice(0, slashIdx);
  // Strip port (:8080) if what follows is purely numeric
  const colonIdx = s.lastIndexOf(":");
  if (colonIdx >= 0 && /^\d+$/.test(s.slice(colonIdx + 1))) s = s.slice(0, colonIdx);
  // Validate: bare DNS hostname
  if (s.length > 253) return null;
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(s)) return null;
  return s;
}

// ---- DPI functions ----

const DPI_STRATEGY_KEYS = [
  "fake_fakedsplit_ts", "simple_fake_ts", "fake_multisplit", "hostfakesplit",
  "exp", "fake_tls_auto_ts", "fake_tls_auto", "multisplit",
  "syndata_multidisorder", "fake_badseq",
  "hybrid_tlsauto_hostfakesplit", "hybrid_badseq_hostfakesplit"
];

function initDpiStrategySelect() {
  const sel = $("dpiStrategy");
  if (!sel) return;
  const lang = optionsLang;
  const names = DPI_STRATEGY_KEYS.map(k => ({
    value: k,
    label: TarnI18n.t(lang, "dpiStrategyName_" + k)
  }));
  sel.innerHTML = "";
  const autoOpt = document.createElement("option");
  autoOpt.value = "auto";
  autoOpt.textContent = TarnI18n.t(lang, "dpiStrategyAuto");
  sel.appendChild(autoOpt);
  for (const n of names) {
    const opt = document.createElement("option");
    opt.value = n.value;
    opt.textContent = n.label;
    sel.appendChild(opt);
  }
}

async function loadDpiSettings() {
  try {
    const dpiSettings = await TarnStorage.getDpiSettings();
    // AdGuard DNS toggle was removed — it is now always ON (as before).
    // Force-enable it so an old saved "false" doesn't silently keep it off.
    if (dpiSettings.dpiAdguardDns !== true) {
      dpiSettings.dpiAdguardDns = true;
      TarnStorage.saveDpiSettings({ dpiAdguardDns: true }).catch(() => {});
    }
    if ($("dpiForceDoh")) $("dpiForceDoh").checked = dpiSettings.dpiForceDoh !== false;
    if ($("dpiBlockQuic")) $("dpiBlockQuic").checked = dpiSettings.dpiBlockQuic !== false;
    if ($("dpiStripHeaders")) $("dpiStripHeaders").checked = dpiSettings.dpiStripHeaders !== false;
    if ($("dpiGameFilter")) $("dpiGameFilter").checked = dpiSettings.dpiGameFilter !== false;
    if ($("dpiAdBlock")) $("dpiAdBlock").checked = dpiSettings.dpiAdBlock !== false;
    if ($("dpiAntiTrack")) $("dpiAntiTrack").checked = dpiSettings.dpiAntiTrack !== false;
    if ($("dpiAutoStart")) $("dpiAutoStart").checked = dpiSettings.dpiAutoStartWithWg === true;
    if ($("dpiCustomDomains") && dpiSettings.dpiCustomDomains && dpiSettings.dpiCustomDomains.length) {
      $("dpiCustomDomains").value = dpiSettings.dpiCustomDomains.join("\n");
    }
    if ($("dpiExcludedDomains") && dpiSettings.dpiExcludedDomains && dpiSettings.dpiExcludedDomains.length) {
      $("dpiExcludedDomains").value = dpiSettings.dpiExcludedDomains.join("\n");
    }
    if ($("dpiProbeTargets") && dpiSettings.dpiProbeHosts && dpiSettings.dpiProbeHosts.length) {
      $("dpiProbeTargets").value = dpiSettings.dpiProbeHosts.join("\n");
    }
    // Tag lists (replaces the plain textareas above on next load).
    if ($("dpiCustomDomainsWrap")) {
      await initTagLists();
    }
    if ($("dpiStrategy")) {
      initDpiStrategySelect();
      let v = dpiSettings.dpiStrategy || "auto";
      if (v !== "auto" && !DPI_STRATEGY_KEYS.includes(v)) v = "auto";
      $("dpiStrategy").value = v;
    }
  } catch(e) { console.warn("loadDpiSettings:", e); }

  try {
    const r = await chrome.runtime.sendMessage({ type: "DPI_STATUS" });
    if (r?.ok && r.dpiState) {
      renderDpiStatus(r.dpiState);
      return;
    }
  } catch(e) {}

  const dpiState = await TarnStorage.getDpiState();
  renderDpiStatus(dpiState);
}

// Show the last strategy test outcome after a reload/reopen of the page:
// results are persisted by the background at the end of every run, and the
// log lines are persisted by this page as they are printed.
function renderLastDpiTestResult() {
  if (dpiTestActive) return;
  chrome.storage.local.get(["tarn.dpiTestResult", "tarn.dpiTestLog"], (d) => {
    const stored = d["tarn.dpiTestResult"];
    if (!stored || !stored.ranking || !stored.ranking.length) return;
    const el = $("dpiTestArea");
    if (!el) return;
    const r = { ...stored, cleanup: true };
    el.style.display = "";
    $("dpiTestResult").innerHTML = buildDpiTestResultHtml(r);
    $("dpiTestPauseBtn").disabled = true;
    $("dpiTestStopBtn").disabled = true;
    const log = $("dpiTestLog");
    log.innerHTML = "";
    const savedLog = d["tarn.dpiTestLog"];
    if (Array.isArray(savedLog) && savedLog.length) {
      dpiTestReplaying = true;
      for (const l of savedLog) {
        const div = document.createElement("div");
        div.className = "test-log-line " + (l.cls || "");
        div.textContent = `[${l.ts || ""}] ${l.text}`;
        log.appendChild(div);
      }
      dpiTestReplaying = false;
      log.scrollTop = log.scrollHeight;
    }
    if (stored.ts) {
      const t = new Date(stored.ts).toLocaleString([], { hour12: false });
      $("dpiTestMeta").textContent = `${ot("dpiTestLastRun")} ${t}`;
    }
  });
}

function renderDpiStatus(dpiState) {
  const startBtn = $("dpiStartBtn");
  const stopBtn = $("dpiStopBtn");
  const statusText = $("dpiStatusText");
  const strategyRow = $("dpiStrategyRow");
  const strategyText = $("dpiStrategyText");
  const lang = optionsLang;

  if (dpiState.dpiActive) {
    startBtn.style.display = "none";
    stopBtn.style.display = "flex";
    statusText.textContent = TarnI18n.t(lang, "dpiStatusActive");
    statusText.style.color = "var(--accent)";
    if (strategyRow && dpiState.dpiStrategy) {
      strategyRow.style.display = "flex";
      const name = TarnI18n.t(lang, "dpiStrategyName_" + dpiState.dpiStrategy);
      strategyText.textContent = name;
    } else if (strategyRow) {
      strategyRow.style.display = "none";
    }
  } else if (dpiState.dpiStarting) {
    startBtn.style.display = "none";
    stopBtn.style.display = "flex";
    statusText.textContent = TarnI18n.t(lang, "dpiStatusStarting");
    statusText.style.color = "var(--warn)";
    if (strategyRow) strategyRow.style.display = "none";
  } else {
    startBtn.style.display = "flex";
    stopBtn.style.display = "none";
    if (strategyRow) strategyRow.style.display = "none";
    if (dpiState.engineAvailable === false) {
      statusText.textContent = TarnI18n.t(lang, "dpiStatusEngineNotInstalled");
      statusText.style.color = "var(--danger)";
      startBtn.disabled = true;
      startBtn.title = TarnI18n.t(lang, "dpiStatusInstallHint");
    } else {
      statusText.textContent = TarnI18n.t(lang, "dpiStatusInactive");
      statusText.style.color = "var(--muted)";
      startBtn.disabled = false;
      startBtn.title = "";
    }
  }

  if (dpiState.dpiError) {
    statusText.textContent = dpiState.dpiError;
    statusText.style.color = "var(--danger)";
  }
}

// ---- DPI strategy testing (progress streaming) ----
let dpiTestActive = false;
let dpiTestPaused = false;
let dpiTestReplaying = false;
let dpiTestLogStore = [];
let dpiTestLogPersistTimer = null;

// ---- DPI diagnostics (progress streaming) ----
let dpiDiagActive = false;

const DIAG_PHASE_KEYS = [
  "diagPhaseBase",
  "diagPhaseEngine",
  "diagPhaseService",
  "diagPhaseRuntime",
  "diagPhaseDns",
  "diagPhaseInternet",
  "diagPhaseEnv",
  "diagPhaseLog",
];

function dpiStrategyLabel(key, lang) {
  return TarnI18n.t(lang || optionsLang, "dpiStrategyName_" + key);
}

function dpiTestLogLine(cls, text) {
  const log = $("dpiTestLog");
  const ts = new Date().toLocaleTimeString([], { hour12: false });
  if (log) {
    const div = document.createElement("div");
    div.className = "test-log-line " + (cls || "");
    div.textContent = `[${ts}] ${text}`;
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
  }
  // Persist every line so the last test's log survives page reloads
  // (the final result already persists via the background).
  if (!dpiTestReplaying) {
    dpiTestLogStore.push({ cls: cls || "", ts, text });
    if (dpiTestLogStore.length > 150) dpiTestLogStore.splice(0, dpiTestLogStore.length - 150);
    if (dpiTestLogPersistTimer) clearTimeout(dpiTestLogPersistTimer);
    dpiTestLogPersistTimer = setTimeout(() => {
      chrome.storage.local.set({ "tarn.dpiTestLog": dpiTestLogStore }).catch(() => {});
    }, 200);
  }
}

function clearDpiTestLog() {
  dpiTestLogStore = [];
  if (dpiTestLogPersistTimer) { clearTimeout(dpiTestLogPersistTimer); dpiTestLogPersistTimer = null; }
  chrome.storage.local.remove("tarn.dpiTestLog").catch(() => {});
}

function dpiTestSetMeta(text) {
  const el = $("dpiTestMeta");
  if (el) el.textContent = text;
}

function renderDpiTestProgress(p) {
  if (p.phase === "started") return;
  $("dpiTestPct").textContent = (p.pct || 0) + "%";
  $("dpiTestBar").style.width = (p.pct || 0) + "%";
  if (p.phase === "run") {
    const name = dpiStrategyLabel(p.strategy);
    const hostTxt = `${p.hostsOk}/${p.hostsTotal}`;
    const tlsTxt = p.tls13Ok != null ? ` · TLS1.3 ${p.tls13Ok}/${p.hostsTotal}` : "";
    const latTxt = p.latencyMs != null ? ` · ${p.latencyMs} ms` : "";
    dpiTestSetMeta(`${ot("dpiTestProgress")}: ${p.done}/${p.totalRuns} · ${name} · ${ot("dpiTestPass")} ${p.pass}/${p.passes} — ${hostTxt}${tlsTxt}${latTxt}`);
    const res = p.ok ? "✔" : "✘";
    const why = p.err ? ` (${p.err})` : "";
    dpiTestLogLine(p.ok ? "ok" : "fail", `${res} ${name} · ${ot("dpiTestPass")} ${p.pass}/${p.passes} — ${hostTxt}${tlsTxt}${latTxt}${why}`);
    if (Array.isArray(p.hosts) && p.hosts.length) {
      for (const h of p.hosts) {
        const st = [
          `${h.host || "?"}:`,
          `HTTP:${h.http ? "OK" : "ERR"}`,
          `TLS1.2:${h.tls12 ? "OK" : "ERR"}`,
          `TLS1.3:${h.tls13 ? "OK" : "ERR"}`,
          h.pingMs != null ? `Ping:${h.pingMs}ms` : "Ping:ERR",
        ].join(" ");
        dpiTestLogLine(h.http ? "hosts" : "fail", "  " + st);
      }
    }
  } else if (p.phase === "cleanup") {
    dpiTestSetMeta(ot("dpiTestCleanup"));
    dpiTestLogLine("info", ot("dpiTestCleanup"));
  } else if (p.phase === "skip") {
    const name = dpiStrategyLabel(p.strategy);
    dpiTestLogLine("fail", `✘ ${name} · ${ot("dpiTestPass")} ${p.pass}/${p.passes} — ${ot("dpiTestEarlyStop")}`);
  }
}

function renderDpiTestFinal(r) {
  dpiTestLogLine("info", r.cancelled ? ot("dpiTestCancelled") : ot("dpiTestDone"));
  const html = buildDpiTestResultHtml(r);
  $("dpiTestResult").innerHTML = html;
  // Reflect the winner in the strategy select immediately (the settings
  // are saved by the background on test completion).
  if (r.winner && !r.cancelled) {
    $("dpiStrategy").value = r.winner;
    $("dpiTestResults").textContent = ot("dpiTestWinnerApplied");
  }
}

function buildDpiTestResultHtml(r) {
  // The ranking numbers come from the native host over IPC, and the HTML
  // below interpolates them directly. Coerce every numeric field here so a
  // malformed value renders as a number and never as raw HTML.
  const toNum = (v) => {
    const n = Number(v);
    return Number.isFinite(n) ? n : 0;
  };
  const cleanEntry = (x) => ({
    ...x,
    hostsOk: toNum(x && x.hostsOk),
    hostsTotal: toNum(x && x.hostsTotal),
    tls13Ok: x && x.tls13Ok != null ? toNum(x.tls13Ok) : null,
    tls12Ok: x && x.tls12Ok != null ? toNum(x.tls12Ok) : null,
    passesOk: toNum(x && x.passesOk),
    passes: toNum(x && x.passes),
    latencyMs: x && x.latencyMs != null ? toNum(x.latencyMs) : null,
    critTlsTotal: toNum(x && x.critTlsTotal),
    critTlsOk: toNum(x && x.critTlsOk),
    hostsDetail: x && x.hostsDetail && typeof x.hostsDetail === "object"
      ? Object.fromEntries(Object.entries(x.hostsDetail).map(([h, s]) => [
          h, { ...s, http: toNum(s && s.http), tls13: toNum(s && s.tls13) },
        ]))
      : undefined,
  });
  r = {
    ...r,
    winner: typeof r.winner === "string" ? r.winner : "",
    ranking: Array.isArray(r.ranking) ? r.ranking.map(cleanEntry) : [],
  };
  const html = [];
  // The critical group (the main probe targets) is the traffic the user
  // actually consumes. A strategy can pass every easy HTTP
  // probe yet leave the TLS path dead (seen on WiFi with
  // hostfakesplit: HTTP fine, critical TLS 0/10) - that gets the
  // strongest warning. Fall back to the TLS 1.3 ratio otherwise. The
  // threshold is inclusive (<= 0.6): 9/15 HTTPS hosts is exactly at the
  // boundary, and a 6/10 ts-family result on a jittery link is not
  // "good enough" either.
  const weakRatio = (x) => x.tls13Ok != null && x.hostsTotal > 0
    && (x.tls13Ok / x.hostsTotal) <= 0.6;
  const critDead = (x) => x.critTlsTotal > 0 && x.critTlsOk === 0;
  if (r.winner) {
    const w = r.ranking.find(x => x.strategy === r.winner);
    const lat = w && w.latencyMs != null ? `, ${ot("dpiTestAvgLat")} ${w.latencyMs} ms` : "";
    const wTls = w && w.tls13Ok != null
      ? `, TLS 1.3 ${w.tls13Ok}/${w.hostsTotal}` : "";
    let wCrit = "";
    if (w && w.critTlsTotal > 0) {
      wCrit = `, crit TLS ${w.critTlsOk}/${w.critTlsTotal}`;
    }
    // A winner with weak HTTPS coverage unblocks HTTP but may be dead for
    // real TLS content (SNI-blocking DPI) - surface that instead of hiding it.
    const wWeak = w && w.tls13Ok != null && w.hostsTotal > 0
      && (critDead(w) || weakRatio(w))
      ? ` <span class="test-winner-hint">${ot(critDead(w) ? "dpiTestCritTlsDead" : "dpiTestHttpsWeak")}</span>` : "";
    html.push(`<div class="test-winner">${ot("dpiTestWinner")}: <strong>${escapeHtml(dpiStrategyLabel(r.winner))}</strong> — ${w.hostsOk}/${w.hostsTotal} ${ot("dpiTestHosts")}${wTls}${wCrit}${lat}${wWeak}${r.cancelled ? "" : `. ${ot("dpiTestWinnerSaved")}`}</div>`);
  } else {
    html.push(`<div class="test-winner fail">${ot("dpiTestNoWinner")}</div>`);
  }
  if (r.ranking && r.ranking.length) {
    html.push(`<table class="test-ranking"><thead><tr><th>#</th><th>${ot("dpiTestStrategy")}</th><th>${ot("dpiTestHosts")}</th><th>${ot("dpiTestTls13")}</th><th>${ot("dpiTestPassesCol")}</th><th>${ot("dpiTestAvgLat")}</th><th>${ot("dpiTestResultCol")}</th></tr></thead><tbody>`);
    r.ranking.forEach((x, i) => {
      const lat = x.latencyMs != null ? x.latencyMs + " ms" : "—";
      const critInfo = x.critTlsTotal > 0
        ? ` · crit TLS ${x.critTlsOk}/${x.critTlsTotal}` : "";
      const tls = x.tls13Ok != null
        ? `<span${(critDead(x) || weakRatio(x)) ? ` class="tls-weak"` : ""} title="TLS 1.2: ${x.tls12Ok != null ? `${x.tls12Ok}/${x.hostsTotal}` : "—"}${critInfo}">${x.tls13Ok}/${x.hostsTotal}</span>`
        : "—";
      const state = (x.passesOk > 0 && x.hostsOk >= x.hostsTotal) ? `<span style="color:var(--green)">✔</span>` : `<span style="color:var(--red)">✘</span>`;
      html.push(`<tr class="${x.strategy === r.winner ? "winner-row" : ""}"><td>${i + 1}</td><td>${escapeHtml(dpiStrategyLabel(x.strategy))}</td><td>${x.hostsOk}/${x.hostsTotal}</td><td>${tls}</td><td>${x.passesOk}/${x.passes}</td><td>${lat}</td><td>${state}</td></tr>`);
      // Per-host breakdown (collapsed by default): shows WHICH hosts passed
      // and marks the media CDN hosts that the ISP does not block anyway -
      // a strategy can score 0/N on the main probe targets while the media
      // path still flows, which is why a 0/N verdict and a playing video
      // are not contradictory.
      const hd = x.hostsDetail;
      if (hd && typeof hd === "object" && Object.keys(hd).length) {
        const lines = Object.entries(hd).map(([h, s]) => {
          const media = s.media
            ? ` <span class="media-badge">${ot("dpiTestMediaHost")}</span>` : "";
          const ok = s.http > 0 && s.tls13 > 0;
          return `<div class="host-line ${ok ? "ok" : "fail"}"><span class="hl-ico">${ok ? "✔" : "✘"}</span>${escapeHtml(h)}${media}</div>`;
        }).join("");
        html.push(`<tr class="host-detail-row"><td colspan="7"><details><summary>${ot("dpiTestHostsDetail")}</summary>${lines}</details></td></tr>`);
      }
    });
    html.push("</tbody></table>");
    const anyMediaAlive = r.ranking.some(x => {
      const hd = x.hostsDetail || {};
      return Object.values(hd).some(s => s.media && s.http > 0);
    });
    if (anyMediaAlive) {
      html.push(`<div class="test-media-hint">${ot("dpiTestMediaHint")}</div>`);
    }
  }
  if (r.cleanup === false) {
    html.push(`<div class="test-winner fail">${ot("dpiTestCleanupWarn")}</div>`);
  }
  return html.join("");
}

function dpiTestSetRunning(running) {
  dpiTestActive = running;
  $("dpiTestBtn").disabled = running;
  $("dpiStrategy").disabled = running;
  $("dpiSaveStrategyBtn").disabled = running;
  $("dpiTestArea").style.display = "";
  $("dpiStartBtn").disabled = running;
  $("dpiTestPasses").disabled = running;
  if (running) {
    clearDpiTestLog();
    $("dpiTestLog").innerHTML = "";
    $("dpiTestResult").innerHTML = "";
    $("dpiDiagOutput").innerHTML = "";
    $("dpiDiagCopyBtn").style.display = "none";
    $("dpiTestBar").style.width = "0%";
    $("dpiTestPct").textContent = "0%";
    $("dpiTestPauseBtn").disabled = false;
    $("dpiTestStopBtn").disabled = false;
  } else {
    // Test finished/cancelled — Pause/Stop must not stay active.
    $("dpiTestPauseBtn").disabled = true;
    $("dpiTestStopBtn").disabled = true;
    dpiTestPaused = false;
    $("dpiTestPauseBtn").querySelector("span").textContent = ot("dpiTestPause");
  }
}

async function dpiTestStrategies() {
  if (dpiTestActive) return;
  const passes = parseInt($("dpiTestPasses").value, 10) || 3;
  const btn = $("dpiTestBtn");
  btn.disabled = true;
  dpiTestSetRunning(true);
  dpiTestLogLine("info", ot("dpiTestRunning"));
  try {
    const r = await chrome.runtime.sendMessage({
      type: "DPI_TEST_STRATEGIES",
      opts: { passes }
    });
    if (r?.ok) {
      renderDpiTestFinal(r);
      dpiTestLogLine("info", ot("dpiTestAutoDiag"));
      await dpiDiagnostics();
    } else {
      dpiTestLogLine("fail", r?.error || ot("dpiTestError"));
      $("dpiTestResult").innerHTML = `<div class="test-winner fail">${escapeHtml(r?.error || ot("dpiTestError"))}</div>`;
    }
  } catch (e) {
    dpiTestLogLine("fail", String(e && e.message || e));
  } finally {
    dpiTestSetRunning(false);
    dpiTestPaused = false;
    $("dpiTestPauseBtn").querySelector("span").textContent = ot("dpiTestPause");
  }
}

async function dpiTestControl(action) {
  const r = await chrome.runtime.sendMessage({ type: "DPI_TEST_CONTROL", action });
  return r && r.ok;
}

async function dpiTestPauseToggle() {
  const btn = $("dpiTestPauseBtn");
  if (!dpiTestActive) return;
  if (dpiTestPaused) {
    const ok = await dpiTestControl("resume");
    if (ok) {
      dpiTestPaused = false;
      btn.querySelector("span").textContent = ot("dpiTestPause");
      btn.classList.remove("active");
      dpiTestLogLine("info", ot("dpiTestResumed"));
    }
  } else {
    const ok = await dpiTestControl("pause");
    if (ok) {
      dpiTestPaused = true;
      btn.querySelector("span").textContent = ot("dpiTestResume");
      btn.classList.add("active");
      dpiTestLogLine("info", ot("dpiTestPausedMsg"));
    }
  }
}

async function dpiTestStop() {
  if (!dpiTestActive) return;
  dpiTestLogLine("info", ot("dpiTestStopping"));
  $("dpiTestStopBtn").disabled = true;
  $("dpiTestPauseBtn").disabled = true;
  // Cancel the worker in the native host. It checks the cancel flag between
  // every strategy and between every host probe, so this is responsive.
  await dpiTestControl("cancel");
  // Do NOT wait for the worker to finish here — the background streams the
  // final result (with cancelled:true) and dpiTestStrategies()'s finally
  // block resets the UI. Until then, reflect "stopping" locally.
  $("dpiTestPauseBtn").querySelector("span").textContent = ot("dpiTestPause");
  dpiTestPaused = false;
}

// ---- DPI diagnostics ----
async function dpiDiagnostics() {
  const btn = $("dpiDiagBtn");
  const out = $("dpiDiagOutput");
  btn.disabled = true;
  dpiDiagActive = true;
  out.innerHTML =
    `<div class="test-progress-row" style="margin:4px 0">` +
    `<div class="test-progress-wrap"><div class="test-progress-bar" id="dpiDiagBar"></div></div>` +
    `<span class="test-progress-pct" id="dpiDiagPct">0%</span>` +
    `</div>` +
    `<div class="diag-progress-phase" id="dpiDiagPhase">${escapeHtml(ot("dpiDiagRunning"))}</div>`;
  let r;
  try {
    r = await chrome.runtime.sendMessage({ type: "DPI_DIAGNOSTICS" });
  } catch (e) {
    r = { ok: false, error: String(e && e.message || e) };
  } finally {
    dpiDiagActive = false;
    btn.disabled = false;
  }
  if (!r?.ok || !r.diagnostics) {
    out.innerHTML = `<div class="diag-line fail">${escapeHtml(r?.error || ot("dpiTestError"))}</div>`;
    return;
  }
  renderDiagnostics(r.diagnostics);
  $("dpiDiagCopyBtn").style.display = "flex";
}

function updateDiagProgress(m) {
  const bar = $("dpiDiagBar");
  const pct = $("dpiDiagPct");
  const ph = $("dpiDiagPhase");
  if (!bar || !pct) return;
  const total = Math.max(1, m.total || 8);
  const done = Math.min(total, Math.max(0, m.done || 0));
  const p = Math.round(done / total * 100);
  bar.style.width = p + "%";
  pct.textContent = p + "%";
  if (ph) {
    const idx = m.phase ? DIAG_PHASE_KEYS.indexOf("diagPhase" + m.phase.charAt(0).toUpperCase() + m.phase.slice(1)) : -1;
    ph.textContent = idx >= 0 ? ot(DIAG_PHASE_KEYS[idx]) : ot("dpiDiagRunning");
  }
}

function renderDiagnostics(d) {
  const out = $("dpiDiagOutput");
  const rows = [];

  const row = (label, value, ok) => {
    const cls = ok === true ? "ok" : (ok === false ? "fail" : "info");
    const icon = ok === true ? "✔" : (ok === false ? "✘" : "·");
    rows.push(`<div class="diag-line ${cls}"><span class="diag-icon">${icon}</span><span class="diag-label">${escapeHtml(label)}</span><span class="diag-value">${escapeHtml(value)}</span></div>`);
  };

  row(ot("diagHostTime"), d.time || "—", null);
  row(ot("diagPython"), d.python + " · " + d.os, null);
  row(ot("diagAdmin"), d.admin ? ot("diagYes") : ot("diagNo"), d.admin);

  const eng = d.engine || {};
  const winws = eng["winws.exe"];
  row(ot("diagWinws"), winws && winws.exists ? `${ot("diagPresent")} (${(winws.size / 1024).toFixed(1)} KB)` : ot("diagMissing"), !!(winws && winws.exists));
  row(ot("diagWinDivert"), eng["WinDivert64.sys"] && eng["WinDivert64.sys"].exists ? ot("diagPresent") : ot("diagMissing"), !!(eng["WinDivert64.sys"] && eng["WinDivert64.sys"].exists));
  row(ot("diagConf"), eng.confDir ? ot("diagPresent") : ot("diagMissing"), !!eng.confDir);

  const svc = d.service || {};
  row(ot("diagService"), svc.installed ? (svc.running ? ot("diagRunning") : ot("diagStopped")) : ot("diagMissing"), !!svc.installed);
  if (svc.installed) {
    if (svc.sddl) {
      row("SDDL", svc.sddl.slice(0, 90) + (svc.sddl.length > 90 ? "…" : ""), null);
    }
    const img = svc.imagePath || "";
    row("ImagePath", img.slice(0, 120) + (img.length > 120 ? "…" : ""), null);
  }
  row(ot("diagWinwsPids"), d.winwsProcesses && d.winwsProcesses.length ? d.winwsProcesses.join(", ") : ot("diagNone"), (d.winwsProcesses || []).length === 0);
  row(ot("diagStrategyCache"), d.strategyCache || ot("diagNone"), !!d.strategyCache);
  row(ot("diagGameFilter"), d.gameFilter || ot("diagOff"), null);
  row(ot("diagDoh"), d.dohEnabledByUs ? ot("diagOn") : ot("diagOff"), null);
  row(ot("diagWireproxy"), d.wireproxy || ot("diagMissing"), !!d.wireproxy);

  const dns = d.dns || {};
  const dnsEntries = Object.entries(dns);
  const dnsOkCount = dnsEntries.filter(([, v]) => Array.isArray(v) && v.length > 0).length;
  row(ot("diagDns"), dnsEntries.length ? `${dnsOkCount}/${dnsEntries.length}` : "—", null);
  for (const [h, v] of dnsEntries) {
    row("  " + h, typeof v === "string" ? v : (Array.isArray(v) && v.length ? v.join(", ") : ot("diagNone")), Array.isArray(v) && v.length > 0);
  }

  const net = d.internet || {};
  if (!net.error) {
    // The check runs WITHOUT bypass. Partial reachability with DNS working
    // is the expected DPI-blocking signature, not an internet outage — so
    // show it as informational unless the bypass was active during the
    // check (then it is a real failure of the current strategy).
    const statusOk = net.okCount >= 3;
    let hint = "";
    if (!statusOk) {
      hint = net.dpiRunningDuringCheck ? ` — ${ot("diagInternetDpi")}` : ` — ${ot("diagInternetDpiSig")}`;
    }
    row(ot("diagInternet"), `${net.okCount}/${net.total}${hint}`,
        statusOk ? true : (net.dpiRunningDuringCheck ? false : null));
    const hosts = net.hosts || {};
    for (const [h, v] of Object.entries(hosts)) {
      row("  " + h, v.ok ? "OK" + (v.ms != null ? ` · ${v.ms}ms` : "") : "ERR", !!v.ok);
    }
  } else {
    row(ot("diagInternet"), net.error, false);
  }

  const env = d.env || {};
  if (Object.keys(env).length && !env.error) {
    const envMap = [
      ["bfe", ot("diagEnvBfe")],
      ["proxy", ot("diagEnvProxy")],
      ["tcpTimestamps", ot("diagEnvTcpTs")],
      ["adguard", ot("diagEnvAdguard")],
      ["killer", ot("diagEnvKiller")],
      ["intel", ot("diagEnvIntel")],
      ["checkpoint", ot("diagEnvCheckpoint")],
      ["smartbyte", ot("diagEnvSmartbyte")],
      ["vpn", ot("diagEnvVpn")],
      ["secureDns", ot("diagEnvSecureDns")],
    ];
    const checks = envMap.filter(([key]) => env[key]);
    row(ot("diagEnv"), `${checks.filter(([key]) => env[key].ok).length}/${checks.length}`, null);
    for (const [key, label] of envMap) {
      const e = env[key];
      if (!e) continue;
      row("  " + label, e.note ? e.note : (e.ok ? ot("diagOk") : ot("diagFail")), e.ok);
    }
  }

  const logTail = d.logTail || [];
  rows.push(`<details class="diag-log"><summary>${escapeHtml(ot("diagLog"))} (${logTail.length})</summary><pre>${escapeHtml(logTail.join("\n"))}</pre></details>`);

  out.innerHTML = rows.join("");
}

async function dpiStart() {
  $("dpiStartBtn").disabled = true;
  const lang = optionsLang;
  $("dpiStatusText").textContent = TarnI18n.t(lang, "dpiStatusStarting");
  $("dpiStatusText").style.color = "var(--warn)";

  const r = await chrome.runtime.sendMessage({ type: "DPI_START" });
  $("dpiStartBtn").disabled = false;

  if (r?.ok) {
    renderDpiStatus({ dpiActive: true });
  } else {
    $("dpiStatusText").textContent = r?.error || TarnI18n.t(lang, "dpiStatusError");
    $("dpiStatusText").style.color = "var(--danger)";
  }
}

async function dpiStop() {
  $("dpiStopBtn").disabled = true;
  await chrome.runtime.sendMessage({ type: "DPI_STOP" });
  $("dpiStopBtn").disabled = false;
  renderDpiStatus({ dpiActive: false });
}

async function dpiSaveDomains() {
  const text = $("dpiCustomDomains").value;
  const domains = text.split("\n").map(d => d.trim()).filter(Boolean);
  await TarnStorage.saveDpiSettings({ dpiCustomDomains: domains });
}

async function dpiSaveExcludedDomains() {
  const text = $("dpiExcludedDomains").value;
  const domains = text.split("\n").map(d => d.trim()).filter(Boolean);
  await TarnStorage.saveDpiSettings({ dpiExcludedDomains: domains });
}

async function dpiSaveProbeTargets() {
  const text = $("dpiProbeTargets").value;
  const raw = text.split("\n").map(d => d.trim()).filter(Boolean);
  // Validate: only bare DNS hostnames survive (no scheme, port, path or IDN).
  // Surplus/invalid lines are dropped silently — same whitelist the native host applies.
  const hosts = raw.filter(h =>
    /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(h.toLowerCase())
  ).map(h => h.toLowerCase()).slice(0, 16);
  // Save even an empty list (clears the override -> native defaults).
  await TarnStorage.saveDpiSettings({ dpiProbeHosts: hosts });
  // Visual feedback so the user knows the save landed.
  flashSaveFeedback("dpiSaveProbeTargetsBtn");
}

function flashSaveFeedback(btnId) {
  const btn = $(btnId);
  if (!btn) return;
  const span = btn.querySelector("span");
  const original = span ? span.textContent : btn.textContent;
  if (span) span.textContent = TarnI18n.t(optionsLang, "saved");
  else btn.textContent = TarnI18n.t(optionsLang, "saved");
  btn.classList.add("saved-flash");
  setTimeout(() => {
    if (span) span.textContent = original;
    else btn.textContent = original;
    btn.classList.remove("saved-flash");
  }, 1500);
}

async function saveDpiSetting(key, value) {
  await TarnStorage.saveDpiSettings({ [key]: value });
}

// ============================================================================
// TagList — reusable editable list for domains / URLs
// ============================================================================
class TagList {
  constructor({ containerId, storageKey, validate, onError, onSaved }) {
    this.container = $(containerId);
    this.storageKey = storageKey;
    this.validate = validate || (() => true);
    this.onError = onError || (() => {});
    this.onSaved = onSaved || (() => {});
    this.items = [];
    this.lang = optionsLang;
    this._build();
  }

  _build() {
    this.container.innerHTML = "";
    // Input row
    this.inputRow = document.createElement("div");
    this.inputRow.className = "tag-add-row";
    this.input = document.createElement("input");
    this.input.type = "text";
    this.input.placeholder = TarnI18n.t(this.lang, "tagPlaceholder");
    this.input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); this.addFromInput(); }
    });
    const addBtn = document.createElement("button");
    addBtn.className = "btn btn-sm";
    addBtn.innerHTML = `<span>${TarnI18n.t(this.lang, "tagAdd")}</span>`;
    addBtn.addEventListener("click", () => this.addFromInput());
    this.inputRow.appendChild(this.input);
    this.inputRow.appendChild(addBtn);
    this.container.appendChild(this.inputRow);
    // Tag list
    this.listEl = document.createElement("div");
    this.listEl.className = "tag-list";
    this.listEl.setAttribute("data-empty", TarnI18n.t(this.lang, "tagEmpty"));
    this.container.appendChild(this.listEl);
    // Toolbar
    this.toolbar = document.createElement("div");
    this.toolbar.className = "tag-toolbar";
    this.clearBtn = document.createElement("button");
    this.clearBtn.className = "btn btn-sm tag-danger";
    this.clearBtn.innerHTML = `<span>${TarnI18n.t(this.lang, "tagClearAll")}</span>`;
    this.clearBtn.addEventListener("click", () => this.clearAll());
    this.toolbar.appendChild(this.clearBtn);
    this.container.appendChild(this.toolbar);
    // Feedback line
    this.feedback = document.createElement("div");
    this.feedback.className = "tag-feedback";
    this.container.appendChild(this.feedback);
  }

  async load() {
    const settings = await TarnStorage.getDpiSettings();
    this.items = Array.isArray(settings[this.storageKey]) ? [...settings[this.storageKey]] : [];
    this._render();
  }

  _render() {
    this.listEl.innerHTML = "";
    for (const item of this.items) {
      const el = document.createElement("div");
      el.className = "tag-item";
      const text = document.createElement("span");
      text.className = "tag-text";
      text.textContent = item;
      text.title = item;
      const rm = document.createElement("button");
      rm.className = "tag-remove";
      rm.innerHTML = "×";
      rm.title = TarnI18n.t(this.lang, "tagRemove");
      rm.addEventListener("click", async () => {
        this.items = this.items.filter(i => i !== item);
        await this._save();
      });
      el.appendChild(text);
      el.appendChild(rm);
      this.listEl.appendChild(el);
    }
    this.clearBtn.disabled = this.items.length === 0;
    this.clearBtn.style.opacity = this.items.length === 0 ? "0.4" : "1";
  }

  async addFromInput() {
    const raw = this.input.value.trim();
    if (!raw) return;
    this.input.value = "";
    const hostname = extractHostname(raw);
    if (!hostname) {
      this._flashFeedback(TarnI18n.t(this.lang, "tagInvalid").replace("{host}", raw), "err");
      this.onError(raw);
      return;
    }
    if (this.items.includes(hostname)) {
      this._flashFeedback("Already in list", "err");
      return;
    }
    if (!this.validate(hostname)) {
      this._flashFeedback(TarnI18n.t(this.lang, "tagInvalid").replace("{host}", hostname), "err");
      return;
    }
    this.items.push(hostname);
    await this._save();
    this._flashFeedback(TarnI18n.t(this.lang, "tagSavedSaved"), "ok");
  }

  async clearAll() {
    if (this.items.length === 0) return;
    if (!confirm(TarnI18n.t(this.lang, "tagClearConfirm"))) return;
    this.items = [];
    await this._save();
  }

  async _save() {
    await TarnStorage.saveDpiSettings({ [this.storageKey]: this.items });
    this._render();
    this.onSaved(this.items);
  }

  _flashFeedback(text, kind) {
    this.feedback.textContent = text;
    this.feedback.className = "tag-feedback " + (kind || "");
    clearTimeout(this._fbTimer);
    this._fbTimer = setTimeout(() => {
      this.feedback.textContent = "";
      this.feedback.className = "tag-feedback";
    }, 2000);
  }
}

// Hold references so real-time sync can refresh them.
const _tagLists = {};

function initTagLists() {
  _tagLists.domains = new TagList({
    containerId: "dpiCustomDomainsWrap",
    storageKey: "dpiCustomDomains",
  });
  _tagLists.excluded = new TagList({
    containerId: "dpiExcludedDomainsWrap",
    storageKey: "dpiExcludedDomains",
  });
  _tagLists.probes = new TagList({
    containerId: "dpiProbeTargetsWrap",
    storageKey: "dpiProbeHosts",
  });
  return Promise.all([
    _tagLists.domains.load(),
    _tagLists.excluded.load(),
    _tagLists.probes.load(),
  ]);
}

// ── Secret game (under profiles) ──
let gameOpen = false;

function initGame() {
  const btn = $("gameLaunchBtn");
  if (btn) btn.addEventListener("click", openGame);
}

function openGame() {
  const overlay = $("gameOverlay");
  const canvas = $("gameCanvas");
  overlay.style.display = "flex";
  gameOpen = true;
  TarnGame.init(canvas);
  TarnGame.start();
  canvas.focus();
}

function closeGame() {
  $("gameOverlay").style.display = "none";
  gameOpen = false;
  TarnGame.stop();
}

document.addEventListener("keydown", (e) => {
  if (!gameOpen) return;
  if (e.code === "Space" || e.code === "ArrowUp") {
    e.preventDefault();
    TarnGame.jump();
  } else if (e.code === "ArrowDown") {
    e.preventDefault();
    TarnGame.duckStart();
  } else if (e.code === "Escape") {
    closeGame();
  }
});

document.addEventListener("keyup", (e) => {
  if (!gameOpen) return;
  if (e.code === "ArrowDown") {
    TarnGame.duckEnd();
  }
});

document.addEventListener("click", (e) => {
  if (!gameOpen) return;
  if (e.target.id === "gameCanvas") {
    TarnGame.jump();
  }
  if (e.target.id === "gameOverlay") {
    closeGame();
  }
});
