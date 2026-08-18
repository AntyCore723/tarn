// lib/antitrack-content.js — ISOLATED world anti-fingerprinting coordinator
// SPDX-License-Identifier: GPL-3.0-only
//
// Runs in ISOLATED world (MV3 default) so it has chrome.storage access.
// This file is a thin shim: it detects storage changes and notifies the
// background service worker, which owns chrome.scripting.executeScript
// and performs the actual MAIN-world injection.
//
// NOTE: The background service worker has its own storage.onChanged listener
// (inside the antitrack IIFE) that handles sync. This content script provides
// redundant coverage for edge cases (e.g., tab opened before SW started).

(function () {
  "use strict";

  if (window.location.protocol === "chrome-extension:") return;

  var lastWanted = null;

  function shouldActivate(state, dpiSettings) {
    if (!state || state.status !== "connected") return false;
    return !dpiSettings || dpiSettings.dpiAntiTrack !== false;
  }

  function sync() {
    chrome.storage.local.get(["tarn.state", "tarn.dpiSettings"], function (result) {
      var wanted = shouldActivate(result["tarn.state"], result["tarn.dpiSettings"]);
      if (wanted === lastWanted) return;
      lastWanted = wanted;
      // Notify background (background ignores this message — it has its own
      // storage.onChanged listener. Kept for future use / debugging).
      try {
        chrome.runtime.sendMessage({ type: "ANTITRACK_SYNC", wanted: wanted }).catch(function () {});
      } catch (_) { /* runtime unavailable */ }
    });
  }

  try {
    chrome.storage.onChanged.addListener(function (changes, area) {
      if (area !== "local") return;
      if (changes["tarn.state"] || changes["tarn.dpiSettings"]) sync();
    });
    sync();
  } catch (_) { /* storage API unavailable */ }
})();
