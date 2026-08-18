// lib/antitrack-remove.js — MAIN world anti-fingerprinting removal
// SPDX-License-Identifier: GPL-3.0-only
//
// Loads via chrome.scripting.executeScript({files: ["lib/antitrack-remove.js"]})
// from the background service worker. Restores original prototypes that were
// patched by antitrack-injected.js.
//
// Self-contained: finds originals stored as Symbol-keyed non-enumerable property
// on the patched functions. Uses Object.getOwnPropertySymbols() to find the
// symbol whose value is a function (the original native implementation).

(function () {
  "use strict";

  // Helper: find the original function stored as a Symbol property on the patched function
  function findOriginal(patchedFn) {
    var symbols = Object.getOwnPropertySymbols(patchedFn);
    for (var i = 0; i < symbols.length; i++) {
      var desc = Object.getOwnPropertyDescriptor(patchedFn, symbols[i]);
      if (desc && typeof desc.value === "function") {
        return desc.value;
      }
    }
    return null;
  }

  // Helper: restore a prototype method from its patched function's stored original
  function restore(proto, propName) {
    var patched = proto[propName];
    if (!patched) return false;
    var original = findOriginal(patched);
    if (original) {
      proto[propName] = original;
      return true;
    }
    return false;
  }

  // Restore canvas + audio + toString
  restore(HTMLCanvasElement.prototype, "toDataURL");
  restore(CanvasRenderingContext2D.prototype, "getImageData");
  restore(AnalyserNode.prototype, "getFloatFrequencyData");
  restore(Function.prototype, "toString");

  // Restore Battery API (best-effort)
  try { delete navigator.getBattery; } catch (_) {}
})();
