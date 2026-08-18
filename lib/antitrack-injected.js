// lib/antitrack-injected.js — MAIN world anti-fingerprinting patches
// SPDX-License-Identifier: GPL-3.0-only
//
// Loads via chrome.scripting.executeScript({files: ["lib/antitrack-injected.js"]})
// from the background service worker. The file is loaded VERBATIM (not toString-
// serialized), so all closures, "use strict", and local state work correctly.
//
// IDEMPOTENT: checks if patched functions have a Symbol-keyed property whose
// value is a function (the stored original). If yes → already patched, skip.
// This prevents re-injection from corrupting originals (the v1.9.19 bug).
//
// State persistence: originals are stored as a non-enumerable Symbol-keyed
// property on each patched function. Private Symbol defeats naive detection
// via getOwnPropertyNames/Object.keys/for...in. The separate antitrack-remove.js
// restores originals by iterating getOwnPropertySymbols().

(function () {
  "use strict";

  // Private Symbol — NOT visible via Object.getOwnPropertyNames().
  // Only detectable via Object.getOwnPropertySymbols() + knowing which symbol to use.
  var ORIGINALS_SYM = Symbol("wgAtOriginals");

  // Already injected? Check if the patched function has any Symbol property
  // whose value is a function (the stored original). This survives across
  // separate executeScript calls (each creates a new Symbol instance).
  function hasOriginalStored(fn) {
    var symbols = Object.getOwnPropertySymbols(fn);
    for (var i = 0; i < symbols.length; i++) {
      var desc = Object.getOwnPropertyDescriptor(fn, symbols[i]);
      if (desc && typeof desc.value === "function") return true;
    }
    return false;
  }

  // No window property needed — eliminates detection vector.
  if (hasOriginalStored(HTMLCanvasElement.prototype.toDataURL)) return;

  // Constants
  var CANVAS_NOISE = 0.0005;
  var AUDIO_NOISE = 0.005;

  // Helper: inject noise into pixel data
  // CSPRNG-backed (crypto.getRandomValues) with Math.random fallback for
  // non-secure contexts; per-pixel noise must not be predictable from a
  // seed so the fingerprint stays unique across visits.
  function randUniform() {
    if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
      var u32 = new Uint32Array(1);
      crypto.getRandomValues(u32);
      return u32[0] / 4294967296;
    }
    return Math.random();
  }

  function injectNoise(data, pixelCount) {
    var i, idx, noise;
    for (i = 0; i < pixelCount; i++) {
      idx = i * 4;
      if (data[idx + 3] > 0) {
        noise = randUniform() * CANVAS_NOISE * 2 - CANVAS_NOISE;
        data[idx]     = Math.min(255, Math.max(0, data[idx]     + noise * 255));
        data[idx + 1] = Math.min(255, Math.max(0, data[idx + 1] + noise * 255));
        data[idx + 2] = Math.min(255, Math.max(0, data[idx + 2] + noise * 255));
      }
    }
  }

  // Save originals (stored as non-enumerable property on each patched function)
  var origStore = {
    toDataURL: HTMLCanvasElement.prototype.toDataURL,
    getImageData: CanvasRenderingContext2D.prototype.getImageData,
    getFloatFreqData: AnalyserNode.prototype.getFloatFrequencyData,
    fnToString: Function.prototype.toString,
    getBattery: navigator.getBattery
  };

  // Store originals on patched function (backup for removal)
  function storeOriginals(fn, original) {
    Object.defineProperty(fn, ORIGINALS_SYM, {
      value: original,
      enumerable: false,
      configurable: true,
      writable: false
    });
  }

  // ── Canvas toDataURL ──
  var patchedToDataURL = function () {
    if (this.width <= 280 && this.height <= 280) {
      var ctx = this.getContext("2d");
      if (ctx) {
        try {
          var imgData = ctx.getImageData(0, 0, this.width, this.height);
          injectNoise(imgData.data, this.width * this.height);
          ctx.putImageData(imgData, 0, 0);
        } catch (_) {}
      }
    }
    return origStore.toDataURL.apply(this, arguments);
  };
  HTMLCanvasElement.prototype.toDataURL = patchedToDataURL;
  Object.defineProperty(HTMLCanvasElement.prototype.toDataURL, "name", { value: "toDataURL", configurable: true });
  Object.defineProperty(HTMLCanvasElement.prototype.toDataURL, "length", { value: 0, configurable: true });
  storeOriginals(HTMLCanvasElement.prototype.toDataURL, origStore.toDataURL);

  // ── Canvas getImageData ──
  var patchedGetImageData = function (sx, sy, sw, sh) {
    var data = origStore.getImageData.call(this, sx, sy, sw, sh);
    if (sw <= 280 && sh <= 280) injectNoise(data.data, sw * sh);
    return data;
  };
  CanvasRenderingContext2D.prototype.getImageData = patchedGetImageData;
  Object.defineProperty(CanvasRenderingContext2D.prototype.getImageData, "name", { value: "getImageData", configurable: true });
  Object.defineProperty(CanvasRenderingContext2D.prototype.getImageData, "length", { value: 4, configurable: true });
  storeOriginals(CanvasRenderingContext2D.prototype.getImageData, origStore.getImageData);

  // ── Audio getFloatFrequencyData ──
  var patchedGetFloatFreqData = function (array) {
    origStore.getFloatFreqData.call(this, array);
    for (var i = 0; i < array.length; i++) array[i] += (randUniform() - 0.5) * AUDIO_NOISE;
  };
  AnalyserNode.prototype.getFloatFrequencyData = patchedGetFloatFreqData;
  Object.defineProperty(AnalyserNode.prototype.getFloatFrequencyData, "name", { value: "getFloatFrequencyData", configurable: true });
  Object.defineProperty(AnalyserNode.prototype.getFloatFrequencyData, "length", { value: 1, configurable: true });
  storeOriginals(AnalyserNode.prototype.getFloatFrequencyData, origStore.getFloatFreqData);

  // ── Function.prototype.toString stealth ──
  var patchedToString = function () {
    if (this === HTMLCanvasElement.prototype.toDataURL) return origStore.fnToString.call(origStore.toDataURL);
    if (this === CanvasRenderingContext2D.prototype.getImageData) return origStore.fnToString.call(origStore.getImageData);
    if (this === AnalyserNode.prototype.getFloatFrequencyData) return origStore.fnToString.call(origStore.getFloatFreqData);
    if (this === Function.prototype.toString) return origStore.fnToString.call(origStore.fnToString);
    return origStore.fnToString.call(this);
  };
  Function.prototype.toString = patchedToString;
  Object.defineProperty(Function.prototype.toString, "name", { value: "toString", configurable: true });
  Object.defineProperty(Function.prototype.toString, "length", { value: 0, configurable: true });
  storeOriginals(Function.prototype.toString, origStore.fnToString);

  // ── Battery API ──
  if (origStore.getBattery) {
    Object.defineProperty(navigator, "getBattery", { value: undefined, configurable: true });
  }

  // ── Speech synthesis: pass-through (real voices, no fingerprinting benefit) ──
})();
