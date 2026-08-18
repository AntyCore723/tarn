// lib/proxy.js — chrome.proxy management, PAC script, kill switch, QUIC block, WebRTC
// SPDX-License-Identifier: GPL-3.0-only
//
// Real-traffic hardening:
//   • setProxy()        → route browser TCP through wireproxy's SOCKS5
//   • applyQuicBlock()  → block UDP/443 (QUIC) so Chrome falls back to TCP
//   • applyKillSwitch() → if the SOCKS proxy is down, block all traffic
//   • setWebRTCProtection() → prevent WebRTC IP leaks

(function (global) {
  "use strict";

  // ---- SOCKS5 proxy setup ----
  function setProxy({ host, port, bypassList, splitTunneling, splitMode, splitDomains }) {
    return new Promise((resolve, reject) => {
      if (!host || !port) return reject(new Error("Missing SOCKS host/port"));

      if (splitTunneling && Array.isArray(splitDomains) && splitDomains.length) {
        const pac = buildPacScript(host, port, bypassList || [], splitMode, splitDomains);
        chrome.proxy.settings.set({
          value: { mode: "pac_script", pacScript: { data: pac } },
          scope: "regular"
        }, () => {
          const err = chrome.runtime.lastError;
          if (err) reject(new Error(err.message)); else resolve();
        });
      } else {
        const rules = {
          singleProxy: { scheme: "socks5", host, port: Number(port) },
          bypassList: bypassList && bypassList.length ? bypassList : ["localhost", "127.0.0.1", "::1", "<local>"]
        };
        chrome.proxy.settings.set({
          value: { mode: "fixed_servers", rules },
          scope: "regular"
        }, () => {
          const err = chrome.runtime.lastError;
          if (err) reject(new Error(err.message)); else resolve();
        });
      }
    });
  }

  function clearProxy() {
    return new Promise((resolve) => {
      chrome.proxy.settings.clear({ scope: "regular" }, () => {
        if (chrome.runtime.lastError) {/* ignore */}
        resolve();
      });
    });
  }

  // ---- WebRTC leak protection ----
  function setWebRTCProtection(enabled) {
    return new Promise((resolve) => {
      const api = chrome.privacy && chrome.privacy.network && chrome.privacy.network.webRTCIPHandlingPolicy;
      if (!api) return resolve(false);
      if (enabled) {
        api.set({ value: "disable_non_proxied_udp", scope: "regular" }, () => {
          if (chrome.runtime.lastError) {/* ignore */}
          resolve(true);
        });
      } else {
        api.clear({ scope: "regular" }, () => {
          if (chrome.runtime.lastError) {/* ignore */}
          resolve(true);
        });
      }
    });
  }

  // ---- QUIC / UDP blocking (force TCP so SOCKS5 can proxy it) ----
  // Chrome's SOCKS5 proxy does NOT handle UDP. QUIC (HTTP/3) uses UDP/443,
  // so without blocking it, some traffic bypasses the tunnel. We block
  // UDP/443 via declarativeNetRequest so Chrome falls back to TCP/443.
  // Rule-ID bands (dynamic rules):
  //   8000-8999  kill switch
  //   9100-9199  QUIC block (this band)
  //   9200-9299  header strip
  //   10000+     adblock (lib/adblock.js)
  // Each band must remove ONLY its own IDs, never the neighbor's.
  const QUIC_RULE_MIN = 9100;
  const QUIC_RULE_MAX = 9199;
  function applyQuicBlock() {
    return new Promise((resolve) => {
      if (!chrome.declarativeNetRequest) return resolve(false);
      const headerRules = [
        {
          id: 9101,
          priority: 2,
          action: {
            type: "modifyHeaders",
            responseHeaders: [{ header: "alt-svc", operation: "remove" }]
          },
          condition: {
            resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest", "script", "image", "stylesheet", "media", "websocket", "other"]
          }
        },
        {
          id: 9102,
          priority: 2,
          action: {
            type: "modifyHeaders",
            responseHeaders: [{ header: "Alt-Svc", operation: "remove" }]
          },
          condition: {
            resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest", "script", "image", "stylesheet", "media", "websocket", "other"]
          }
        }
      ];
      chrome.declarativeNetRequest.getDynamicRules((existing) => {
        const removeIds = existing.map(r => r.id).filter(id => id >= QUIC_RULE_MIN && id < QUIC_RULE_MAX);
        chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: removeIds,
          addRules: headerRules
        }, () => {
          if (chrome.runtime.lastError) {/* ignore */}
          resolve(true);
        });
      });
    });
  }

  function clearQuicBlock() {
    return new Promise((resolve) => {
      if (!chrome.declarativeNetRequest) return resolve(false);
      chrome.declarativeNetRequest.getDynamicRules((existing) => {
        const removeIds = existing.map(r => r.id).filter(id => id >= QUIC_RULE_MIN && id < QUIC_RULE_MAX);
        chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: removeIds,
          addRules: []
        }, () => { resolve(true); });
      });
    });
  }

  // ---- Kill switch ----
  // Uses declarativeNetRequest to block ALL traffic when tunnel drops.
  // This prevents any data from leaking outside the VPN.
  // Rules allow localhost (for native host) and the extension itself.
  function applyKillSwitch(socksAddr) {
    return new Promise((resolve) => {
      if (!chrome.declarativeNetRequest) return resolve(false);

      const blockRules = [
        // Allow localhost (native host communication) — IPv4 loopback
        {
          id: 8001,
          priority: 3,
          action: { type: "allow" },
          condition: {
            urlFilter: "||127.0.0.1",
            resourceTypes: ["main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest", "ping", "media", "websocket", "other"]
          }
        },
        // Allow localhost — IPv6 loopback (::1)
        {
          id: 8002,
          priority: 3,
          action: { type: "allow" },
          condition: {
            urlFilter: "||[::1]",
            resourceTypes: ["main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest", "ping", "media", "websocket", "other"]
          }
        },
        // Allow localhost hostname
        {
          id: 8003,
          priority: 3,
          action: { type: "allow" },
          condition: {
            urlFilter: "||localhost",
            resourceTypes: ["main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest", "ping", "media", "websocket", "other"]
          }
        },
        // Allow extension's own requests
        {
          id: 8004,
          priority: 3,
          action: { type: "allow" },
          condition: {
            regexFilter: `chrome-extension://${chrome.runtime.id}/.*`,
            resourceTypes: ["main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest", "ping", "media", "websocket", "other"]
          }
        },
        // Block everything else
        {
          id: 8000,
          priority: 1,
          action: { type: "block" },
          condition: {
            resourceTypes: ["main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest", "ping", "media", "websocket", "other"]
          }
        }
      ];

      chrome.declarativeNetRequest.getDynamicRules((existing) => {
        const removeIds = existing.map(r => r.id).filter(id => id >= 8000 && id < 9000);
        chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: removeIds,
          addRules: blockRules
        }, () => {
          if (chrome.runtime.lastError) { console.error("kill switch error:", chrome.runtime.lastError); }
          resolve(true);
        });
      });
    });
  }

  function clearKillSwitch() {
    return new Promise((resolve) => {
      if (!chrome.declarativeNetRequest) return resolve(false);
      // Remove any leftover kill switch rules (IDs 8000-8999)
      chrome.declarativeNetRequest.getDynamicRules((existing) => {
        const removeIds = existing.map(r => r.id).filter(id => id >= 8000 && id < 9000);
        if (removeIds.length === 0) return resolve(true);
        chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: removeIds,
          addRules: []
        }, () => { resolve(true); });
      });
    });
  }

  // ---- PAC script for split tunneling ----
  function buildPacScript(host, port, bypassList, splitMode, splitDomains) {
    const proxy = `SOCKS5 ${host}:${port}; SOCKS ${host}:${port}; DIRECT`;
    const domains = (splitDomains || []).map(d => d.trim().toLowerCase()).filter(Boolean);
    const bypass = (bypassList || []).map(b => JSON.stringify(b)).join(",");

    let body = "";
    body += `  var host = host.toLowerCase();\n`;
    body += `  var bypass = [${bypass}];\n`;
    body += `  for (var i=0;i<bypass.length;i++){ if (shExpMatch(host, bypass[i])) return "DIRECT"; }\n`;
    body += `  var list = [${domains.map(d => JSON.stringify(d)).join(",")}];\n`;
    body += `  var match = false;\n`;
    body += `  for (var i=0;i<list.length;i++){ if (host === list[i] || dnsDomainIs(host, "."+list[i]) || shExpMatch(host, "*."+list[i])) { match = true; break; } }\n`;
    if (splitMode === "include") {
      body += `  return match ? ${JSON.stringify(proxy)} : "DIRECT";\n`;
    } else {
      body += `  return match ? "DIRECT" : ${JSON.stringify(proxy)};\n`;
    }
    return `function FindProxyForURL(url, host) {\n${body}}\n`;
  }

  function testPacScript(script) {
    return /function\s+FindProxyForURL/.test(script);
  }

  // ---- Strip identifying headers (DPI countermeasure) ----
  // Removes server, x-powered-by, alt-svc, and other headers that reveal
  // browser fingerprint or enable QUIC/HTTP3 upgrades.
  function applyStripHeaders(options) {
    return new Promise((resolve) => {
      if (!chrome.declarativeNetRequest) return resolve(false);
      const rules = [];
      let id = 9200;
      const headers = (options && options.headers) || ["alt-svc", "Alt-Svc", "server", "Server", "x-powered-by", "X-Powered-By"];
      // RFC 7230 token: header names may only contain tchar. DNR
      // updateDynamicRules is ATOMIC — a single invalid header name (empty,
      // space, control char, non-ASCII) would make the whole call fail and
      // silently drop every strip rule. Validate + dedupe (case-insensitive,
      // HTTP header names are case-insensitive) so user-configured junk can
      // never break the rule set.
      const seen = new Set();
      for (const raw of headers) {
        const h = String(raw || "").trim();
        if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(h)) continue;
        const key = h.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        rules.push({
          id: id++,
          priority: 2,
          action: { type: "modifyHeaders", responseHeaders: [{ header: h, operation: "remove" }] },
          condition: { resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest", "script", "image", "stylesheet", "media", "websocket", "other"] }
        });
      }
      chrome.declarativeNetRequest.getDynamicRules((existing) => {
        const removeIds = existing.map(r => r.id).filter(id => id >= 9200 && id < 9300);
        chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: removeIds,
          addRules: rules
        }, () => {
          if (chrome.runtime.lastError) {
            console.error("applyStripHeaders failed:", chrome.runtime.lastError);
            resolve(false);
            return;
          }
          resolve(true);
        });
      });
    });
  }

  function clearStripHeaders() {
    return new Promise((resolve) => {
      if (!chrome.declarativeNetRequest) return resolve(false);
      chrome.declarativeNetRequest.getDynamicRules((existing) => {
        const removeIds = existing.map(r => r.id).filter(id => id >= 9200 && id < 9300);
        if (removeIds.length === 0) return resolve(true);
        chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: removeIds, addRules: [] }, () => { resolve(true); });
      });
    });
  }

  global.TarnProxy = {
    setProxy, clearProxy, setWebRTCProtection,
    applyQuicBlock, clearQuicBlock,
    applyKillSwitch, clearKillSwitch,
    applyStripHeaders, clearStripHeaders,
    buildPacScript, testPacScript
  };
})(typeof self !== "undefined" ? self : this);
