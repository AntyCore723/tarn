// lib/adblock.js — browser-level ad & tracking domain blocking.
// SPDX-License-Identifier: GPL-3.0-only
//
// Uses chrome.declarativeNetRequest dynamic rules with IDs 10000-19999
// (reserved for ad blocking; other subsystems use 7000-9999). Blocking
// requests to known ad-serving domains applies at the browser network layer,
// so it works BOTH with the packet filter running and through the WG tunnel.
(function (global) {
  "use strict";

  const RULE_ID_BASE = 10000;

  // Ad-serving / ad-exchange networks. Deliberately excludes analytics-only
  // domains (Google Analytics, Yandex Metrica, GTM) and CDNs — blocking those
  // would break sites, not ads.
  const AD_DOMAINS = [
    "doubleclick.net",
    "googleadservices.com",
    "googlesyndication.com",
    "googletagservices.com",
    "2mdn.net",
    "adservice.google.",
    "adnxs.com",
    "adform.net",
    "adsrvr.org",
    "criteo.com",
    "criteo.net",
    "rubiconproject.com",
    "pubmatic.com",
    "openx.net",
    "taboola.com",
    "outbrain.com",
    "bidswitch.net",
    "casalemedia.com",
    "advertising.com",
    "adsafeprotected.com",
    "moatads.com",
    "revcontent.com",
    "adcolony.com",
    "inmobi.com",
    "applovin.com",
    "vungle.com",
    "smartadserver.com",
    "adspirit.de",
    "adition.com",
    "plista.com",
    "mgid.com",
    "nativery.com",
    "onetag.com",
    "popads.net",
    "rhythmone.com",
    "sharethrough.com",
    "sovrn.com",
    "spotx.tv",
    "teads.tv",
    "triplelift.com",
    "unrulymedia.com",
    "zergnet.com",
    "admixer.net",
    "media.net",
    "emxdgt.com",
    "gumgum.com",
    "kargo.com",
    "nativo.com",
    "yieldmo.com",
    "adyoulike.com",
    "quantserve.com",
    "scorecardresearch.com",
    "an.yandex.ru",
    "adfox.ru",
    "adriver.ru",
    "ad.mail.ru",
    "ads.vk.com"
  ];

  // "main_frame" is intentionally absent: a user manually visiting an
  // ad-domain should still see the page rather than a blank tab.
  const RESOURCE_TYPES = ["script", "image", "xmlhttprequest", "sub_frame", "media", "font", "object", "ping", "other"];

  function buildRules(enabled) {
    if (!enabled) return [];
    return AD_DOMAINS.map((domain, i) => ({
      id: RULE_ID_BASE + i,
      priority: 1,
      action: { type: "block" },
      condition: {
        urlFilter: "||" + domain + (domain.endsWith(".") ? "" : "^"),
        resourceTypes: RESOURCE_TYPES
      }
    }));
  }

  function getAdBlockRuleIds() {
    return new Promise((resolve) => {
      try {
        chrome.declarativeNetRequest.getDynamicRules((existing) => {
          resolve(existing.map(r => r.id).filter(id => id >= RULE_ID_BASE && id < RULE_ID_BASE + 1000));
        });
      } catch (e) { resolve([]); }
    });
  }

  async function apply(enabled) {
    if (!chrome.declarativeNetRequest) return false;
    const rules = buildRules(!!enabled);
    const removeIds = await getAdBlockRuleIds();
    return new Promise((resolve) => {
      chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: removeIds,
        addRules: rules
      }, () => {
        if (chrome.runtime.lastError) { console.error("adblock error:", chrome.runtime.lastError); }
        resolve(true);
      });
    });
  }

  global.TarnBlockAds = { apply };
})(typeof globalThis !== "undefined" ? globalThis : this);
