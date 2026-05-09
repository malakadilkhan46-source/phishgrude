// PhishGuard background service worker
// Scans visited URLs against VirusTotal and notifies the user if dangerous.

const VT_BASE = "https://www.virustotal.com/api/v3";
const CACHE_TTL_MS = 1000 * 60 * 60 * 6; // 6 hours
const SKIP_PROTOCOLS = ["chrome:", "chrome-extension:", "edge:", "about:", "file:", "moz-extension:"];

async function getApiKey() {
  const { vtApiKey } = await chrome.storage.local.get("vtApiKey");
  return vtApiKey || "";
}

async function getCache(key) {
  const { cache = {} } = await chrome.storage.local.get("cache");
  const entry = cache[key];
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL_MS) return null;
  return entry.result;
}

async function setCache(key, result) {
  const { cache = {} } = await chrome.storage.local.get("cache");
  cache[key] = { ts: Date.now(), result };
  await chrome.storage.local.set({ cache });
}

async function logHistory(entry) {
  const { history = [] } = await chrome.storage.local.get("history");
  history.unshift(entry);
  await chrome.storage.local.set({ history: history.slice(0, 50) });
}

function urlToVtId(url) {
  // VirusTotal expects base64url of the URL with no padding
  const b64 = btoa(unescape(encodeURIComponent(url)));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function classify(stats) {
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  if (malicious >= 1) return "dangerous";
  if (suspicious >= 2) return "suspicious";
  return "safe";
}

async function vtLookup(url, apiKey) {
  const id = urlToVtId(url);
  const res = await fetch(`${VT_BASE}/urls/${id}`, {
    headers: { "x-apikey": apiKey },
  });
  if (res.status === 404) {
    // Submit for analysis
    const submit = await fetch(`${VT_BASE}/urls`, {
      method: "POST",
      headers: {
        "x-apikey": apiKey,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: `url=${encodeURIComponent(url)}`,
    });
    if (!submit.ok) throw new Error(`VT submit failed: ${submit.status}`);
    // Give it a moment then poll once
    await new Promise((r) => setTimeout(r, 4000));
    const second = await fetch(`${VT_BASE}/urls/${id}`, { headers: { "x-apikey": apiKey } });
    if (!second.ok) throw new Error(`VT lookup failed: ${second.status}`);
    return await second.json();
  }
  if (!res.ok) throw new Error(`VT lookup failed: ${res.status}`);
  return await res.json();
}

async function scanUrl(url, tabId) {
  try {
    const u = new URL(url);
    if (SKIP_PROTOCOLS.includes(u.protocol)) return;

    const apiKey = await getApiKey();
    if (!apiKey) {
      await chrome.action.setBadgeBackgroundColor({ color: "#9CA3AF" });
      await chrome.action.setBadgeText({ tabId, text: "KEY" });
      return;
    }

    const cacheKey = `${u.protocol}//${u.host}${u.pathname}`;
    let cached = await getCache(cacheKey);
    let result;
    if (cached) {
      result = cached;
    } else {
      const data = await vtLookup(cacheKey, apiKey);
      const stats = data?.data?.attributes?.last_analysis_stats || {};
      const verdict = classify(stats);
      result = { verdict, stats, scannedAt: Date.now(), url: cacheKey };
      await setCache(cacheKey, result);
    }

    await logHistory({ url: cacheKey, verdict: result.verdict, ts: Date.now(), stats: result.stats });

    const badgeColor =
      result.verdict === "dangerous" ? "#DC2626" :
      result.verdict === "suspicious" ? "#F59E0B" : "#16A34A";
    const badgeText =
      result.verdict === "dangerous" ? "!" :
      result.verdict === "suspicious" ? "?" : "✓";
    await chrome.action.setBadgeBackgroundColor({ color: badgeColor });
    await chrome.action.setBadgeText({ tabId, text: badgeText });

    if (result.verdict !== "safe") {
      const title = result.verdict === "dangerous" ? "⚠️ Dangerous site detected" : "⚠️ Suspicious site";
      const message = `${cacheKey}\nMalicious: ${result.stats.malicious || 0}, Suspicious: ${result.stats.suspicious || 0}`;
      chrome.notifications.create(`pg-${tabId}-${Date.now()}`, {
        type: "basic",
        iconUrl: "icon.png",
        title,
        message,
        priority: 2,
      });
      // Tell content script to display the in-page banner
      chrome.tabs.sendMessage(tabId, { type: "PHISHGUARD_ALERT", result }).catch(() => {});
    }

    chrome.runtime.sendMessage({ type: "PHISHGUARD_RESULT", tabId, result }).catch(() => {});
  } catch (err) {
    console.error("[PhishGuard] scan error", err);
    await chrome.action.setBadgeBackgroundColor({ color: "#6B7280" });
    await chrome.action.setBadgeText({ tabId, text: "ERR" });
  }
}

chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return;
  scanUrl(details.url, details.tabId);
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId);
  if (tab?.url) scanUrl(tab.url, tabId);
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "PHISHGUARD_RESCAN") {
    (async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.url) {
        const u = new URL(tab.url);
        const cacheKey = `${u.protocol}//${u.host}${u.pathname}`;
        const { cache = {} } = await chrome.storage.local.get("cache");
        delete cache[cacheKey];
        await chrome.storage.local.set({ cache });
        await scanUrl(tab.url, tab.id);
        sendResponse({ ok: true });
      } else sendResponse({ ok: false });
    })();
    return true;
  }
});