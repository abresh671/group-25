// Service worker for hooked (MV3).
// - Maintains settings and lists.
// - Applies dynamic DNR rules to filter malicious domains.
// - Coordinates page risk assessments from content script.
// - Early checks on navigation.
// - Registers the content script for all sites.

const DEFAULT_SETTINGS = {
  threshold: 60,            // Risk score [0..100] above which we alert
  suspiciousTLDWeight: 15,  // Weights used by lightweight navigator checks
  punycodeWeight: 25
};

const state = {
  settings: null,
  allowlist: new Set(),
  blocklist: new Set(),
  dynamicRulesByDomain: new Map() // domain -> ruleId (we use urlFilter pattern; id per domain)
};

const RULE_ID_BASE = 20000;
const SuspiciousTLDs = new Set([
  "zip","mov","country","gq","tk","ml","cf","xyz","top","club","link","work","click"
]);

// ---------- Storage helpers ----------
async function loadAll() {
  const { settings, allowlist, blocklist } = await chrome.storage.local.get({
    settings: DEFAULT_SETTINGS,
    allowlist: [],
    blocklist: []
  });
  state.settings = { ...DEFAULT_SETTINGS, ...settings };
  state.allowlist = new Set(allowlist);
  state.blocklist = new Set(blocklist);
  await rebuildDynamicRules();
  await registerContentScript();
}

async function saveLists() {
  await chrome.storage.local.set({
    allowlist: [...state.allowlist],
    blocklist: [...state.blocklist]
  });
}

// ---------- DNR (filtering) ----------
async function rebuildDynamicRules() {
  const removeRuleIds = [...state.dynamicRulesByDomain.values()];
  if (removeRuleIds.length) {
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds });
    state.dynamicRulesByDomain.clear();
  }

  const addRules = [];
  let nextId = RULE_ID_BASE;

  for (const domain of state.blocklist) {
    const id = nextId++;
    state.dynamicRulesByDomain.set(domain, id);
    // Use urlFilter to match domain and all subdomains: ||example.com^
    addRules.push({
      id,
      priority: 1,
      action: { type: "block" },
      condition: {
        urlFilter: `||${domain}^`,
        resourceTypes: ["main_frame", "sub_frame"]
      }
    });
  }

  if (addRules.length) {
    await chrome.declarativeNetRequest.updateDynamicRules({ addRules });
  }
}

// ---------- Utils ----------
function getETLDPlusOne(hostname) {
  const parts = hostname.split('.').filter(Boolean);
  if (parts.length <= 2) return hostname;
  return parts.slice(-2).join('.');
}
function isPunycode(hostname) { return hostname.includes('xn--'); }
function tld(hostname) {
  const parts = hostname.split('.').filter(Boolean);
  return parts.length ? parts[parts.length - 1].toLowerCase() : '';
}
function computeEarlyRisk(urlStr) {
  try {
    const u = new URL(urlStr);
    const host = u.hostname.toLowerCase();
    let score = 0;
    if (isPunycode(host)) score += state.settings.punycodeWeight;
    if (SuspiciousTLDs.has(tld(host))) score += state.settings.suspiciousTLDWeight;
    if (host.length > 55) score += 10;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) score += 10;
    return { score, host, domain: getETLDPlusOne(host) };
  } catch {
    return { score: 0, host: "", domain: "" };
  }
}

// ---------- Content script registration ----------
async function registerContentScript() {
  try {
    // Remove existing (in case of updated extension)
    const existing = await chrome.scripting.getRegisteredContentScripts();
    const toUnreg = existing.filter(cs => cs.id === "hooked-cs").map(cs => cs.id);
    if (toUnreg.length) await chrome.scripting.unregisterContentScripts({ ids: toUnreg });
  } catch { /* no-op */ }

  await chrome.scripting.registerContentScripts([{
    id: "hooked-cs",
    js: ["content.js"],
    matches: ["<all_urls>"],
    runAt: "document_start",
    allFrames: false,
    persistAcrossSessions: true
  }]);
}

// ---------- Navigation monitoring ----------
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // only top-level
  const { url, tabId } = details;

  const { score, host, domain } = computeEarlyRisk(url);
  if (!host) return;

  if (state.allowlist.has(domain)) return;
  if (state.blocklist.has(domain)) return; // DNR will block

  if (score >= state.settings.threshold) {
    try {
      await chrome.notifications.create(`hooked-early-${tabId}`, {
        type: "basic",
        iconUrl: "assets/notify-128.png",
        title: "hooked: Suspicious site detected",
        message: `${host} looks risky (score ${score}). Click to open details.`,
        priority: 2
      });
    } catch {
      // ignore if notifications fail
    }
  }
});

// ---------- Messaging with content script & popup ----------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg.type === "getState") {
      const domain = sender?.url ? getETLDPlusOne(new URL(sender.url).hostname) : "";
      sendResponse({
        settings: state.settings,
        allowlist: [...state.allowlist],
        blocklist: [...state.blocklist],
        currentDomain: domain
      });
      return;
    }

    if (msg.type === "riskReport") {
      // msg: { url, score, findings: [...], host, domain }
      const { score, domain } = msg;
      if (state.allowlist.has(domain)) {
        sendResponse({ action: "allowed" });
        return;
      }
      if (score >= state.settings.threshold) {
        sendResponse({ action: "warn" });
        return;
      }
      sendResponse({ action: "ok" });
      return;
    }

    if (msg.type === "blockDomain") {
      const { domain } = msg;
      state.blocklist.add(domain);
      state.allowlist.delete(domain);
      await saveLists();
      await rebuildDynamicRules();
      sendResponse({ ok: true });
      return;
    }

    if (msg.type === "allowDomain") {
      const { domain } = msg;
      state.allowlist.add(domain);
      state.blocklist.delete(domain);
      await saveLists();
      await rebuildDynamicRules();
      sendResponse({ ok: true });
      return;
    }

    if (msg.type === "removeFromList") {
      const { domain, list } = msg; // list: "allow" | "block"
      if (list === "allow") state.allowlist.delete(domain);
      if (list === "block") state.blocklist.delete(domain);
      await saveLists();
      await rebuildDynamicRules();
      sendResponse({ ok: true });
      return;
    }

    if (msg.type === "updateSettings") {
      state.settings = { ...state.settings, ...msg.settings };
      await chrome.storage.local.set({ settings: state.settings });
      sendResponse({ ok: true, settings: state.settings });
      return;
    }
  })();

  return true; // async
});

// ---------- Install / startup ----------
chrome.runtime.onInstalled.addListener(loadAll);
chrome.runtime.onStartup.addListener(loadAll);
