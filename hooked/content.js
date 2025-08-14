// Injected into pages. Computes a risk score using simple heuristics.
// Reports to background. If background says "warn", render a blocking banner.

(function () {
  const PAGE = new URL(location.href);
  const HOST = PAGE.hostname.toLowerCase();

  function getETLDPlusOne(hostname) {
    const parts = hostname.split('.').filter(Boolean);
    if (parts.length <= 2) return hostname;
    return parts.slice(-2).join('.');
  }

  function isPunycode(hostname) {
    return hostname.includes('xn--');
  }

  function looksLikeBrand(text) {
    const brands = ["apple", "paypal", "microsoft", "google", "amazon", "bank", "credential", "wallet", "verify", "support", "security"];
    const t = text.toLowerCase();
    return brands.some(b => t.includes(b));
  }

  function hrefHost(href) {
    try { return new URL(href, location.href).hostname.toLowerCase(); }
    catch { return ""; }
  }

  function calcRisk() {
    let score = 0;
    const findings = [];

    // Punycode / suspicious TLD
    if (isPunycode(HOST)) { score += 25; findings.push("Domain uses punycode."); }
    const tld = HOST.split('.').pop();
    const susTLD = new Set(["zip","mov","country","gq","tk","ml","cf","xyz","top","club","link","work","click"]);
    if (susTLD.has((tld||"").toLowerCase())) { score += 15; findings.push(`Suspicious TLD .${tld}`); }

    // IP address host
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(HOST)) { score += 10; findings.push("Domain is a raw IP address."); }

    // Password form
    const hasPassword = !!document.querySelector('input[type="password"]');
    if (hasPassword) { score += 20; findings.push("Password field present."); }

    // Login/verify wording
    const bodyText = (document.body?.innerText || "").slice(0, 20000); // cap for perf
    if (looksLikeBrand(bodyText) && /login|verify|update|unlock|suspend/i.test(bodyText)) {
      score += 10; findings.push("Brand & login/verify wording detected.");
    }

    // Link mismatch: anchor text contains well-known domain but href points elsewhere
    const anchors = Array.from(document.querySelectorAll('a[href]')).slice(0, 200);
    for (const a of anchors) {
      const text = (a.textContent || "").trim().toLowerCase();
      const dest = hrefHost(a.getAttribute('href'));
      if (!dest) continue;
      const hints = ["paypal.com","apple.com","microsoft.com","google.com","amazon.com","bankofamerica.com","chase.com"];
      const hinted = hints.find(h => text.includes(h.replace("www.","")));
      if (hinted && !dest.endsWith(hinted)) {
        score += 10; findings.push(`Link mismatch: "${hinted}" -> ${dest}`);
        break;
      }
    }

    // Hidden iframes or overlays covering page
    const overlays = Array.from(document.querySelectorAll('iframe,div'))
      .filter(el => {
        try {
          const st = getComputedStyle(el);
          const w = el.offsetWidth, h = el.offsetHeight;
          const covers = w > innerWidth * 0.9 && h > innerHeight * 0.9 && st.position === "fixed" && st.zIndex && Number(st.zIndex) > 9999;
          const hidden = st.opacity === "0" || st.visibility === "hidden";
          return (el.tagName === "IFRAME" && w > 600 && h > 400) || covers || hidden;
        } catch { return false; }
      });
    if (overlays.length) { score += 10; findings.push("Suspicious overlays/iframes detected."); }

    // Data URL main document (rare and suspicious)
    if (location.href.startsWith("data:")) { score += 20; findings.push("Page served from a data: URL."); }

    // Very long hostname
    if (HOST.length > 55) { score += 10; findings.push("Very long hostname."); }

    const domain = getETLDPlusOne(HOST);
    return { score, findings, host: HOST, domain };
  }

  function renderWarning(findings, score, domain) {
    if (document.getElementById("hooked-banner")) return;

    const style = document.createElement('style');
    style.textContent = `
      #hooked-blocker {
        position: fixed; inset: 0; background: rgba(0,0,0,.65);
        z-index: 2147483646; backdrop-filter: blur(1px);
      }
      #hooked-banner {
        font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
        position: fixed; left: 0; right: 0; top: 0;
        background: #111;
        color: #fff; z-index: 2147483647;
        padding: 14px 16px;
        border-bottom: 3px solid #ff5252;
        display: flex; gap: 12px; align-items: center;
        box-shadow: 0 6px 24px rgba(0,0,0,.35);
      }
      #hooked-banner strong { color: #ffb300; }
      #hooked-banner .spacer { flex: 1; }
      #hooked-banner button {
        all: unset; background: #ff5252; color: #fff; padding: 8px 12px;
        border-radius: 8px; cursor: pointer; font-weight: 600;
      }
      #hooked-banner button.secondary { background: #444; }
      #hooked-banner details {
        margin-left: 8px; background:#222; padding:6px 8px; border-radius:6px;
        max-width: 40vw; overflow:auto;
      }
    `;
    document.documentElement.appendChild(style);

    const blocker = document.createElement('div');
    blocker.id = "hooked-blocker";
    document.documentElement.appendChild(blocker);

    const bar = document.createElement('div');
    bar.id = "hooked-banner";
    bar.innerHTML = `
      <div>⚠️ <strong>hooked</strong> suspects phishing on <strong>${domain}</strong> (score ${score}).</div>
      <details><summary>Details</summary><ul style="margin:6px 0;padding-left:18px">${findings.map(f=>`<li>${f}</li>`).join("")}</ul></details>
      <div class="spacer"></div>
      <button id="hooked-block">Block domain</button>
      <button id="hooked-allow" class="secondary">Allow for now</button>
    `;
    document.documentElement.appendChild(bar);

    const teardown = () => {
      blocker.remove();
      bar.remove();
    };

    document.getElementById('hooked-block').addEventListener('click', async () => {
      await chrome.runtime.sendMessage({ type: "blockDomain", domain });
      // Keep the page blocked visually; reload will get blocked by DNR next time
      location.reload();
    });
    document.getElementById('hooked-allow').addEventListener('click', async () => {
      await chrome.runtime.sendMessage({ type: "allowDomain", domain });
      teardown();
    });
  }

  async function run() {
    const { score, findings, domain } = calcRisk();
    try {
      const res = await chrome.runtime.sendMessage({
        type: "riskReport",
        url: location.href,
        score,
        findings,
        host: HOST,
        domain
      });
      if (res && res.action === "warn") {
        renderWarning(findings, score, domain);
      }
    } catch {
      // ignore if service worker is not ready
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", run, { once: true });
  } else {
    run();
  }
})();
