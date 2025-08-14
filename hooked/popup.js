// Popup logic: show threshold, current domain, and allow/block list management.

async function getState() {
  try {
    return await chrome.runtime.sendMessage({ type: "getState" });
  } catch {
    return null;
  }
}

function renderList(el, items, listName) {
  el.innerHTML = "";
  for (const d of items) {
    const li = document.createElement("li");
    li.innerHTML = `<span class="pill">${d}</span> <button data-d="${d}" class="secondary">Remove</button>`;
    li.querySelector("button").addEventListener("click", async (ev) => {
      const dom = ev.currentTarget.getAttribute("data-d");
      await chrome.runtime.sendMessage({ type: "removeFromList", domain: dom, list: listName });
      init();
    });
    el.appendChild(li);
  }
}

async function init() {
  const state = await getState();
  if (!state) return;
  document.getElementById("threshold").value = state.settings.threshold;
  document.getElementById("curDom").textContent = state.currentDomain || "n/a";
  renderList(document.getElementById("allowlist"), state.allowlist, "allow");
  renderList(document.getElementById("blocklist"), state.blocklist, "block");

  document.getElementById("allow").onclick = async () => {
    if (!state.currentDomain) return;
    await chrome.runtime.sendMessage({ type: "allowDomain", domain: state.currentDomain });
    init();
  };
  document.getElementById("block").onclick = async () => {
    if (!state.currentDomain) return;
    await chrome.runtime.sendMessage({ type: "blockDomain", domain: state.currentDomain });
    init();
  };
  document.getElementById("save").onclick = async () => {
    const v = Number(document.getElementById("threshold").value);
    if (Number.isFinite(v)) {
      await chrome.runtime.sendMessage({ type: "updateSettings", settings: { threshold: Math.max(0, Math.min(100, Math.round(v))) } });
    }
    init();
  };
}

init();
