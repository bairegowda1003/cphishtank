// Right-click any selected text -> "Check with CPhishTank". Shows the verdict as a badge + notification.
const DEFAULT_API = "http://localhost:8000";

async function apiBase() {
  const { apiUrl } = await chrome.storage.sync.get("apiUrl");
  return (apiUrl || DEFAULT_API).replace(/\/$/, "");
}

async function scan(payload) {
  const res = await fetch(`${await apiBase()}/api/scan`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ save: true, ...payload }),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `Server error ${res.status}`);
  return res.json();
}

chrome.runtime.onInstalled.addListener(() =>
  chrome.contextMenus.create({ id: "cpt-scan", title: "Check with CPhishTank", contexts: ["selection"] }));

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "cpt-scan" || !info.selectionText) return;
  try {
    const r = await scan({ text: info.selectionText, channel: "email" });
    const color = { legitimate: "#177E5A", suspicious: "#D9A400", phishing: "#C41E30" }[r.label];
    chrome.action.setBadgeBackgroundColor({ color, tabId: tab.id });
    chrome.action.setBadgeText({ text: String(Math.round(r.risk_score)), tabId: tab.id });
    await chrome.storage.session.set({ last: r });
    chrome.action.openPopup?.();
  } catch (e) {
    chrome.action.setBadgeText({ text: "!", tabId: tab.id });
  }
});

// content scripts / popup ask the worker to call the API (avoids page CORS issues)
chrome.runtime.onMessage.addListener((msg, _s, reply) => {
  if (msg?.type !== "scan") return;
  scan(msg.payload).then((r) => reply({ ok: true, result: r })).catch((e) => reply({ ok: false, error: e.message }));
  return true;
});
