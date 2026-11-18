const $ = (id) => document.getElementById(id);
const NAMES = { legitimate: "Looks legitimate", suspicious: "Suspicious", phishing: "Likely phishing" };
const CLS = { legitimate: "ok", suspicious: "warn", phishing: "bad" };

function show(r) {
  const out = $("out"); out.hidden = false; out.className = CLS[r.label]; out.textContent = "";
  const h = document.createElement("strong"); h.textContent = `${NAMES[r.label]} · risk ${Math.round(r.risk_score)}/100`;
  const p = document.createElement("p"); p.textContent = r.summary;
  const ul = document.createElement("ul");
  r.signals.slice(0, 5).forEach((s) => { const li = document.createElement("li"); li.textContent = s.title; ul.appendChild(li); });
  out.append(h, p, ul);
}
async function useSelection() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  try {
    const [{ result }] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: () => String(getSelection()) });
    if (result) $("text").value = result;
  } catch { /* chrome:// pages etc. */ }
}
$("sel").onclick = useSelection;
$("opt").onclick = (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); };
$("go").onclick = () => {
  const text = $("text").value.trim(); if (text.length < 3) return;
  $("go").disabled = true; $("go").textContent = "Checking…";
  chrome.runtime.sendMessage({ type: "scan", payload: { text, channel: "email" } }, (resp) => {
    $("go").disabled = false; $("go").textContent = "Check";
    if (resp?.ok) show(resp.result);
    else { const o = $("out"); o.hidden = false; o.className = "warn"; o.textContent = "Couldn't reach the server: " + (resp?.error || "is it running?"); }
  });
};
chrome.storage.session.get("last").then(({ last }) => { if (last) { show(last); chrome.storage.session.remove("last"); } else useSelection(); });
