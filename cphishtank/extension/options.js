const u = document.getElementById("u");
chrome.storage.sync.get("apiUrl").then(({ apiUrl }) => (u.value = apiUrl || "http://localhost:8000"));
document.getElementById("s").onclick = async () => {
  const url = u.value.trim().replace(/\/$/, "");
  try {
    const origin = new URL(url).origin + "/*";
    if (!url.startsWith("http://localhost") && !url.startsWith("http://127.0.0.1")) {
      const ok = await chrome.permissions.request({ origins: [origin] });
      if (!ok) { document.getElementById("m").textContent = "Permission denied."; return; }
    }
    await chrome.storage.sync.set({ apiUrl: url });
    document.getElementById("m").textContent = "Saved.";
  } catch { document.getElementById("m").textContent = "Enter a valid URL."; }
};
