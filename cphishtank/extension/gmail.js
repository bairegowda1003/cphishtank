// Gmail inline scanner (best effort: Gmail's markup changes, so selectors fail soft).
// Adds a "Check with CPhishTank" button above the open message and renders the verdict inline.
(function () {
  const BODY = ".a3s.aiL, .a3s";            // message body
  const SENDER = "span.gD[email]";          // sender span carries name + email attributes
  const SUBJECT = "h2.hP";

  function readOpenEmail(root) {
    const body = root.querySelector(BODY);
    if (!body) return null;
    const s = document.querySelector(SENDER);
    const sender = s ? `${s.getAttribute("name") || ""} <${s.getAttribute("email")}>`.trim() : null;
    const subject = document.querySelector(SUBJECT)?.innerText || null;
    // include real link targets, which are the part phishers disguise
    const links = [...body.querySelectorAll("a[href]")].map((a) => a.href).filter((h) => /^https?:/.test(h));
    const text = body.innerText + (links.length ? "\n\n" + links.join("\n") : "");
    return { text: text.slice(0, 19000), sender, subject, channel: "email" };
  }

  function render(box, r) {
    const cls = { legitimate: "ok", suspicious: "warn", phishing: "bad" }[r.label];
    const name = { legitimate: "Looks legitimate", suspicious: "Suspicious", phishing: "Likely phishing" }[r.label];
    box.className = `cpt-box cpt-${cls}`;
    box.innerHTML = "";
    const h = document.createElement("strong"); h.textContent = `${name} · risk ${Math.round(r.risk_score)}/100`;
    const p = document.createElement("p"); p.textContent = r.summary;
    const ul = document.createElement("ul");
    r.signals.slice(0, 4).forEach((s) => { const li = document.createElement("li"); li.textContent = s.title; ul.appendChild(li); });
    box.append(h, p, ul);
  }

  function inject() {
    document.querySelectorAll(BODY).forEach((bodyEl) => {
      const host = bodyEl.closest(".adn, .gs") || bodyEl.parentElement;
      if (!host || host.querySelector(".cpt-btn")) return;
      const btn = document.createElement("button"); btn.className = "cpt-btn"; btn.textContent = "Check with CPhishTank";
      const box = document.createElement("div"); box.className = "cpt-box"; box.hidden = true;
      btn.onclick = () => {
        const payload = readOpenEmail(host);
        if (!payload) return;
        btn.disabled = true; btn.textContent = "Checking…";
        chrome.runtime.sendMessage({ type: "scan", payload }, (resp) => {
          btn.disabled = false; btn.textContent = "Check again";
          box.hidden = false;
          if (resp?.ok) render(box, resp.result);
          else { box.className = "cpt-box cpt-warn"; box.textContent = "Couldn't reach CPhishTank: " + (resp?.error || "is the server running?"); }
        });
      };
      bodyEl.parentElement.insertBefore(box, bodyEl);
      bodyEl.parentElement.insertBefore(btn, box);
    });
  }
  new MutationObserver(inject).observe(document.body, { childList: true, subtree: true });
  inject();
})();
