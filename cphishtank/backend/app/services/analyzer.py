"""Orchestrates one scan: parse -> heuristics -> live URL checks -> ML -> fuse -> explain."""
from __future__ import annotations

import re
from email import policy
from email.parser import BytesParser

from . import heuristics as H
from . import ml
from .url_checker import live_signals, load_blocklist

HEADER_RE = re.compile(r"^(from|to|subject|reply-to|date|return-path):\s*(.*)$", re.I)
PRIORITY = {"credential": 0, "url_bad": 1, "urgency": 2, "money": 3, "url_warn": 4,
            "greeting": 5, "attachment": 6, "ml": 7}


def strip_html(html: str) -> str:
    html = re.sub(r"(?is)<(script|style).*?</\1>", " ", html)
    html = re.sub(r"(?i)<br\s*/?>|</p>|</div>", "\n", html)
    return re.sub(r"[ \t]+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


def parse_message(text: str, sender=None, subject=None):
    """Pull From/Subject/Reply-To out of pasted headers, leaving the body."""
    lines, reply_to, i = text.replace("\r\n", "\n").split("\n"), None, 0
    found = False
    while i < len(lines):
        m = HEADER_RE.match(lines[i].strip())
        if not m:
            if lines[i].strip() == "" and found:
                i += 1
            break
        found = True
        k, v = m.group(1).lower(), m.group(2).strip()
        if k == "from" and not sender:
            sender = v
        elif k == "subject" and not subject:
            subject = v
        elif k == "reply-to":
            reply_to = v
        i += 1
    body = "\n".join(lines[i:]).strip() if found else text.strip()
    return body or text.strip(), sender, subject, reply_to


def parse_eml(data: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(data)
    plain = msg.get_body(preferencelist=("plain",))
    html = msg.get_body(preferencelist=("html",))
    html_s = html.get_content() if html else ""
    text = plain.get_content() if plain else strip_html(html_s)
    return {"text": text, "html": html_s, "sender": str(msg.get("From") or "") or None,
            "subject": str(msg.get("Subject") or "") or None, "reply_to": str(msg.get("Reply-To") or "") or None,
            "attachments": [p.get_filename() for p in msg.iter_attachments() if p.get_filename()]}


def _merge_highlights(spans: list[dict]) -> list[dict]:
    spans = sorted(spans, key=lambda s: (PRIORITY[s["kind"]], s["start"]))
    kept: list[dict] = []
    for s in spans:
        if s["end"] <= s["start"]:
            continue
        if all(s["end"] <= k["start"] or s["start"] >= k["end"] for k in kept):
            kept.append(s)
    return sorted(kept, key=lambda s: s["start"])


def _advice(label: str, ids: set[str]) -> list[str]:
    tips = []
    if label != "legitimate":
        tips.append("Don't click links or open attachments in this message.")
    if ids & {"credential", "name_domain_mismatch", "freemail_brand", "sender_lookalike"}:
        tips.append("Never type a password, PIN or OTP after following a link from a message. "
                    "Open the company's official app or website yourself instead.")
    if ids & {"urgency"}:
        tips.append("Urgency is a pressure tactic. Real providers give you time and don't threaten instant closure.")
    if ids & {"shortener", "ip_host", "lookalike", "brand_misuse", "bad_tld", "anchor_mismatch"}:
        tips.append("Hover over (or long-press) links to see the real address before trusting them.")
    if ids & {"money", "attachment"}:
        tips.append("Unexpected prizes, refunds and invoices are common lures. Verify through a separate channel.")
    if label == "phishing":
        tips.append("Report it (e.g. forward to reportphishing@apwg.org, or use your email app's Report phishing option), then delete it.")
        tips.append("If you already entered details, change that password immediately and tell your bank or IT team.")
    if label == "legitimate":
        tips.append("No strong warning signs were found, but stay cautious. Verify anything that asks for money or credentials.")
    return tips


def analyze(text: str, sender: str | None = None, subject: str | None = None, channel: str = "email",
            html: str | None = None, reply_to: str | None = None, attachments: list[str] | None = None) -> dict:
    body, sender, subject, hdr_reply = parse_message(text, sender, subject)
    reply_to = reply_to or hdr_reply
    blocklist = load_blocklist()

    # --- heuristics
    url_items = H.extract_urls(body)
    if html:  # anchors hidden inside HTML count too
        for href, _ in H.ANCHOR_RE.findall(html):
            if href.lower().startswith("http") and href.lower() not in {u["url"].lower() for u in url_items}:
                url_items.append({"url": href, "start": -1, "end": -1})
    urls_out = []
    for u in url_items[:15]:
        res = H.analyze_url(u["url"], blocklist)
        extra, info = live_signals(u["url"], res["domain"]) if res["host"] else ([], {})
        res["signals"] += extra
        res["risk"] = H.noisy_or([s["points"] for s in res["signals"]])
        res.update(info=info, start=u["start"], end=u["end"])
        urls_out.append(res)

    signals = []
    signals += H.analyze_sender(sender, reply_to, channel, has_links=bool(urls_out))
    content_signals, phrase_hits = H.analyze_content(body, subject)
    signals += content_signals
    if html:
        signals += H.analyze_html_anchors(html)
    if attachments:
        risky = [a for a in attachments if re.search(r"(?i)\.(exe|scr|js|bat|jar|vbs|iso|html?|zip)$", a)]
        if risky:
            signals.append(H.sig("risky_attachment", "content", 24, "Risky attachment type",
                                 "Executable, script or archive attachments are a common malware route.", ", ".join(risky)))
    seen_url_sig = set()
    for u in urls_out:  # one entry per signal type, listing the hosts affected
        for s in u["signals"]:
            if s["id"] in seen_url_sig:
                continue
            seen_url_sig.add(s["id"])
            signals.append(dict(s))
    heur = H.noisy_or([s["points"] for s in signals])

    # --- ML
    model_text = f"{subject}\n{body}" if subject else body
    sender_domain = H.parse_sender(sender)["domain"]
    sender_registered = H.registered_domain(sender_domain) if sender_domain else ""
    sender_age = next((u["info"].get("domain_age_days") for u in urls_out
                       if u["domain"] == sender_registered and u["info"].get("domain_age_days") is not None), None)
    pred = ml.predict(model_text, sender=sender, html=html, attachments=attachments,
                      domain_age_days=sender_age)
    expl = ml.explain(f"{subject}\n{body}" if subject else body)

    # --- reassurance: only official brand links, nothing alarming. The language model was trained on
    # real mail that lacks modern legitimate notifications, so it over-flags them; halve its vote in this narrow case.
    ids = {s["id"] for s in signals}
    ALARMING = {"credential", "blocklist", "safe_browsing", "name_domain_mismatch", "freemail_brand", "sender_lookalike",
                "reply_to_mismatch", "anchor_mismatch", "lookalike", "brand_misuse", "ip_host", "punycode", "at_symbol",
                "risky_attachment", "risky_file", "urgency"}
    reassurance = []
    trusted = [u for u in urls_out if u["host"] and H.is_trusted_link(u["host"])]
    if urls_out and len(trusted) == len(urls_out) and not (ids & ALARMING):
        reassurance.append("All links go to official " + ", ".join(sorted({u["domain"] for u in trusted})) + " addresses.")
    sd = H.parse_sender(sender)["domain"]
    if sd and H.is_trusted_link(sd) and not (ids & ALARMING) and not reply_to:
        reassurance.append(f"Sender address is on {H.registered_domain(sd)}. Note: sender addresses can be forged, so this alone proves little.")

    # --- fuse
    scam_probability = pred.get("scam_probability", pred["risk"] / 100)
    final = ml.fuse(scam_probability, signals, heur) * 100
    if ids & {"blocklist", "safe_browsing"}:
        final = max(final, 92)
    final = round(min(final, 100), 1)
    safe_cutoff, scam_cutoff = ml.thresholds()
    label = "legitimate" if final < safe_cutoff else "suspicious" if final < scam_cutoff else "phishing"

    # --- highlights
    spans = [{"kind": h["kind"], "start": h["start"], "end": h["end"], "reason": h["label"]} for h in phrase_hits]
    for u in urls_out:
        if u["start"] >= 0 and u["signals"]:
            bad = u["risk"] >= 25
            spans.append({"kind": "url_bad" if bad else "url_warn", "start": u["start"], "end": u["end"],
                          "reason": u["signals"][0]["title"]})
    for t in expl["toward_phishing"][:6]:
        for s, e in ml.locate_term(t["term"], body):
            spans.append({"kind": "ml", "start": s, "end": e, "reason": "Wording typical of phishing messages"})
    highlights = _merge_highlights(spans)

    signals.sort(key=lambda s: -s["points"])
    top = [s["title"][0].lower() + s["title"][1:] for s in signals[:3]]
    if label == "legitimate":
        summary = "No strong phishing indicators were found in this message."
    else:
        summary = ("This message looks like " + ("a phishing attempt" if label == "phishing" else "suspicious or unwanted mail")
                   + (": " + "; ".join(top) + "." if top else "."))

    return {
        "label": label, "risk_score": final, "confidence": round(pred["confidence"], 3),
        "summary": summary, "channel": channel, "subject": subject, "text": body,
        "sender": H.parse_sender(sender), "reply_to": reply_to,
        "scores": {"ml_risk": pred["risk"], "heuristic_risk": heur, "ml_probs": {k: round(v, 3) for k, v in pred["probs"].items()},
                   "ml_label": pred["label"]},
        "reassurance": reassurance, "signals": signals, "urls": [{k: v for k, v in u.items() if k not in ("start", "end")} for u in urls_out],
        "highlights": highlights, "explanation": expl, "advice": _advice(label, ids),
    }
