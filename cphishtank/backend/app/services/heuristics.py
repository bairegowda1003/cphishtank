"""Rule-based phishing heuristics.

Every rule emits a *signal* (id, severity, points, title, detail, evidence) so the UI can
explain exactly why something was flagged. Points are treated as independent probabilities
and merged with a noisy-OR, which keeps the score bounded in [0, 100] and gives diminishing
returns when many weak signals pile up.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

# ------------------------------------------------------------------ constants
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amzn.to", "amzn.in"},
    "google": {"google.com", "gmail.com", "google.co.in", "youtube.com", "goo.gl", "googleapis.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com",
                  "office365.com", "sharepoint.com"},
    "apple": {"apple.com", "icloud.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "wa.me"},
    "linkedin": {"linkedin.com", "lnkd.in"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "irs": {"irs.gov"},
    "hdfc": {"hdfcbank.com", "hdfcbank.net", "hdfc.com", "hdfclife.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com"},
    "icici": {"icicibank.com", "icicidirect.com"},
    "axis": {"axisbank.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "flipkart": {"flipkart.com"},
    "uidai": {"uidai.gov.in"},
    "chase": {"chase.com", "jpmorgan.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "adobe": {"adobe.com"},
    "zoom": {"zoom.us"},
    "github": {"github.com"},
}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
              "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "bit.do", "lnkd.in", "s.id", "t.ly"}

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "link", "tk", "ml", "ga", "cf", "gq", "work",
                   "rest", "country", "support", "icu", "buzz", "cyou", "cam", "monster", "sbs",
                   "loan", "download", "review", "stream", "gdn", "bid", "men", "date", "party"}

FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "proton.me",
             "protonmail.com", "mail.com", "yandex.com", "rediffmail.com", "icloud.com"}

BAIT_WORDS = ("login", "signin", "sign-in", "verify", "secure", "account", "update", "banking",
              "wallet", "confirm", "password", "billing", "support", "helpdesk", "kyc")

SECOND_LEVEL = {"co", "com", "org", "gov", "ac", "net", "edu", "nic"}

URL_RE = re.compile(
    r"(?i)(?:\b(?:https?://|www\.)[^\s<>\"'\[\]]+|(?<![@\w./-])(?:[a-z0-9-]+\.)+"
    r"(?:com|net|org|info|biz|xyz|top|click|link|tk|ml|ga|cf|gq|ly|me|co|in|io|ru|cn|support|online|"
    r"site|live|shop|icu|buzz|zip|cc|ws|vip|club)\b(?:/[^\s<>\"'\[\]]*)?)")
ANCHOR_RE = re.compile(r"(?is)<a\s+[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>")
EMAIL_RE = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")

# (kind, regex, label)
PHRASES = [
    ("urgency", r"\bact (?:now|immediately|fast)\b", "Pressure to act immediately"),
    ("urgency", r"\burgent(?:ly)?\b", "Urgency language"),
    ("urgency", r"\bimmediate(?:ly)? (?:action|attention|response)\b", "Pressure to act immediately"),
    ("urgency", r"\bwithin \d+ ?(?:hours?|hrs?|minutes?|mins?|days?)\b", "Artificial deadline"),
    ("urgency", r"\b(?:final|last) (?:notice|warning|reminder|chance)\b", "Final-warning pressure"),
    ("urgency", r"\b(?:expires?|expiring) (?:today|soon|tonight|in \d+)", "Expiry pressure"),
    ("urgency", r"\b(?:account|card|access|wallet|number|sim)\b[^.\n]{0,25}\b(?:will be|has been|is|been) "
                r"(?:suspended|locked|closed|blocked|deactivated|disabled|limited|terminated)\b",
     "Threat of account suspension"),
    ("urgency", r"\bfailure to (?:comply|respond|verify|update)\b", "Threat of consequences"),
    ("urgency", r"\bunusual (?:activity|sign-?in|login|transaction)\b|\bsuspicious (?:activity|login|transaction)\b",
     "Alarming security claim"),
    ("credential", r"\b(?:confirm|update|verify|validate|enter|provide|share|submit|re-?enter)\b[^.\n]{0,30}"
                   r"\b(?:password|passcode|pin|otp|cvv|card (?:number|details)|ssn|social security|bank details|"
                   r"login (?:details|credentials)|credentials|aadhaar|pan (?:card|number))\b",
     "Asks for credentials or sensitive data"),
    ("credential", r"\bverify (?:your|ur) (?:account|identity|information|details|email)\b",
     "Asks you to verify your account"),
    ("credential", r"\bkyc\b[^.\n]{0,30}\b(?:update|expired?|pending|incomplete|verify)\b|"
                   r"\b(?:update|complete) (?:your )?kyc\b", "KYC-update bait"),
    ("credential", r"\b(?:click|tap) (?:here|the link|below)\b[^.\n]{0,40}\b(?:login|sign in|verify|confirm|"
                   r"update|secure)\b", "Click-to-login bait"),
    ("money", r"\byou(?:'ve| have)? (?:won|been selected)\b", "Unexpected prize claim"),
    ("money", r"\b(?:lottery|jackpot|sweepstakes?)\b", "Lottery / prize bait"),
    ("money", r"\bclaim (?:your )?(?:reward|prize|refund|gift|cashback|bonus)\b", "Reward claim bait"),
    ("money", r"\b(?:gift cards?|bitcoin|crypto(?:currency)?|wire transfer|western union)\b",
     "Untraceable payment method"),
    ("money", r"\binheritance\b|\bunclaimed (?:funds?|money|package)\b", "Unexpected money offer"),
    ("greeting", r"\bdear (?:customer|user|client|member|sir|madam|sir/madam|account holder|valued customer)\b",
     "Generic greeting"),
    ("attachment", r"\b(?:open|see|view|download) (?:the )?attached (?:invoice|document|file|statement|form)\b|"
                   r"\battached (?:invoice|statement|document)\b", "Pushes you to open an attachment"),
]
PHRASES = [(k, re.compile(p, re.I), l) for k, p, l in PHRASES]

POINTS = {"urgency": 14, "credential": 24, "money": 16, "greeting": 6, "attachment": 10}
SEV = lambda p: "high" if p >= 20 else "medium" if p >= 10 else "low"  # noqa: E731


# ------------------------------------------------------------------ helpers
def noisy_or(points: list[float]) -> float:
    """Combine independent evidence (points are percentages) into 0-100."""
    q = 1.0
    for p in points:
        q *= 1 - min(max(p, 0), 99) / 100
    return round((1 - q) * 100, 1)


BRAND_DISPLAY = {"paypal": "PayPal", "hdfc": "HDFC Bank", "sbi": "SBI", "icici": "ICICI Bank", "axis": "Axis Bank",
                 "linkedin": "LinkedIn", "whatsapp": "WhatsApp", "phonepe": "PhonePe", "docusign": "DocuSign",
                 "github": "GitHub", "uidai": "UIDAI", "irs": "IRS", "dhl": "DHL", "usps": "USPS", "fedex": "FedEx",
                 "wellsfargo": "Wells Fargo", "bankofamerica": "Bank of America", "chase": "Chase"}


def disp(brand: str) -> str:
    return BRAND_DISPLAY.get(brand, brand.title())


def sig(id_, category, points, title, detail, evidence=None):
    return {"id": id_, "category": category, "severity": SEV(points), "points": points,
            "title": title, "detail": detail, "evidence": evidence}


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a", "4": "a", "7": "t"})


def registered_domain(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_official(reg_domain: str, brand: str) -> bool:
    return any(reg_domain == d or reg_domain.endswith("." + d) for d in BRANDS[brand])


def is_known_official(reg_domain: str) -> bool:
    return any(is_official(reg_domain, b) for b in BRANDS)


# Hosts on official brand domains where *anyone* can publish content; never treated as reassuring.
USER_CONTENT_HOSTS = {"docs.google.com", "drive.google.com", "sites.google.com", "forms.gle", "script.google.com",
                      "storage.googleapis.com", "googleapis.com", "sharepoint.com", "onedrive.live.com", "1drv.ms",
                      "dropbox.com", "dropboxusercontent.com", "github.io", "githubusercontent.com", "amazonaws.com",
                      "goo.gl", "youtube.com", "wa.me", "office.com"}


def is_trusted_link(host: str) -> bool:
    """True only for official brand domains that are not open publishing platforms."""
    reg = registered_domain(host)
    if not is_known_official(reg):
        return False
    return not any(host == h or host.endswith("." + h) for h in USER_CONTENT_HOSTS)


def brand_impersonation(host: str):
    """Return (brand, kind) if the host imitates a brand it doesn't belong to."""
    host = host.lower()
    reg = registered_domain(host)
    labels = re.split(r"[.\-]", host)
    reg_label = reg.split(".")[0]
    for brand in BRANDS:
        if is_official(reg, brand):
            continue
        for tok in labels:
            if not tok:
                continue
            if tok == brand or (len(brand) >= 5 and brand in tok):
                return brand, "contains"
        for tok in {reg_label, *re.split(r"-", reg_label)}:
            norm = tok.translate(LEET).replace("rn", "m").replace("vv", "w")
            if tok != brand and len(brand) >= 4 and (norm == brand or (
                    len(brand) >= 5 and len(tok) >= 5 and levenshtein(tok, brand) == 1)):
                return brand, "lookalike"
    return None


def extract_urls(text: str) -> list[dict]:
    seen, out = set(), []
    for m in URL_RE.finditer(text or ""):
        raw = m.group(0).rstrip(".,;:!?)\"'")
        if raw.lower() in seen:
            continue
        seen.add(raw.lower())
        out.append({"url": raw, "start": m.start(), "end": m.start() + len(raw)})
    return out


def parse_host(url: str) -> tuple[str, str]:
    full = url if re.match(r"(?i)^https?://", url) else "http://" + url
    p = urlparse(full)
    return (p.hostname or "").lower(), full


# ------------------------------------------------------------------ URL analysis
def analyze_url(url: str, blocklist: set[str] | None = None) -> dict:
    host, full = parse_host(url)
    reg = registered_domain(host)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    scheme_explicit = bool(re.match(r"(?i)^https?://", url))
    signals = []

    if blocklist and (host in blocklist or reg in blocklist):
        signals.append(sig("blocklist", "url", 92, "Listed in phishing blocklist",
                           f"{reg} appears in the local phishing blocklist.", host))
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) or re.fullmatch(r"0x[0-9a-f]+|\d{8,10}", host):
        signals.append(sig("ip_host", "url", 24, "Link uses a raw IP address",
                           "Legitimate services use domain names, not numeric addresses.", host))
    if reg in SHORTENERS or host in SHORTENERS:
        signals.append(sig("shortener", "url", 12, "Shortened link hides the real destination",
                           "URL shorteners let attackers disguise where a link goes.", host))
    if "xn--" in host:
        signals.append(sig("punycode", "url", 20, "Look-alike (punycode) domain",
                           "The domain uses international characters that can imitate real brands.", host))
    if "@" in urlparse(full).netloc:
        signals.append(sig("at_symbol", "url", 18, "Link contains an @ symbol",
                           "Text before @ is ignored by browsers and often used to fake a trusted name.", url))
    if tld in SUSPICIOUS_TLDS:
        signals.append(sig("bad_tld", "url", 12, f"Uncommon domain ending (.{tld})",
                           f".{tld} domains are cheap and heavily abused for phishing.", host))
    if host.count(".") >= 4:
        signals.append(sig("subdomains", "url", 10, "Unusually many subdomains",
                           "Long subdomain chains are used to bury the real domain.", host))
    if host.count("-") >= 3:
        signals.append(sig("hyphens", "url", 8, "Many hyphens in domain",
                           "Domains stuffed with hyphens often imitate official pages.", host))
    imp = brand_impersonation(host) if not re.fullmatch(r"[\d.]+", host) else None
    if imp:
        brand, kind = imp
        if kind == "lookalike":
            signals.append(sig("lookalike", "url", 26, f"Look-alike of {disp(brand)}",
                               f"{reg} imitates {brand} using swapped or replaced characters.", host))
        else:
            signals.append(sig("brand_misuse", "url", 24, f"Uses the {disp(brand)} name on an unrelated site",
                               f"{reg} is not an official {disp(brand)} domain.", host))
    elif any(w in host for w in BAIT_WORDS) and reg not in SHORTENERS and not is_known_official(reg):
        signals.append(sig("bait_words", "url", 8, "Account-related words in domain",
                           "Words like 'login' or 'verify' in a domain are a common phishing pattern.", host))
    if scheme_explicit and full.lower().startswith("http://"):
        signals.append(sig("no_https", "url", 6, "Link is not encrypted (http)",
                           "Real login pages use https.", url))
    if len(url) > 110:
        signals.append(sig("long_url", "url", 4, "Very long link",
                           "Long URLs can hide misleading parts.", url[:60] + "…"))
    if re.search(r"(?i)\.(exe|scr|zip|apk|bat|js|jar)(\?|$)", urlparse(full).path):
        signals.append(sig("risky_file", "url", 20, "Link downloads an executable or archive",
                           "Direct downloads of programs are a common malware route.", url))

    return {"url": url, "host": host, "domain": reg,
            "risk": noisy_or([s["points"] for s in signals]), "signals": signals}


# ------------------------------------------------------------------ sender analysis
def parse_sender(sender: str | None) -> dict:
    if not sender:
        return {"raw": None, "name": "", "address": "", "domain": ""}
    m = re.match(r"\s*\"?([^\"<]*)\"?\s*<([^>]+)>", sender)
    name, addr = (m.group(1).strip(), m.group(2).strip()) if m else ("", sender.strip())
    domain = addr.split("@", 1)[1].lower() if "@" in addr else ""
    return {"raw": sender, "name": name, "address": addr, "domain": domain}


def analyze_sender(sender: str | None, reply_to: str | None = None, channel: str = "email",
                   has_links: bool = False) -> list[dict]:
    info = parse_sender(sender)
    signals = []
    if channel == "sms":
        raw = (sender or "").strip()
        digits = re.sub(r"\D", "", raw)
        if raw and len(digits) >= 10 and has_links:
            signals.append(sig("sms_number", "sender", 8, "Link sent from an ordinary phone number",
                               "Banks and delivery firms normally use registered sender names, not personal numbers.", raw))
        return signals
    if not info["domain"]:
        return signals
    dom, reg = info["domain"], registered_domain(info["domain"])
    name_l = info["name"].lower()
    claimed = next((b for b in BRANDS if b in name_l.replace(" ", "")), None)
    if claimed and not is_official(reg, claimed):
        if dom in FREE_MAIL:
            signals.append(sig("freemail_brand", "sender", 26, f"Claims to be {disp(claimed)} but uses a free mailbox",
                               f"Sender name says {disp(claimed)}, but the address is {info['address']}.", info["address"]))
        else:
            signals.append(sig("name_domain_mismatch", "sender", 28, f"Sender name says {disp(claimed)}, domain does not match",
                               f"The address uses {reg}, which is not an official {disp(claimed)} domain.", info["address"]))
    else:
        imp = brand_impersonation(dom)
        if imp:
            kind = "Look-alike of" if imp[1] == "lookalike" else "Uses the name of"
            signals.append(sig("sender_lookalike", "sender", 28, f"Sender domain: {kind} {disp(imp[0])}",
                               f"{reg} is not an official {disp(imp[0])} domain.", info["address"]))
    if reg.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        signals.append(sig("sender_tld", "sender", 10, "Sender uses an uncommon domain ending",
                           f"{reg} ends in a TLD frequently abused for spam.", info["address"]))
    if reply_to:
        r = parse_sender(reply_to)
        if r["domain"] and registered_domain(r["domain"]) != reg:
            signals.append(sig("reply_to_mismatch", "sender", 16, "Reply-To goes to a different domain",
                               f"Replies would go to {r['address']} instead of {info['address']}.", r["address"]))
    return signals


# ------------------------------------------------------------------ content analysis
NEGATION = re.compile(r"(?:do not|don't|dont|never|not|won't|will not)\s+(?:\w+\s+){0,2}$", re.I)


def find_phrase_hits(text: str) -> list[dict]:
    hits = []
    for kind, rx, label in PHRASES:
        for m in rx.finditer(text):
            # "Do not share your OTP" is a warning, not a request
            if kind == "credential" and NEGATION.search(text[max(0, m.start() - 24):m.start()]):
                continue
            hits.append({"kind": kind, "label": label, "start": m.start(), "end": m.end(),
                         "text": m.group(0)})
    return hits


def analyze_content(text: str, subject: str | None = None) -> tuple[list[dict], list[dict]]:
    body = f"{subject}\n{text}" if subject else text
    hits = find_phrase_hits(text) + (
        [dict(h, start=-1, end=-1) for h in find_phrase_hits(subject)] if subject else [])
    signals = []
    by_kind: dict[str, list[dict]] = {}
    for h in hits:
        by_kind.setdefault(h["kind"], []).append(h)
    titles = {"urgency": ("Urgency or threat language", "Scammers pressure you to act before you think."),
              "credential": ("Asks for passwords or sensitive details", "Legitimate companies don't ask for these by email or SMS."),
              "money": ("Money, prize or reward bait", "Unexpected rewards and payment requests are classic lures."),
              "greeting": ("Generic greeting", "Real providers usually address you by name."),
              "attachment": ("Pushes you to open an attachment", "Unexpected attachments can carry malware or fake login pages.")}
    for kind, items in by_kind.items():
        pts = POINTS[kind] + min(len(items) - 1, 3) * (4 if kind in ("urgency", "credential") else 2)
        ev = "; ".join(sorted({i["text"].strip() for i in items}))[:160]
        signals.append(sig(kind, "content", pts, titles[kind][0], titles[kind][1], ev))
    letters = [c for c in body if c.isalpha()]
    if len(letters) > 30 and sum(c.isupper() for c in letters) / len(letters) > 0.45:
        signals.append(sig("shouting", "content", 5, "Excessive capital letters", "Shouting text is used to create alarm.", None))
    if body.count("!") >= 3:
        signals.append(sig("exclaim", "content", 4, "Many exclamation marks", "Overly excited punctuation is common in scams.", None))
    return signals, [h for h in hits if h["start"] >= 0]


def analyze_html_anchors(html: str) -> list[dict]:
    signals = []
    for href, label in ANCHOR_RE.findall(html or ""):
        label_txt = re.sub(r"<[^>]+>", "", label).strip()
        m = URL_RE.search(label_txt)
        if not m:
            continue
        shown, _ = parse_host(m.group(0))
        real, _ = parse_host(href)
        if shown and real and registered_domain(shown) != registered_domain(real):
            signals.append(sig("anchor_mismatch", "url", 30, "Link text shows one site but goes to another",
                               f"The link says {shown} but actually leads to {real}.", href))
    return signals
