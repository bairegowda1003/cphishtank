"""Collect real phishing / spam / legitimate messages from public sources.

    python -m pipeline.collect            # everything reachable
    python -m pipeline.collect --only smishtank uci_sms

Downloads are cached in data/downloads/ (git-ignored). Each source is converted to a simple
CSV in data/collected/ with columns:  text, label_raw, channel, source, date
(nothing is cleaned here; see pipeline/clean.py).
"""
from __future__ import annotations

import argparse
import csv
import html
import io
import json
import re
import sys
import tarfile
import zipfile
from email import message_from_string, policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path

import httpx

BASE = Path(__file__).resolve().parent.parent
DL, OUT, FEEDS = BASE / "data" / "downloads", BASE / "data" / "collected", BASE / "data" / "feeds"
UA = {"User-Agent": "CPhishTank-research-collector/1.0"}

URLS = {
    "phishing_pot": "https://codeload.github.com/rf-peixoto/phishing_pot/zip/refs/heads/main",   # ~1 GB
    "smishing_mirror": "https://codeload.github.com/Joshoneill6649/smishing-nlp-josh-oneill/zip/refs/heads/main",
    "uci_sms": "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv",
    "phishing_domains": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    "spamassassin_npm": "https://registry.npmjs.org/@stdlib/datasets-spam-assassin/latest",
}
COLS = ["text", "label_raw", "channel", "source", "date"]


# ----------------------------------------------------------------------------- helpers
def download(key: str, name: str, url: str | None = None) -> Path:
    DL.mkdir(parents=True, exist_ok=True)
    dest = DL / name
    if dest.exists() and dest.stat().st_size > 0:
        print(f"  cached: {dest.name} ({dest.stat().st_size / 1e6:.1f} MB)")
        return dest
    url = url or URLS[key]
    print(f"  downloading {url}")
    tmp = dest.with_suffix(dest.suffix + ".part")
    with httpx.stream("GET", url, follow_redirects=True, timeout=600, headers=UA) as r:
        r.raise_for_status()
        with open(tmp, "wb") as f:
            for chunk in r.iter_bytes(1 << 20):
                f.write(chunk)
    tmp.rename(dest)
    return dest


class _Html2Text(HTMLParser):
    """Minimal HTML -> text that also records link targets."""
    BLOCK = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "table", "blockquote"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.links, self._skip = [], [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head"):
            self._skip += 1
        if tag == "a":
            href = dict(attrs).get("href", "")
            if href.lower().startswith(("http://", "https://")):
                self.links.append(href)
        if tag in self.BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head"):
            self._skip = max(0, self._skip - 1)
        if tag in self.BLOCK:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def html_to_text(src: str) -> tuple[str, list[str]]:
    p = _Html2Text()
    try:
        p.feed(src)
        p.close()
    except Exception:
        return re.sub(r"<[^>]+>", " ", src), []
    return "".join(p.parts), p.links


def _part_text(part) -> str:
    try:
        return part.get_content()
    except Exception:  # unknown charset etc.
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", "ignore")


def extract_message(msg) -> dict | None:
    """Subject + best text body (+ real link targets) from an email.message.EmailMessage."""
    plain, htm = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_filename():
            continue
        ct = part.get_content_type()
        if ct == "text/plain":
            plain.append(_part_text(part))
        elif ct == "text/html":
            htm.append(_part_text(part))
    links: list[str] = []
    htm_text = ""
    if htm:
        htm_text, links = html_to_text("\n".join(htm))
    body = "\n".join(plain).strip()
    if len(body) < 20:  # html-only (or empty text part)
        body = htm_text.strip()
    subject = str(msg.get("Subject") or "").strip()
    shown = set(re.findall(r"https?://[^\s<>\"']+", body))
    extra = [l for l in dict.fromkeys(links) if l not in shown][:5]
    text = (subject + "\n\n" if subject else "") + body + ("\n\n" + "\n".join(extra) if extra else "")
    date = ""
    try:
        date = parsedate_to_datetime(str(msg.get("Date"))).strftime("%Y-%m-%d")
    except Exception:
        pass
    return {"text": text, "date": date}


def write_csv(name: str, rows: list[dict]):
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"{name}.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        w.writerows(rows)
    print(f"  -> {path.relative_to(BASE)}: {len(rows)} rows")


# ----------------------------------------------------------------------------- sources
def phishing_pot():
    z = zipfile.ZipFile(download("phishing_pot", "phishing_pot.zip"))
    rows, bad = [], 0
    for n in z.namelist():
        if not n.endswith(".eml") or "/email/" not in n:
            continue
        try:
            r = extract_message(BytesParser(policy=policy.default).parsebytes(z.read(n)))
        except Exception:
            bad += 1
            continue
        rows.append({**r, "label_raw": "phishing", "channel": "email", "source": "phishing_pot"})
    print(f"  parse failures: {bad}")
    write_csv("phishing_pot", rows)


def spamassassin():
    info = httpx.get(URLS["spamassassin_npm"], timeout=60, headers=UA).json()
    tgz = download("spamassassin_npm", "spamassassin.tgz", info["dist"]["tarball"])
    rows = []
    with tarfile.open(tgz) as t:
        for m in t.getmembers():
            mm = re.search(r"/data/(easy-ham-1|easy-ham-2|hard-ham-1|spam-1|spam-2)/[^/]+\.txt$", m.name)
            if not mm:
                continue
            group = mm.group(1)
            raw = t.extractfile(m).read().decode("utf-8", "ignore")
            msg = message_from_string(raw, policy=policy.default)
            try:
                r = extract_message(msg)
            except Exception:
                continue
            rows.append({**r, "label_raw": "spam" if group.startswith("spam") else "ham", "channel": "email",
                         "source": f"spamassassin_{group}"})
    write_csv("spamassassin", rows)


def uci_sms():
    p = download("uci_sms", "uci_sms.tsv")
    rows = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "\t" in line:
            lab, txt = line.split("\t", 1)
            rows.append({"text": txt, "label_raw": lab.strip(), "channel": "sms", "source": "uci_sms", "date": "2012"})
    write_csv("uci_sms", rows)


def smishing_mirror():
    """Smishtank (real reported smishing), SpamDam (labels unreliable) and NUS SMS corpus (real ham)."""
    import pandas as pd
    z = zipfile.ZipFile(download("smishing_mirror", "smishing_mirror.zip"))
    root = next(n for n in z.namelist() if n.endswith("data/raw/smishtank.csv")).rsplit("smishtank.csv", 1)[0]
    st = pd.read_csv(io.BytesIO(z.read(root + "smishtank.csv")))
    write_csv("smishtank", [{"text": t, "label_raw": "smish", "channel": "sms", "source": "smishtank", "date": ""} for t in st["text"].astype(str)])
    sd = pd.read_csv(io.BytesIO(z.read(root + "spamdam.csv")))
    write_csv("spamdam", [{"text": t, "label_raw": "unverified_smish_or_spam", "channel": "sms", "source": "spamdam", "date": ""} for t in sd["text"].astype(str)])
    nus = json.loads(z.read(root + "NUS_SMS_Corpus.json"))["smsCorpus"]["message"]
    rows = []
    for m in nus:
        if (m.get("messageProfile") or {}).get("@language") != "en":
            continue
        txt = ((m.get("text") or {}).get("$")) or ""
        if isinstance(txt, str) and txt.strip():
            rows.append({"text": txt, "label_raw": "ham", "channel": "sms", "source": "nus_sms", "date": ""})
    write_csv("nus_sms", rows)


def phishing_domains():
    """Live feed (Phishing.Database, refreshed daily upstream) -> blocklist used by the URL checker."""
    DL.mkdir(parents=True, exist_ok=True)
    dest = DL / "phishing_domains_active.txt"
    if "--refresh" in sys.argv and dest.exists():
        dest.unlink()
    p = download("phishing_domains", dest.name)
    FEEDS.mkdir(parents=True, exist_ok=True)
    domains = {l.strip().lower() for l in p.read_text(errors="ignore").splitlines() if l.strip() and not l.startswith("#")}
    domains = {d for d in domains if re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", d)}
    out = FEEDS / "phishing_domains.txt"
    out.write_text("# Source: github.com/mitchellkrogza/Phishing.Database (phishing-domains-ACTIVE)\n" + "\n".join(sorted(domains)) + "\n")
    print(f"  -> {out.relative_to(BASE)}: {len(domains)} domains")


SOURCES = {"phishing_pot": phishing_pot, "spamassassin": spamassassin, "uci_sms": uci_sms,
           "smishing_mirror": smishing_mirror, "phishing_domains": phishing_domains}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*", choices=SOURCES)
    ap.add_argument("--refresh", action="store_true", help="re-download the live domain feed")
    args = ap.parse_args()
    for name in args.only or SOURCES:
        print(f"[{name}]")
        try:
            SOURCES[name]()
        except Exception as e:
            print(f"  FAILED: {type(e).__name__}: {e}")
