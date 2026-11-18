"""Clean the collected raw data into one training-ready dataset.

    python -m pipeline.clean

Steps (every removal is counted per source and written to data/clean/report.md):
  1. text normalisation   Unicode NFKC, HTML entities, zero-width/control chars, whitespace
  2. artifact removal     honeypot recipients, mailing-list footers, quoted replies, signatures,
                          subject prefixes ("Re:", "[list-tag]"), long random/base64 tokens, tracking-URL tails
  3. PII masking          e-mail addresses -> user@example.com, long phone numbers -> 000-000-0000
  4. length filter        too short / mostly non-text
  5. English filter       stop-word language ID (the model is English-only)
  6. de-duplication       exact (normalised) + near-duplicate (MinHash, Jaccard >= 0.8)
  7. label-conflict drop  near-identical texts that carry different labels are removed
  8. balancing            very large sources are down-sampled with a fixed seed
"""
from __future__ import annotations

import csv
import hashlib
import html
import json
import random
import re
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path

from datasketch import MinHash, MinHashLSH

BASE = Path(__file__).resolve().parent.parent
COLLECTED, CLEAN, RAW_DROPIN = BASE / "data" / "collected", BASE / "data" / "clean", BASE / "data" / "raw"
csv.field_size_limit(10 ** 9)
SEED = 13
TODAY = __import__("datetime").date.today().isoformat()
MAX_CHARS = {"email": 3000, "sms": 1000}
MIN_CHARS = {"email": 40, "sms": 12}
# max rows kept per source after cleaning (None = all); keeps big sources from dominating
CAPS = {"nus_sms": 5000, "phishing_pot": None, "synthetic_legit": 700, "synthetic_bec": 120,
        "user_labeled": 5000}

# source -> (label mapping from label_raw, role)
LABELS = {
    "phishing_pot": {"phishing": "phishing"},
    "smishtank": {"smish": "phishing"},
    "spamassassin": {"ham": "legitimate", "spam": "suspicious"},
    "uci_sms": {"ham": "legitimate", "spam": "suspicious"},
    "nus_sms": {"ham": "legitimate"},
}
EXTERNAL = {"spamdam"}  # labels unverified -> used only as an external recall check, never for training

# ---------------------------------------------------------------- language id (stop-word based)
_W = lambda s: set(s.split())  # noqa: E731
STOP = {
    "en": _W("the and to of in is you that it for on with as are this be at or have not your from by we will can if all our "
             "but an was has my me i please would there their they what which who when been were do does did about more "
             "so just get its us one out up"),
    "pt": _W("de que e o a do da em um para com não uma os no se na por mais as dos como mas foi ao ele das tem seu sua ou "
             "você está nos já pelo pela são muito também sobre"),
    "de": _W("der die und in den von zu das mit sich des auf für ist im dem nicht ein eine als auch es an werden aus er hat "
             "dass sie nach wird bei einer um am sind noch wie einem über einen so zum war haben nur oder aber vor zur bis "
             "mehr durch man sein ihr ihre ihnen jetzt"),
    "es": _W("de la que el en y los del se las por un para con no una su al lo como más pero sus le ya o este sí porque esta "
             "entre cuando muy sin sobre también me hasta hay donde desde todo nos todos usted"),
    "fr": _W("le la les de des du un une et en est que qui dans pour pas sur au avec ce il elle ne se vous nous votre vos "
             "ou par plus mais sont être cette ces leur son sa ses tout comme aux"),
    "it": _W("di e il la che in un per è con non una le si da del della dei al come più ma sono gli nel alla suo sua anche "
             "lo ha questo tutto"),
    "nl": _W("de het een en van in is dat op te voor met zijn niet aan er ook als maar om bij uw je u naar wordt door nog "
             "dit die worden"),
    "id": _W("yang dan di untuk dengan ini dari anda akan pada adalah atau ke dalam tidak itu juga kami saya telah sudah"),
}
_ALL_OTHER = set().union(*(v for k, v in STOP.items() if k != "en"))
EN_ONLY = STOP["en"] - _ALL_OTHER
_FOREIGN = {k: v - STOP["en"] for k, v in STOP.items() if k != "en"}
WORD = re.compile(r"[^\W\d_]+", re.UNICODE)


def is_english(text: str) -> bool:
    letters = [c for c in text if c.isalpha()]
    if len(letters) < 8:
        return False
    if sum(c.isascii() for c in letters) / len(letters) < 0.93:
        return False
    words = [w.lower() for w in WORD.findall(text)]
    if not words:
        return False
    en = sum(w in EN_ONLY for w in words)
    foreign = max(sum(w in v for w in words) for v in _FOREIGN.values())
    if len(words) < 6:
        return foreign == 0
    return en / len(words) >= 0.04 and en > foreign


# ---------------------------------------------------------------- text cleaning
ZERO_WIDTH = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e]")
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
URL = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
HONEYPOT = re.compile(r"\b(?:phishing@pot|zzzz@localhost|jm@netnoteinc\.com)\b", re.I)
PHONE = re.compile(r"(?<![\w/.-])(?:\+?\d[\d\s().-]{8,}\d)(?![\w/.-])")
LONG_NUMBER = re.compile(r"(?<!\d)\d{6,}(?!\d)")
LONG_TOKEN = re.compile(r"(?<![\w/])(?=[A-Za-z0-9+/_=-]*\d)(?=[A-Za-z0-9+/_=-]*[A-Za-z])[A-Za-z0-9+/_=-]{28,}(?![\w/])")
QP = re.compile(r"=\r?\n|=[0-9A-F]{2}")
# mailing-list / corpus-specific boilerplate (would let the model identify the *source* instead of the label)
BOILER = re.compile(
    r"^\s*(?:_{8,}|-{8,}|={8,}|\*{8,})\s*$|mailing list|listinfo|lists?\.sourceforge|spamassassin|taint\.org|"
    r"razor-users|exmh-|ilug|spambayes|redhat\.com/mailman|to unsubscribe from this list|"
    r"^\s*(?:sent|posted) (?:from|via) |^\s*(?:from|to|cc|date|sent|subject):\s.*$|^\s*>|^\s*on .{5,80} wrote:\s*$|"
    r"^\s*-{2,}\s*original message|^\s*begin pgp|^\s*-{3,}begin|\bwrote:\s*$|^\s*in (?:message|article|a message) .{0,120}(?:said|wrote):?\s*$", re.I)
SANITIZER = re.compile(r"deathtospam\w*", re.I)       # SpamAssassin corpus sanitizer signature
SUBJ_PREFIX = re.compile(r"^\s*(?:(?:re|fwd?|aw|sv)\s*:\s*|\[[^\]]{1,40}\]\s*)+", re.I)


def _shorten_url(m: re.Match) -> str:
    u = m.group(0).rstrip(".,;:!?")
    return u if len(u) <= 200 else u[:200]


def clean_text(text: str, channel: str) -> str:
    t = unicodedata.normalize("NFKC", html.unescape(str(text)))
    t = ZERO_WIDTH.sub("", t)
    t = CONTROL.sub(" ", t)
    t = t.replace("\r\n", "\n").replace("\r", "\n").replace("\xa0", " ")
    t = HONEYPOT.sub("user@example.com", t)
    if channel == "email":
        t = t[:60000]                                  # hash-busting padding can be megabytes
        t = QP.sub(lambda m: "" if m.group(0).startswith("=\n") else " ", t)
        lines = t.split("\n")
        if lines:
            lines[0] = SUBJ_PREFIX.sub("", lines[0])
        t = "\n".join(lines)
        t = re.split(r"\n-- ?\n", t, maxsplit=1)[0]    # signature delimiter
        t = "\n".join(l for i, l in enumerate(t.split("\n")) if i == 0 or not BOILER.search(l))
    t = SANITIZER.sub(" ", t)
    t = URL.sub(_shorten_url, t)
    t = LONG_TOKEN.sub(lambda m: m.group(0) if m.group(0).lower().startswith("http") else " ", t) if channel == "email" else t
    t = EMAIL.sub("user@example.com", t)
    t = PHONE.sub("000-000-0000", t)
    t = LONG_NUMBER.sub("000000", t)
    t = re.sub(r"[ \t]+", " ", t)                       # collapse spaces
    t = re.sub(r"(?: ?\n){3,}", "\n\n", t)              # collapse blank lines
    t = "\n".join(l.strip() for l in t.split("\n")).strip()
    if len(t) > MAX_CHARS[channel]:
        t = t[:MAX_CHARS[channel]].rsplit(None, 1)[0]
    return t


def ascii_fold(t: str) -> str:
    """Strip accents / emoji / symbols so character set cannot reveal the source or era."""
    t = unicodedata.normalize("NFKD", t).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[ \t]+", " ", re.sub(r"(?: ?\n){3,}", "\n\n", t)).strip()


def norm_key(t: str) -> str:
    t = URL.sub(" u ", t.lower())
    t = re.sub(r"\d+", "0", t)
    return re.sub(r"\W+", " ", t).strip()


def minhash(t: str, k: int = 3, perm: int = 64) -> MinHash:
    w = norm_key(t).split()
    m = MinHash(num_perm=perm)
    for s in {" ".join(w[i:i + k]) for i in range(max(1, len(w) - k + 1))}:
        m.update(s.encode())
    return m


# ---------------------------------------------------------------- pipeline
def read_sources():
    for name, mapping in {**LABELS, **{e: {} for e in EXTERNAL}}.items():
        p = COLLECTED / f"{name}.csv"
        if not p.exists():
            print(f"  (missing {p.name}; run `python -m pipeline.collect`)")
            continue
        with open(p, encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                yield name, r
    user_labeled = CLEAN / "user_labeled.csv"
    if user_labeled.exists():
        with open(user_labeled, encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                if r.get("text") and r.get("label") and r.get("channel") in MAX_CHARS:
                    yield "dropin_user_labeled", {
                        "text": r["text"], "label_raw": r["label"].lower(), "channel": r["channel"],
                        "date": r.get("date", ""), "source": "user_labeled",
                    }
    # user drop-in CSVs (text,label) in data/raw/
    for p in RAW_DROPIN.glob("*.csv"):
        with open(p, encoding="utf-8", errors="ignore", newline="") as f:
            for r in csv.DictReader(f):
                if r.get("text") and r.get("label"):
                    yield f"dropin_{p.stem}", {"text": r["text"], "label_raw": r["label"].lower(), "channel": r.get("channel", "email"),
                                              "date": "", "source": f"dropin_{p.stem}"}


def run():
    random.seed(SEED)
    CLEAN.mkdir(parents=True, exist_ok=True)
    funnel: dict[str, Counter] = defaultdict(Counter)
    kept: list[dict] = []
    external: list[dict] = []
    DROPIN_MAP = {"ham": "legitimate", "safe": "legitimate", "legit": "legitimate", "legitimate": "legitimate",
                  "scam": "phishing", "spam": "suspicious",
                  "suspicious": "suspicious", "phishing": "phishing", "smish": "phishing"}

    for src, r in read_sources():
        sub = r.get("source", src)
        key = "spamassassin" if sub.startswith("spamassassin") else sub
        funnel[key]["raw"] += 1
        ch = r["channel"] if r["channel"] in MAX_CHARS else "email"
        label = LABELS.get(src, {}).get(r["label_raw"]) or (DROPIN_MAP.get(r["label_raw"]) if src.startswith("dropin_") else None)
        if src not in EXTERNAL and not label:
            funnel[key]["dropped: unknown label"] += 1
            continue
        t = clean_text(r["text"], ch)
        if len(t) < MIN_CHARS[ch] or len(t.split()) < (3 if ch == "sms" else 5):
            funnel[key]["dropped: empty/too short"] += 1
            continue
        letters = sum(c.isalpha() for c in t)
        if letters / len(t) < 0.45:
            funnel[key]["dropped: mostly non-text"] += 1
            continue
        if not is_english(t):
            funnel[key]["dropped: not English"] += 1
            continue
        if any(ord(c) > 127 for c in t):
            funnel[key]["changed: ascii-folded"] += 1
        t = ascii_fold(t)
        if len(t) < MIN_CHARS[ch]:
            funnel[key]["dropped: empty/too short"] += 1
            continue
        d = r.get("date", "")
        if len(d) >= 10 and not ("2000-01-01" <= d <= TODAY):   # forged Date headers (e.g. year 2033) are common in phishing
            funnel[key]["changed: forged/invalid date blanked"] += 1
            d = ""
        row = {"text": t, "label": label, "channel": ch, "source": sub, "date": d}
        (external if src in EXTERNAL else kept).append(row)
        funnel[key]["after cleaning"] += 1

    # ---- synthetic *legitimate* transactional / modern messages (train-only; see report) ----------
    # Real ham corpora are 2002 mailing lists and chatty SMS: none has modern alerts or links, which would
    # teach the model "any link => phishing". These templates fill that gap and are tagged for exclusion from tests.
    from app.ml.dataset import bec_templates, legit_templates, legit_templates_v2, rnd
    rnd.seed(SEED)
    synth = []
    for label, src, fns, n in (("legitimate", "synthetic_legit", legit_templates() + legit_templates_v2(), 4000),
                               ("phishing", "synthetic_bec", bec_templates(), 800)):
        for i in range(n):
            txt = fns[i % len(fns)]()
            ch = "sms" if len(txt) < 200 else "email"
            funnel[src]["raw"] += 1
            synth.append({"text": ascii_fold(clean_text(txt, ch)), "label": label, "channel": ch, "source": src, "date": ""})
    kept = kept + synth

    # ---- exact + near-duplicate removal (global; keeps first occurrence) ------------------
    def dedup(rows, tag):
        lsh, seen, out, conflicts = MinHashLSH(threshold=0.8, num_perm=64), {}, [], 0
        dropped_conf = set()
        for i, row in enumerate(rows):
            k = hashlib.md5(norm_key(row["text"]).encode()).hexdigest()
            fk = row["source"].split("_")[0] if row["source"].startswith("spamassassin") else row["source"]
            fk = "spamassassin" if row["source"].startswith("spamassassin") else row["source"]
            if k in seen:
                other = rows[seen[k]]
                if other["label"] != row["label"]:
                    dropped_conf.add(seen[k]); funnel[fk]["dropped: label conflict"] += 1
                else:
                    funnel[fk]["dropped: exact duplicate"] += 1
                continue
            seen[k] = i
            mh = minhash(row["text"])
            near = lsh.query(mh)
            if near:
                j = int(near[0])
                if rows[j]["label"] != row["label"]:
                    dropped_conf.add(j); funnel[fk]["dropped: label conflict"] += 1
                else:
                    funnel[fk]["dropped: near duplicate"] += 1
                continue
            lsh.insert(str(i), mh)
            out.append(i)
        return [rows[i] for i in out if i not in dropped_conf]

    kept = dedup(kept, "train")
    external = dedup([dict(r, label="unverified") for r in external], "external")

    # ---- caps (deterministic down-sampling) -------------------------------------------------
    by_src = defaultdict(list)
    for r in kept:
        by_src[r["source"]].append(r)
    final = []
    for s, rs in by_src.items():
        cap = CAPS.get(s)
        if cap and len(rs) > cap:
            funnel[s]["dropped: down-sampled"] += len(rs) - cap
            rs = random.sample(rs, cap)
        final += rs
    for r in final:
        pass
    random.shuffle(final)
    for i, r in enumerate(final):
        r["id"] = i
        r["n_chars"] = len(r["text"])
    for s, rs in by_src.items():
        key = "spamassassin" if s.startswith("spamassassin") else s
        funnel[key]["final"] += sum(1 for r in final if r["source"] == s)

    ext = random.sample(external, min(3000, len(external)))
    cols = ["id", "text", "label", "channel", "source", "date", "n_chars"]
    for name, rows in (("dataset.csv", final), ("external_test.csv", ext)):
        with open(CLEAN / name, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for i, r in enumerate(rows):
                r.setdefault("id", i)
                r.setdefault("n_chars", len(r["text"]))
                w.writerow(r)
    summary = write_report(final, ext, funnel)
    print(summary)


def write_report(final, ext, funnel) -> str:
    import numpy as np
    cls = Counter((r["label"], r["channel"]) for r in final)
    lens = defaultdict(list)
    for r in final:
        lens[(r["label"], r["channel"])].append(r["n_chars"])
    dates = sorted(r["date"] for r in final if r["source"] == "phishing_pot" and r["date"])
    rep = {
        "total": len(final), "external_test": len(ext),
        "by_class": dict(Counter(r["label"] for r in final)),
        "by_class_channel": {f"{k[0]}/{k[1]}": v for k, v in sorted(cls.items())},
        "median_chars": {f"{k[0]}/{k[1]}": int(np.median(v)) for k, v in sorted(lens.items())},
        "phishing_pot_date_range": [dates[0], dates[-1]] if dates else None,
        "funnel": {k: dict(v) for k, v in funnel.items()},
    }
    (CLEAN / "report.json").write_text(json.dumps(rep, indent=2))
    md = ["# Data cleaning report", "", f"Final training set: **{rep['total']:,}** messages (+{rep['external_test']:,} in external_test.csv).", "",
          "## Class x channel", "| class | channel | count | median chars |", "|---|---|---|---|"]
    for k, v in sorted(cls.items()):
        md.append(f"| {k[0]} | {k[1]} | {v:,} | {int(np.median(lens[k]))} |")
    md += ["", "## Cleaning funnel per source", "| source | raw | " + " | ".join(
        sorted({r for c in funnel.values() for r in c if r.startswith('dropped')})) + " | final |"]
    reasons = sorted({r for c in funnel.values() for r in c if r.startswith("dropped")})
    md.append("|---|---|" + "---|" * (len(reasons) + 1))
    for s, c in sorted(funnel.items()):
        md.append(f"| {s} | {c['raw']:,} | " + " | ".join(f"{c.get(r, 0):,}" for r in reasons) + f" | {c.get('final', c.get('after cleaning', 0)):,} |")
    (CLEAN / "report.md").write_text("\n".join(md) + "\n")
    return "\n".join(md)


if __name__ == "__main__":
    run()
