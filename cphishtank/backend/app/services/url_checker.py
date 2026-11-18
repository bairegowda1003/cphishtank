"""URL safety checks: local blocklist, optional WHOIS age, redirect chains,
Google Safe Browsing and VirusTotal. Every network check fails *open* (a timeout
never breaks a scan) and is disabled unless enabled/configured in .env."""
from __future__ import annotations

import base64
import concurrent.futures
import logging
from datetime import datetime, timezone

import httpx

from ..config import settings
from .heuristics import sig

log = logging.getLogger("cphishtank.urlcheck")
_blocklist_cache = {"mtime": None, "data": set()}
TIMEOUT = 5


# Never block these registered domains outright: they host millions of legitimate pages. The feed lists
# individual bad sub-domains on them (e.g. evil123.netlify.app), which still match exactly.
SHARED_HOSTS = {"sites.google.com", "docs.google.com", "forms.gle", "netlify.app", "github.io", "blogspot.com",
                "weebly.com", "wixsite.com", "godaddysites.com", "repl.co", "web.app", "firebaseapp.com",
                "pages.dev", "workers.dev", "herokuapp.com", "vercel.app", "glitch.me", "amazonaws.com",
                "000webhostapp.com", "storage.googleapis.com", "wordpress.com", "google.com", "microsoft.com"}


def _blocklist_files():
    feeds = settings.BLOCKLIST_PATH.parent / "feeds"
    return [settings.BLOCKLIST_PATH, *sorted(feeds.glob("*.txt"))] if feeds.exists() else [settings.BLOCKLIST_PATH]


def load_blocklist() -> set[str]:
    """Union of the hand-kept list and live feeds in data/feeds/ (refresh: python -m pipeline.collect --only phishing_domains --refresh)."""
    files = [f for f in _blocklist_files() if f.exists()]
    stamp = tuple((str(f), f.stat().st_mtime) for f in files)
    if _blocklist_cache["mtime"] != stamp:
        entries = set()
        for f in files:
            for line in f.read_text(errors="ignore").splitlines():
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    entries.add(line.replace("https://", "").replace("http://", "").split("/")[0])
        entries -= SHARED_HOSTS
        _blocklist_cache.update(mtime=stamp, data=entries)
    return _blocklist_cache["data"]


def domain_age_days(domain: str) -> int | None:
    import whois  # lazy: optional dependency

    def _lookup():
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        return created

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        try:
            created = ex.submit(_lookup).result(timeout=TIMEOUT)
        except Exception as e:  # network, parse, timeout
            log.info("whois failed for %s: %s", domain, e)
            return None
    if not created:
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - created).days


def redirect_chain(url: str) -> list[str]:
    full = url if url.lower().startswith("http") else "http://" + url
    try:
        with httpx.Client(follow_redirects=True, timeout=TIMEOUT, max_redirects=6,
                          headers={"User-Agent": "CPhishTank-URLCheck/1.0"}) as c:
            r = c.head(full)
            return [str(h.url) for h in r.history] + [str(r.url)]
    except Exception as e:
        log.info("redirect check failed for %s: %s", url, e)
        return []


def safe_browsing_hit(url: str) -> bool | None:
    key = settings.GOOGLE_SAFE_BROWSING_KEY
    if not key:
        return None
    body = {"client": {"clientId": "cphishtank", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                           "threatEntries": [{"url": url}]}}
    try:
        r = httpx.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
                       json=body, timeout=TIMEOUT)
        return bool(r.json().get("matches"))
    except Exception as e:
        log.info("safe browsing failed: %s", e)
        return None


def virustotal_hits(url: str) -> int | None:
    key = settings.VIRUSTOTAL_API_KEY
    if not key:
        return None
    uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        r = httpx.get(f"https://www.virustotal.com/api/v3/urls/{uid}",
                      headers={"x-apikey": key}, timeout=TIMEOUT)
        if r.status_code != 200:
            return None
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    except Exception as e:
        log.info("virustotal failed: %s", e)
        return None


def live_signals(url: str, domain: str) -> tuple[list[dict], dict]:
    """Run whichever optional checks are enabled. Returns (signals, extra info)."""
    signals, info = [], {}
    full = url if url.lower().startswith("http") else "http://" + url
    if settings.ENABLE_WHOIS:
        age = domain_age_days(domain)
        info["domain_age_days"] = age
        if age is not None and age < 30:
            signals.append(sig("new_domain", "url", 26, f"Domain registered only {age} days ago",
                               "Phishing sites are usually set up days before an attack.", domain))
        elif age is not None and age < 180:
            signals.append(sig("young_domain", "url", 10, "Domain is under 6 months old",
                               "Newly registered domains are riskier than established ones.", domain))
    if settings.ENABLE_REDIRECT_CHECK:
        chain = redirect_chain(url)
        info["redirects"] = chain
        if len(chain) >= 4:
            signals.append(sig("redirect_chain", "url", 14, f"Link bounces through {len(chain) - 1} redirects",
                               "Long redirect chains are used to evade filters.", " → ".join(chain[:4])))
    if settings.GOOGLE_SAFE_BROWSING_KEY:
        hit = safe_browsing_hit(full)
        info["safe_browsing"] = hit
        if hit:
            signals.append(sig("safe_browsing", "url", 95, "Flagged by Google Safe Browsing",
                               "Google lists this URL as malware or phishing.", url))
    if settings.VIRUSTOTAL_API_KEY:
        n = virustotal_hits(full)
        info["virustotal_detections"] = n
        if n:
            signals.append(sig("virustotal", "url", min(40 + n * 8, 95), f"{n} security vendors flag this URL",
                               "VirusTotal aggregates results from many scanners.", url))
    return signals, info
