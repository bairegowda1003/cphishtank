"""Append verified phishing domains from PhishTank to data/blocklist.txt.
Usage: python -m app.ml.import_phishtank   (optionally set PHISHTANK_API_KEY)"""
import csv
import io
import os
from urllib.parse import urlparse

import httpx

from ..config import settings

URL = "http://data.phishtank.com/data/{key}online-valid.csv"


def main():
    key = os.getenv("PHISHTANK_API_KEY", "")
    url = URL.format(key=f"{key}/" if key else "")
    print("Downloading", url)
    r = httpx.get(url, timeout=60, follow_redirects=True, headers={"User-Agent": "phishtank/cphishtank"})
    r.raise_for_status()
    domains = set()
    for row in csv.DictReader(io.StringIO(r.text)):
        host = urlparse(row["url"]).hostname
        if host:
            domains.add(host.lower())
    with open(settings.BLOCKLIST_PATH, "a") as f:
        f.write("\n# --- PhishTank import ---\n")
        f.write("\n".join(sorted(domains)) + "\n")
    print(f"Added {len(domains)} domains to {settings.BLOCKLIST_PATH}")


if __name__ == "__main__":
    main()
