"""Freeze a sanitized, disjoint 100+ message blind test set before model tuning.

Create ``data/clean/blind_test.csv`` with columns ``text,label,channel`` and
safe/scam labels, then run ``python -m scripts.freeze_blind_test`` once.
"""
from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from app.config import settings
from app.ml.user_labels import sanitize_message
from pipeline.clean import norm_key

BLIND_PATH = settings.BLOCKLIST_PATH.parent / "clean" / "blind_test.csv"
MANIFEST_PATH = settings.BLOCKLIST_PATH.parent / "clean" / "blind_test.freeze.json"
TRAINING_PATH = settings.BLOCKLIST_PATH.parent / "clean" / "dataset.csv"
FIELDS = ["text", "label", "channel"]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def freeze(path: Path = BLIND_PATH) -> dict:
    manifest = MANIFEST_PATH if path == BLIND_PATH else path.with_suffix(".freeze.json")
    if manifest.exists():
        raise ValueError("This blind set is already frozen; do not edit or overwrite it.")
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as stream:
            csv.writer(stream).writerow(FIELDS)
        raise ValueError(f"Template created at {path}; add at least 100 hand-labelled rows, then retry.")
    blind = pd.read_csv(path, keep_default_na=False)
    if not set(FIELDS).issubset(blind.columns):
        raise ValueError("Blind CSV must have text,label,channel columns.")
    if len(blind) < 100:
        raise ValueError("Blind set needs at least 100 hand-labelled messages.")
    if not blind["label"].isin({"safe", "scam"}).all():
        raise ValueError("Blind labels must be safe or scam.")
    if not blind["channel"].isin({"email", "sms"}).all():
        raise ValueError("Blind channels must be email or sms.")

    sanitized = []
    seen = set()
    for row in blind.to_dict("records"):
        text = sanitize_message(str(row["text"]), str(row["channel"]))
        key = (str(row["channel"]), norm_key(text))
        if key in seen:
            raise ValueError("Blind set contains duplicate or near-identical messages.")
        seen.add(key)
        sanitized.append({"text": text, "label": row["label"], "channel": row["channel"]})

    if TRAINING_PATH.exists():
        training = pd.read_csv(TRAINING_PATH, keep_default_na=False)
        training_keys = {
            (str(row.get("channel", "email")), norm_key(str(row.get("text", ""))))
            for row in training.to_dict("records")
        }
        if seen & training_keys:
            raise ValueError("Blind set overlaps cleaned training data; remove overlap before freezing.")

    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(sanitized)
    record = {
        "sha256": _sha256(path),
        "rows": len(sanitized),
        "frozen_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "labels": "safe/scam",
        "training_overlap_checked": True,
    }
    manifest.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


if __name__ == "__main__":
    try:
        frozen = freeze()
    except ValueError as exc:
        raise SystemExit(str(exc))
    print(f"Frozen {frozen['rows']} sanitized blind messages ({frozen['sha256']}).")
