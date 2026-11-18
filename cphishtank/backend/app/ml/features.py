"""Structured message features shared by model training and inference."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

import numpy as np
from scipy.sparse import csr_matrix
from sklearn.base import BaseEstimator, TransformerMixin

from ..services import heuristics as H


@dataclass(frozen=True)
class MessageInput:
    text: str
    sender: str | None = None
    html: str | None = None
    attachments: tuple[str, ...] = ()
    domain_age_days: int | None = None


def message_text(value: str | MessageInput) -> str:
    return value.text if isinstance(value, MessageInput) else str(value)


def numeric_features(value: str | MessageInput) -> dict[str, float]:
    text = message_text(value)
    metadata = value if isinstance(value, MessageInput) else MessageInput(text)
    letters = [c for c in text if c.isalpha()]
    anchors = H.ANCHOR_RE.findall(metadata.html or "")
    mismatch_count = len(H.analyze_html_anchors(metadata.html or ""))
    age = metadata.domain_age_days
    attachment = bool(metadata.attachments) or bool(
        re.search(r"(?i)\b[\w-]+\.(?:pdf|docx?|xlsx?|pptx?|zip|7z|exe|js|html?)\b", text)
    )
    return {
        "url_count": float(len(H.extract_urls(text))),
        "link_text_domain_mismatch": float(mismatch_count / max(len(anchors), 1)),
        "sender_domain_age_bucket": float(1 if age is not None and age < 30 else
                                          2 if age is not None and age < 180 else
                                          3 if age is not None else 0),
        "uppercase_ratio": sum(c.isupper() for c in letters) / max(len(letters), 1),
        "digit_ratio": sum(c.isdigit() for c in text) / max(len(text), 1),
        "has_attachment": float(attachment),
        "exclamation_count": float(text.count("!")),
    }


class NumericMessageFeatures(BaseEstimator, TransformerMixin):
    """Convert message strings or metadata-carrying MessageInput objects to sparse features."""

    def fit(self, X: Iterable[str | MessageInput], y=None):
        return self

    def transform(self, X: Iterable[str | MessageInput]) -> csr_matrix:
        rows = [numeric_features(value) for value in X]
        columns = list(numeric_features("").keys())
        return csr_matrix(np.asarray([[row[name] for name in columns] for row in rows], dtype=float))

    def get_feature_names_out(self, input_features=None):
        return np.asarray(list(numeric_features("").keys()), dtype=object)


def _static_rule_signals(text: str) -> list[dict]:
    """Extract deterministic rule evidence without live network lookups."""
    sender = None
    body_lines = []
    for line in text.splitlines():
        match = re.match(r"(?i)^\s*from:\s*(.+)$", line)
        if match and sender is None:
            sender = match.group(1).strip()
        else:
            body_lines.append(line)
    body = "\n".join(body_lines)
    urls = H.extract_urls(body)
    signals = H.analyze_sender(sender, has_links=bool(urls))
    content, _ = H.analyze_content(body)
    signals.extend(content)
    for item in urls:
        signals.extend(H.analyze_url(item["url"])["signals"])
    return signals


def fusion_features(ml_probability: float, signals: list[dict], rule_score: float) -> dict[str, float]:
    features = {"ml_probability": float(ml_probability), "rule_score": float(rule_score)}
    for signal in signals:
        key = "signal_" + re.sub(r"[^a-z0-9_]+", "_", signal["id"].lower())
        features[key] = max(features.get(key, 0.0), float(signal.get("points", 1.0)))
    return features


def static_fusion_features(text: str, ml_probability: float) -> dict[str, float]:
    signals = _static_rule_signals(text)
    return fusion_features(ml_probability, signals, H.noisy_or([s["points"] for s in signals]))
