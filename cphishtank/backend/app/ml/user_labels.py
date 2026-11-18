"""Privacy-conscious ingestion for explicitly user-labelled messages."""
from __future__ import annotations

import csv
import hashlib
import re
from email import message_from_string, policy
from html.parser import HTMLParser
from pathlib import Path

from ..config import settings
from pipeline.clean import EMAIL, MIN_CHARS, PHONE, ascii_fold, clean_text, is_english, norm_key

CSV_COLUMNS = ["text", "label", "channel", "source", "date"]
_HEADER = re.compile(r"(?im)^(?:from|to|cc|bcc|reply-to|date|return-path|subject):\s*")
_URL = re.compile(r"(?i)\bhttps?://[^\s<>\"')\]]+")
_LABELS = {"safe": "legitimate", "scam": "phishing"}


class _HTMLText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str):
        self.parts.append(data)


def _remove_html(value: str) -> str:
    parser = _HTMLText()
    parser.feed(value)
    parser.close()
    return " ".join(parser.parts)


def _message_body(raw: str, channel: str) -> str:
    if channel != "email" or not _HEADER.search(raw):
        return raw
    msg = message_from_string(raw, policy=policy.default)
    subject = str(msg.get("Subject") or "")
    plain_parts, html_parts = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_filename():
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError, TypeError):
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", "ignore")
        if part.get_content_type() == "text/html":
            html_parts.append(_remove_html(str(content)))
        elif part.get_content_type() == "text/plain":
            plain_parts.append(str(content))
    body = "\n".join(plain_parts).strip() or "\n".join(html_parts).strip()
    return f"{subject}\n\n{body}".strip()


def sanitize_message(raw: str, channel: str) -> str:
    """Clean, de-identify common PII, remove URL query secrets, and ASCII-fold before storage."""
    text = _message_body(raw, channel)
    text = _URL.sub(lambda match: match.group(0).split("?", 1)[0].split("#", 1)[0], text)
    text = clean_text(text, channel)
    text = EMAIL.sub("user@example.com", text)
    text = PHONE.sub("000-000-0000", text)
    text = ascii_fold(text)
    if len(text) < MIN_CHARS[channel] or not is_english(text):
        raise ValueError("Message is too short or is not supported English text.")
    return text


def _fingerprint(text: str, channel: str) -> str:
    value = f"{channel}:{norm_key(text)}".encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def append_labeled_message(
    raw: str,
    label: str,
    channel: str,
    path: Path | None = None,
) -> dict:
    """Append only a sanitized message; never return or log message content."""
    if label not in _LABELS:
        raise ValueError("Choose safe or scam.")
    if channel not in MIN_CHARS:
        raise ValueError("Choose email or SMS.")
    if len(raw) > 20_000:
        raise ValueError("Message is larger than 20,000 characters.")
    text = sanitize_message(raw, channel)
    target = path or settings.USER_LABELED_PATH
    target.parent.mkdir(parents=True, exist_ok=True)

    normalized_key = _fingerprint(text, channel)
    if target.exists():
        with target.open(encoding="utf-8", newline="") as stream:
            for existing in csv.DictReader(stream):
                if _fingerprint(existing.get("text", ""), existing.get("channel", "email")) == normalized_key:
                    if existing.get("label") != _LABELS[label]:
                        raise ValueError("A matching message already exists with a different label.")
                    return {"status": "duplicate", "label": _LABELS[label]}

    with target.open("a", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        if stream.tell() == 0:
            writer.writeheader()
        writer.writerow({"text": text, "label": _LABELS[label], "channel": channel,
                         "source": "user_labeled", "date": ""})
    return {"status": "added", "label": _LABELS[label]}
