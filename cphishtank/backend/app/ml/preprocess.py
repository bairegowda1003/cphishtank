"""Text normalisation shared by training and inference (they MUST match)."""
import re
import unicodedata
from ..services import heuristics as H

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_NUM = re.compile(r"\b\d[\d,.:]*\b")
_WS = re.compile(r"\s+")


def normalize(text: str) -> str:
    """Lowercase; replace URLs with tokens that keep their risk cues; mask numbers/emails."""
    text = unicodedata.normalize("NFKD", unicodedata.normalize("NFKC", text or "")).encode("ascii", "ignore").decode("ascii")
    for u in sorted(H.extract_urls(text), key=lambda x: -len(x["url"])):
        res = H.analyze_url(u["url"])
        ids = {s["id"] for s in res["signals"]}
        tag = " urltoken"
        if ids & {"ip_host", "lookalike", "brand_misuse", "punycode", "at_symbol", "blocklist"}:
            tag += " urlfake"
        if "shortener" in ids:
            tag += " urlshort"
        if ids & {"bad_tld", "bait_words", "hyphens", "subdomains"}:
            tag += " urlodd"
        if not ids:
            tag += " urlclean"
        text = text.replace(u["url"], tag + " ")
    text = _EMAIL.sub(" emailtoken ", text)
    text = _NUM.sub(" numtoken ", text.lower())
    return _WS.sub(" ", text).strip()
