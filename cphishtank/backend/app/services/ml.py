"""Model loading, prediction and token-level explanation."""
from __future__ import annotations

import logging
import re
import threading

import joblib
import numpy as np
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

from ..config import settings
from ..ml.features import MessageInput, fusion_features
from ..ml.preprocess import normalize

log = logging.getLogger("cphishtank.ml")
_lock = threading.Lock()
_bundle = None

HIDDEN_TERMS = {"urltoken", "numtoken", "emailtoken", "urlclean", "urlfake", "urlshort", "urlodd"}
FRIENDLY = {"urlfake": "a link that imitates a real site", "urlshort": "a shortened link",
            "urlodd": "an odd-looking link", "urlclean": "a link to a normal site"}


def load_model(force: bool = False):
    global _bundle
    with _lock:
        if _bundle is None or force:
            if not settings.MODEL_PATH.exists():
                log.warning("No trained model found; training on bundled data (takes a few seconds)...")
                from ..ml.train import train_and_save
                train_and_save(verbose=False, evaluate=False)
            _bundle = joblib.load(settings.MODEL_PATH)
    return _bundle


def predict(text: str, sender: str | None = None, html: str | None = None,
            attachments: list[str] | None = None, domain_age_days: int | None = None) -> dict:
    b = load_model()
    if b.get("version") == 2:
        message = MessageInput(text, sender, html, tuple(attachments or ()), domain_age_days)
        x = b["feature_union"].transform([message])
        model = b["model"]
        classes = list(model.classes_)
        probability = float(model.predict_proba(x)[0, classes.index("scam")])
        safe = 1.0 - probability
        top = "phishing" if probability >= 0.5 else "legitimate"
        return {
            "probs": {"legitimate": safe, "phishing": probability},
            "label": top,
            "confidence": max(safe, probability),
            "risk": round(probability * 100, 1),
            "scam_probability": probability,
        }
    pipe, labels = b["pipeline"], b["labels"]
    probs = pipe.predict_proba([normalize(text)])[0]
    p = {l: float(pr) for l, pr in zip(labels, probs)}
    top = max(p, key=p.get)
    # expected risk: phishing counts fully, suspicious half
    risk = 100 * (p.get("phishing", 0) + 0.5 * p.get("suspicious", 0))
    return {"probs": p, "label": top, "confidence": p[top], "risk": round(risk, 1)}


def fuse(scam_probability: float, signals: list[dict], heuristic_risk: float) -> float:
    """Return a calibrated stack score, or the legacy fusion score for an old artifact."""
    bundle = load_model()
    if bundle.get("version") == 2:
        row = fusion_features(scam_probability, signals, heuristic_risk)
        x = bundle["fusion_vectorizer"].transform([row])
        classes = list(bundle["fusion_model"].classes_)
        return float(bundle["fusion_model"].predict_proba(x)[0, classes.index(True)])
    return 0.5 * scam_probability + 0.5 * (heuristic_risk / 100)


def thresholds() -> tuple[float, float]:
    """Return safe/caution and caution/scam boundaries on the 0-100 UI scale."""
    bundle = load_model()
    if bundle.get("version") == 2:
        learned = bundle["thresholds"]
        return 100 * learned["safe_cutoff"], 100 * learned["scam_cutoff"]
    return 30.0, 60.0


def explain(text: str, top_k: int = 8) -> dict:
    """Exact per-n-gram contributions of the linear model (equivalent to linear SHAP).

    contribution(t) = (coef[phishing, t] - coef[legitimate, t]) * tfidf(t)
    positive -> pushes towards phishing, negative -> pushes towards legitimate.
    """
    b = load_model()
    if b.get("version") == 2:
        feature_union, model = b["feature_union"], b["model"]
        x = feature_union.transform([text])
        names = feature_union.get_feature_names_out()
        coefficient = None
        for calibrated in getattr(model, "calibrated_classifiers_", []):
            estimator = getattr(calibrated, "estimator", None) or getattr(calibrated, "base_estimator", None)
            if estimator is not None and hasattr(estimator, "coef_"):
                coefficient = np.asarray(estimator.coef_)[0]
                break
        if coefficient is None:
            return {"toward_phishing": [], "toward_legitimate": []}
        idx = x.nonzero()[1]
        contributions = []
        for index in idx:
            name = str(names[index])
            if not name.startswith("word__"):
                continue
            term = name.removeprefix("word__")
            if term.lower() in ENGLISH_STOP_WORDS:
                continue
            weight = float(coefficient[index] * x[0, index])
            contributions.append((term, weight))
        toward_scam = sorted((item for item in contributions if item[1] > 0),
                             key=lambda item: -item[1])[:top_k]
        toward_safe = sorted((item for item in contributions if item[1] < 0),
                             key=lambda item: item[1])[:4]
        format_items = lambda items: [{"term": term, "weight": round(weight, 3)}
                                      for term, weight in items]
        return {"toward_phishing": format_items(toward_scam),
                "toward_legitimate": format_items(toward_safe)}
    pipe, labels = b["pipeline"], b["labels"]
    vec, clf = pipe.steps[0][1], pipe.steps[1][1]
    x = vec.transform([normalize(text)])
    idx = x.nonzero()[1]
    if len(idx) == 0:
        return {"toward_phishing": [], "toward_legitimate": []}
    ci = {c: i for i, c in enumerate(clf.classes_)}
    w = clf.coef_[ci["phishing"]] - clf.coef_[ci["legitimate"]]
    names = vec.get_feature_names_out()
    contribs = []
    for i in idx:
        term, c = names[i], float(w[i] * x[0, i])
        if term in FRIENDLY:                       # e.g. "urlfake" -> readable phrase
            term = FRIENDLY[term]
        elif any(tok in HIDDEN_TERMS for tok in term.split()):
            continue                               # drop internal placeholder tokens
        contribs.append((term, c))
    pos = sorted([c for c in contribs if c[1] > 0], key=lambda c: -c[1])[:top_k]
    neg = sorted([c for c in contribs if c[1] < 0], key=lambda c: c[1])[:4]
    f = lambda L: [{"term": t, "weight": round(c, 3)} for t, c in L]  # noqa: E731
    return {"toward_phishing": f(pos), "toward_legitimate": f(neg)}


def locate_term(term: str, text: str) -> list[tuple[int, int]]:
    """Find a model n-gram in the ORIGINAL text so it can be highlighted."""
    toks = [t for t in term.split() if t not in HIDDEN_TERMS]
    if not toks or len(" ".join(toks)) < 3:
        return []
    rx = re.compile(r"\b" + r"\W+".join(re.escape(t) for t in toks) + r"\b", re.I)
    return [(m.start(), m.end()) for m in rx.finditer(text)][:2]


def metrics() -> dict:
    try:
        import json
        return json.loads(settings.METRICS_PATH.read_text())
    except Exception:
        return {}
