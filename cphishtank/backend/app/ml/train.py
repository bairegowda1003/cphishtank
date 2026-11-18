"""Train, calibrate, stack, and evaluate the binary scam detector.

Run from backend/: ``python -m app.ml.train``.
The blind test file is evaluated only when it has been frozen with
``python -m scripts.freeze_blind_test``; it is never used for fitting or tuning.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS, TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion
from sklearn.svm import LinearSVC

from ..config import settings
from .dataset import build_dataset
from .features import NumericMessageFeatures, static_fusion_features
from .preprocess import normalize

SEED = 42
SYN_SOURCES = ("synthetic_legit", "synthetic_bec", "synthetic")
PHISH_LABELS = {"phishing", "suspicious", "scam"}
LEGIT_LABELS = {"legitimate", "safe"}
BLIND_PATH = settings.BLOCKLIST_PATH.parent / "clean" / "blind_test.csv"
BLIND_MANIFEST = settings.BLOCKLIST_PATH.parent / "clean" / "blind_test.freeze.json"


def make_features() -> FeatureUnion:
    """Word and character TF-IDF plus numeric message features."""
    from .features import message_text

    def normalized(value):
        return normalize(message_text(value))

    return FeatureUnion([
        ("word", TfidfVectorizer(
            preprocessor=normalized, token_pattern=r"(?u)\b\w\w+\b", stop_words="english",
            ngram_range=(1, 2), min_df=2, sublinear_tf=True, max_features=60000,
        )),
        ("char", TfidfVectorizer(
            preprocessor=normalized, analyzer="char_wb", ngram_range=(3, 5),
            min_df=2, sublinear_tf=True, max_features=100000,
        )),
        ("numeric", NumericMessageFeatures()),
    ])


def candidate_names() -> list[str]:
    candidates = ["logistic_regression", "linear_svc"]
    if importlib.util.find_spec("lightgbm"):
        candidates.append("lightgbm")
    return candidates


def _base_estimator(name: str):
    if name == "logistic_regression":
        return LogisticRegression(C=4.0, max_iter=3000, class_weight="balanced", random_state=SEED)
    if name == "linear_svc":
        return LinearSVC(C=1.0, class_weight="balanced", random_state=SEED)
    if name == "lightgbm":
        if not importlib.util.find_spec("lightgbm"):
            raise RuntimeError("LightGBM is not installed.")
        from lightgbm import LGBMClassifier
        return LGBMClassifier(n_estimators=300, learning_rate=0.05, num_leaves=31,
                              class_weight="balanced", verbosity=-1, random_state=SEED)
    raise ValueError(f"Unknown estimator: {name}")


def _calibrated(name: str, X, y, folds: int = 3):
    return CalibratedClassifierCV(
        estimator=_base_estimator(name), method="sigmoid", cv=folds, n_jobs=1,
    ).fit(X, y)


def _scam_probability(model, X) -> np.ndarray:
    classes = list(model.classes_)
    if "scam" not in classes:
        raise ValueError("The fitted model has no scam class.")
    return model.predict_proba(X)[:, classes.index("scam")]


def binary_metrics(y_true, score, threshold: float) -> dict:
    truth = np.asarray([str(label) in PHISH_LABELS for label in y_true], dtype=bool)
    predicted = np.asarray(score) >= threshold
    tn, fp, fn, tp = confusion_matrix(truth, predicted, labels=[False, True]).ravel()
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    result = {
        "n": int(len(truth)),
        "accuracy": round(float(accuracy_score(truth, predicted)), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(2 * precision * recall / max(precision + recall, 1e-12)), 4),
        "false_positive_rate": round(float(fp / max(fp + tn, 1)), 4),
        "roc_auc": round(float(roc_auc_score(truth, score)), 4) if truth.any() and (~truth).any() else None,
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }
    return result


def choose_thresholds(y_true, scores, max_false_alarm: float = 0.02, min_scam_recall: float = 0.90) -> dict:
    """Find a validation operating interval; the interval between cuts is the caution band."""
    truth = np.asarray([str(label) in PHISH_LABELS for label in y_true], dtype=bool)
    scores = np.asarray(scores, dtype=float)
    candidates = np.unique(np.concatenate(([0.0, 1.000001], scores)))
    safe_cuts = []
    scam_cuts = []
    for threshold in candidates:
        predicted = scores >= threshold
        fpr = float((predicted & ~truth).sum() / max((~truth).sum(), 1))
        recall = float((predicted & truth).sum() / max(truth.sum(), 1))
        if fpr <= max_false_alarm:
            safe_cuts.append(float(threshold))
        if recall >= min_scam_recall:
            scam_cuts.append(float(threshold))
    safe_cut = min(safe_cuts) if safe_cuts else 1.000001
    scam_cut = max(scam_cuts) if scam_cuts else safe_cut
    feasible = safe_cut <= scam_cut
    if not feasible:
        scam_cut = safe_cut
    decision_cut = safe_cut if feasible else safe_cut
    observed = binary_metrics(["scam" if x else "safe" for x in truth], scores, decision_cut)
    return {
        "safe_cutoff": round(safe_cut, 6),
        "scam_cutoff": round(scam_cut, 6),
        "binary_decision_threshold": round(decision_cut, 6),
        "target_false_alarm_rate": max_false_alarm,
        "target_scam_recall": min_scam_recall,
        "constraints_met": bool(feasible and observed["false_positive_rate"] <= max_false_alarm
                                and observed["recall"] >= min_scam_recall),
        "validation_at_decision_threshold": observed,
    }


def _fusion_rows(texts, probabilities):
    return [static_fusion_features(str(text), float(probability))
            for text, probability in zip(texts, probabilities)]


def _fused_probability(vectorizer, stacker, texts, probabilities) -> np.ndarray:
    rows = _fusion_rows(texts, probabilities)
    return stacker.predict_proba(vectorizer.transform(rows))[:, list(stacker.classes_).index(1)]


def _optional_runtime_trials() -> dict:
    """Record whether the optional LightGBM and GPU-only transformer trials are possible."""
    trials = {}
    if importlib.util.find_spec("lightgbm"):
        trials["lightgbm"] = "candidate"
    else:
        trials["lightgbm"] = "skipped: optional package not installed"
    try:
        import torch
    except ImportError:
        trials["distilbert"] = "skipped: PyTorch is not installed"
    else:
        if not torch.cuda.is_available():
            trials["distilbert"] = "skipped: no CUDA GPU is available"
        elif not (importlib.util.find_spec("transformers") and importlib.util.find_spec("datasets")):
            trials["distilbert"] = "skipped: GPU available, but transformers/datasets are not installed"
        else:
            trials["distilbert"] = "not run: no isolated transformer fine-tuning implementation is configured"
    return trials


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _blind_is_frozen() -> bool:
    if not BLIND_PATH.exists() or not BLIND_MANIFEST.exists():
        return False
    try:
        manifest = json.loads(BLIND_MANIFEST.read_text(encoding="utf-8"))
        blind = pd.read_csv(BLIND_PATH, keep_default_na=False)
    except (OSError, json.JSONDecodeError, pd.errors.ParserError):
        return False
    return (len(blind) >= 100
            and {"text", "label", "channel"}.issubset(blind.columns)
            and blind["label"].isin({"safe", "scam"}).all()
            and blind["channel"].isin({"email", "sms"}).all()
            and _hash_file(BLIND_PATH) == manifest.get("sha256"))


def _evaluate_blind(metrics: dict, feature_union, model, fusion_vectorizer, stacker, thresholds) -> None:
    if not BLIND_PATH.exists() or not BLIND_MANIFEST.exists():
        metrics["blind_test"] = {
            "status": "blocked_pending_frozen_human_labels",
            "required_minimum": 100,
            "current_legacy_set_size": 32,
        }
        return
    manifest = json.loads(BLIND_MANIFEST.read_text(encoding="utf-8"))
    digest = _hash_file(BLIND_PATH)
    if digest != manifest.get("sha256"):
        raise ValueError("Frozen blind test changed after freeze; refusing to score it.")
    blind = pd.read_csv(BLIND_PATH, keep_default_na=False)
    if len(blind) < 100:
        raise ValueError("Frozen blind test must contain at least 100 hand-labelled messages.")
    required = {"text", "label", "channel"}
    if not required.issubset(blind.columns) or not set(blind["label"]).issubset({"safe", "scam"}):
        raise ValueError("Blind test must contain text, channel, and safe/scam labels.")
    y = blind["label"].map({"safe": "safe", "scam": "scam"}).tolist()
    x = feature_union.transform(blind["text"].astype(str).tolist())
    base = _scam_probability(model, x)
    fused = _fused_probability(fusion_vectorizer, stacker, blind["text"], base)
    metrics["blind_test"] = {
        "status": "evaluated_frozen",
        "n": int(len(blind)),
        "sha256": digest,
        "metrics": binary_metrics(y, fused, thresholds["binary_decision_threshold"]),
    }


def train_and_save(per_class: int = 1200, verbose: bool = True, evaluate: bool = True) -> dict:
    if not _blind_is_frozen():
        raise RuntimeError(
            "Training is gated until data/clean/blind_test.csv has at least 100 hand-labelled "
            "rows and has been frozen with python -m scripts.freeze_blind_test."
        )
    df = build_dataset(per_class).reset_index(drop=True)
    df = df[df["label"].isin(LEGIT_LABELS | PHISH_LABELS)].reset_index(drop=True)
    if df.empty or df["label"].nunique() != 2:
        raise ValueError("Training data must include both safe and scam messages.")
    df["target"] = df["label"].map(lambda label: "scam" if label in PHISH_LABELS else "safe")
    targets = df["target"].to_numpy()
    texts = df["text"].astype(str).to_numpy()
    is_synthetic = df["source"].astype(str).isin(SYN_SOURCES).to_numpy()
    eligible = np.flatnonzero(~is_synthetic)
    train_and_hold, test_indices = train_test_split(
        eligible, test_size=0.15, stratify=targets[eligible], random_state=SEED,
    )
    train_indices, validation_indices = train_test_split(
        train_and_hold, test_size=0.1765, stratify=targets[train_and_hold], random_state=SEED,
    )
    train_indices = np.concatenate((train_indices, np.flatnonzero(is_synthetic)))
    feature_union = make_features()
    x_train = feature_union.fit_transform(texts[train_indices])
    x_validation = feature_union.transform(texts[validation_indices])
    x_test = feature_union.transform(texts[test_indices])

    metrics: dict = {
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "samples": int(len(df)),
        "class_balance": df["target"].value_counts().to_dict(),
        "data_sources": sorted(df["source"].astype(str).unique().tolist()),
        "algorithm": "word TF-IDF(1-2) + char_wb TF-IDF(3-5) + numeric features + sigmoid calibration + LR stack",
        "feature_names": ["url_count", "link_text_domain_mismatch", "sender_domain_age_bucket",
                          "uppercase_ratio", "digit_ratio", "has_attachment", "exclamation_count"],
        "trials": _optional_runtime_trials(),
    }
    if "channel" in df.columns:
        metrics["class_channel"] = {
            f"{label}/{channel}": int(count)
            for (label, channel), count in df.groupby(["target", "channel"]).size().items()
        }

    trial_models = {}
    validation_probabilities = {}
    trial_reports = {}
    candidates = candidate_names()
    for name in candidates:
        fitted = _calibrated(name, x_train, targets[train_indices])
        probability = _scam_probability(fitted, x_validation)
        trial_models[name] = fitted
        validation_probabilities[name] = probability
        candidate_thresholds = choose_thresholds(targets[validation_indices], probability)
        trial_reports[name] = binary_metrics(
            targets[validation_indices], probability, candidate_thresholds["binary_decision_threshold"],
        )
        metrics["trials"][name] = {
            "validation": trial_reports[name],
            "validation_thresholds": candidate_thresholds,
            "calibration": {
                "method": "sigmoid",
                "brier_score": round(float(np.mean((probability - (targets[validation_indices] == "scam")) ** 2)), 5),
            },
        }

    selected_name = max(
        candidates,
        key=lambda name: (
            trial_reports[name]["false_positive_rate"] <= 0.02
            and trial_reports[name]["recall"] >= 0.90,
            trial_reports[name]["recall"],
            trial_reports[name]["f1"],
            trial_reports[name]["roc_auc"] or 0.0,
        ),
    )
    selected_model = trial_models[selected_name]
    validation_probability = validation_probabilities[selected_name]

    # Stacking and thresholds use validation only. The final random-split test remains untouched.
    fusion_vectorizer = DictVectorizer(sparse=True)
    validation_fusion = fusion_vectorizer.fit_transform(_fusion_rows(texts[validation_indices], validation_probability))
    stacker = LogisticRegression(C=1.0, max_iter=2000, random_state=SEED)
    stacker.fit(validation_fusion, targets[validation_indices] == "scam")
    validation_fused = _fused_probability(
        fusion_vectorizer, stacker, texts[validation_indices], validation_probability,
    )
    thresholds = choose_thresholds(targets[validation_indices], validation_fused)

    test_probability = _scam_probability(selected_model, x_test)
    test_fused = _fused_probability(fusion_vectorizer, stacker, texts[test_indices], test_probability)
    metrics["selected_model"] = selected_name
    metrics["validation_thresholds"] = thresholds
    metrics["random_split"] = {
        "protocol": "70/15/15 source-independent stratified split; synthetic rows used in training only",
        "train_n": int(len(train_indices)),
        "validation_n": int(len(validation_indices)),
        "test_n": int(len(test_indices)),
        "base_model": binary_metrics(targets[test_indices], test_probability, 0.5),
        "binary": binary_metrics(targets[test_indices], test_fused, thresholds["binary_decision_threshold"]),
    }
    metrics["headline"] = {
        "name": "untouched 15% real-data test split after validation-only stacking",
        "accuracy": metrics["random_split"]["binary"]["accuracy"],
        "macro_f1": metrics["random_split"]["binary"]["f1"],
        "binary_f1": metrics["random_split"]["binary"]["f1"],
    }
    metrics["leave_one_source_out"] = {}
    metrics["temporal"] = {"status": "not_computed"}
    if evaluate:
        _evaluate_protocols(
            metrics, df, texts, targets, feature_union, selected_name,
            fusion_vectorizer, stacker, thresholds,
        )

    names = feature_union.get_feature_names_out()
    coef = _linear_coefficients(selected_model)
    if coef is not None:
        word_features = [(str(name).removeprefix("word__"), float(weight))
                         for name, weight in zip(names, coef) if str(name).startswith("word__")]
        metrics["top_features"] = {
            "safe": [term for term, weight in sorted(word_features, key=lambda x: x[1])[:12]
                     if term.lower() not in ENGLISH_STOP_WORDS],
            "scam": [term for term, weight in sorted(word_features, key=lambda x: -x[1])[:12]
                     if term.lower() not in ENGLISH_STOP_WORDS],
        }
    else:
        metrics["top_features"] = {"status": "unavailable_for_non_linear_candidate"}
    terms = metrics["top_features"]
    if isinstance(terms.get("scam"), list):
        metrics["explainability_check"] = {
            "stop_words_excluded": True,
            "top_scam_words_are_not_only_stop_words": bool(terms["scam"]),
        }

    try:
        previous = json.loads(settings.METRICS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        previous = {}
    metrics["baseline"] = {
        "algorithm": previous.get("algorithm"),
        "random_split": (previous.get("random_split") or {}).get("binary"),
        "temporal": previous.get("temporal"),
        "blind_test": "legacy 32-message set; not a 100-message blinded evaluation",
    }
    _evaluate_blind(metrics, feature_union, selected_model, fusion_vectorizer, stacker, thresholds)

    settings.MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "version": 2,
        "feature_union": feature_union,
        "model": selected_model,
        "fusion_vectorizer": fusion_vectorizer,
        "fusion_model": stacker,
        "thresholds": thresholds,
        "selected_model": selected_name,
    }, settings.MODEL_PATH)
    settings.METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    if verbose:
        print(f"trained {selected_name} on {len(train_indices):,} examples -> {settings.MODEL_PATH}")
        for name in ("random_split", "temporal", "leave_one_source_out", "blind_test"):
            if name in metrics:
                print(f"\n[{name}]\n{json.dumps(metrics[name], indent=1)[:2000]}")
    return metrics


def _linear_coefficients(model):
    calibrated = getattr(model, "calibrated_classifiers_", [])
    for item in calibrated:
        estimator = getattr(item, "estimator", None) or getattr(item, "base_estimator", None)
        if estimator is not None and hasattr(estimator, "coef_"):
            coefficient = np.asarray(estimator.coef_)
            return coefficient[0] if coefficient.shape[0] == 1 else coefficient[-1]
    return None


def _evaluate_protocols(metrics, df, texts, targets, feature_union, selected_name,
                        fusion_vectorizer, stacker, thresholds):
    source = df["source"].astype(str).to_numpy()
    date = df["date"].astype(str).to_numpy() if "date" in df.columns else np.full(len(df), "")
    dated_phishing = np.flatnonzero((source == "phishing_pot") & (date >= "2000-01-01") & (date <= "9999-12-31"))
    if len(dated_phishing) >= 10:
        ordered = dated_phishing[np.argsort(date[dated_phishing])]
        holdout_at = max(1, int(len(ordered) * 0.8))
        newest = ordered[holdout_at:]
        older = ordered[:holdout_at]
        training = np.setdiff1d(np.arange(len(df)), newest)
        temporal_features = make_features()
        temporal_train_x = temporal_features.fit_transform(texts[training])
        temporal_test_x = temporal_features.transform(texts[newest])
        model = _calibrated(selected_name, temporal_train_x, targets[training], folds=3)
        base = _scam_probability(model, temporal_test_x)
        fused = _fused_probability(fusion_vectorizer, stacker, texts[newest], base)
        metrics["temporal"] = {
            "train_phishing_pot_through": str(date[older[-1]]),
            "test_source": "phishing_pot",
            "metrics": binary_metrics(targets[newest], fused, thresholds["binary_decision_threshold"]),
        }

    groups = {
        "phishing_pot": source == "phishing_pot",
        "smishtank": source == "smishtank",
        "spamassassin": np.char.startswith(source.astype(str), "spamassassin"),
        "uci_sms": source == "uci_sms",
        "nus_sms": source == "nus_sms",
        "user_labeled": source == "user_labeled",
    }
    for name, mask in groups.items():
        held = np.flatnonzero(mask)
        remaining = np.flatnonzero(~mask)
        if len(held) and len(np.unique(targets[remaining])) == 2:
            source_features = make_features()
            source_train_x = source_features.fit_transform(texts[remaining])
            source_test_x = source_features.transform(texts[held])
            model = _calibrated(selected_name, source_train_x, targets[remaining], folds=3)
            base = _scam_probability(model, source_test_x)
            fused = _fused_probability(fusion_vectorizer, stacker, texts[held], base)
            metrics["leave_one_source_out"][name] = binary_metrics(
                targets[held], fused, thresholds["binary_decision_threshold"],
            )
    ext_path = settings.BLOCKLIST_PATH.parent / "clean" / "external_test.csv"
    if ext_path.exists():
        ext = pd.read_csv(ext_path, keep_default_na=False)
        model = _calibrated(selected_name, feature_union.transform(texts), targets, folds=3)
        ext_x = feature_union.transform(ext["text"].astype(str).tolist())
        ext_p = _scam_probability(model, ext_x)
        metrics["external_spamdam"] = {
            "n": int(len(ext)),
            "flagged_at_threshold": round(float((ext_p >= thresholds["binary_decision_threshold"]).mean()), 4),
            "labels_unverified": True,
        }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-class", type=int, default=1200)
    ap.add_argument("--no-eval", action="store_true")
    args = ap.parse_args()
    train_and_save(args.per_class, evaluate=not args.no_eval)
