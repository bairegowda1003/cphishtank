import csv

import pytest

from app.ml.features import MessageInput, numeric_features
from app.ml.user_labels import append_labeled_message
from app.ml.train import choose_thresholds


def test_capture_stores_only_cleaned_data_and_strips_url_query(tmp_path):
    target = tmp_path / "user_labeled.csv"
    raw = (
        "From: Alice Example <alice@example.org>\n"
        "Subject: Receipt for order 12345678\n"
        "Content-Type: text/plain; charset=utf-8\n\n"
        "Your monthly invoice is available at https://shop.example.org/orders/12345678?token=private123. "
        "For help, call +1 415 555 0199."
    )
    result = append_labeled_message(raw, "safe", "email", target)
    assert result == {"status": "added", "label": "legitimate"}
    saved = target.read_text(encoding="utf-8")
    assert "alice@example.org" not in saved
    assert "private123" not in saved
    assert "token=" not in saved
    assert "12345678" not in saved
    with target.open(encoding="utf-8", newline="") as stream:
        row = next(csv.DictReader(stream))
    assert row["source"] == "user_labeled"
    assert row["channel"] == "email"
    assert row["label"] == "legitimate"


def test_capture_deduplicates_and_rejects_conflicting_labels(tmp_path):
    target = tmp_path / "user_labeled.csv"
    text = "Your weekly account statement is ready in the customer portal for review."
    assert append_labeled_message(text, "safe", "email", target)["status"] == "added"
    assert append_labeled_message(text, "safe", "email", target)["status"] == "duplicate"
    with pytest.raises(ValueError, match="different label"):
        append_labeled_message(text, "scam", "email", target)


def test_capture_rejects_non_english_and_invalid_channel(tmp_path):
    with pytest.raises(ValueError, match="English"):
        append_labeled_message("短いメッセージです", "safe", "email", tmp_path / "labels.csv")
    with pytest.raises(ValueError, match="email or SMS"):
        append_labeled_message("Your weekly account statement is ready for review.", "safe", "fax", tmp_path / "labels.csv")


def test_numeric_features_include_structured_metadata():
    msg = MessageInput(
        text="URGENT!!! Receipt 1234 https://example.org/account",
        sender="alerts@example.org",
        html='<a href="https://evil.example/login">https://example.org</a>',
        attachments=("invoice.pdf",),
        domain_age_days=10,
    )
    features = numeric_features(msg)
    assert features["url_count"] == 1
    assert features["link_text_domain_mismatch"] == 1
    assert features["sender_domain_age_bucket"] == 1
    assert features["uppercase_ratio"] > 0
    assert features["digit_ratio"] > 0
    assert features["has_attachment"] == 1
    assert features["exclamation_count"] == 3


def test_threshold_selection_reports_infeasible_target_instead_of_claiming_success():
    thresholds = choose_thresholds(
        ["safe"] * 20 + ["scam"] * 10,
        [0.4] * 19 + [0.9] + [0.3] * 8 + [0.8] * 2,
    )
    assert thresholds["constraints_met"] is False
    assert thresholds["validation_at_decision_threshold"]["false_positive_rate"] <= 0.02
