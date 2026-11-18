# Model evaluation and upgrade status

## Status

The measurements in `backend/models/metrics.json` are the **legacy three-class baseline**. They are not measurements of the in-progress binary safe/scam model, calibrated probabilities, numeric features, or learned fusion.

The upgraded pipeline has no validated before/after comparison yet. `backend/models/metrics.json` records its after metrics as `null`. The existing 32-message hand-written set is too small to serve as the required blind set. Do not tune against it or report it as the new blind evaluation.

## Before/after snapshot

These are the available legacy random-split binary metrics versus the current upgrade status. They are **not a matched evaluation**: the legacy metrics are retained from an older three-class model and split. Upgrade values remain unmeasured pending the frozen blind set and a validated training run.

| Metric | Legacy baseline | Upgraded pipeline |
|---|---:|---|
| Precision | 0.9717 | Not measured |
| Recall | 0.9589 | Not measured |
| F1 | 0.9652 | Not measured |
| False-alarm rate on safe mail | 0.0125 (1.25%) | Not measured |
| ROC-AUC | 0.9931 | Not measured |
| Confusion matrix (safe/scam; rows=true, columns=predicted) | `[[2519, 32], [47, 1097]]` | Not measured |

Other legacy-only checks: temporal phishing recall was 0.8638 with a 0.0129 safe-mail false-positive rate; leave-one-source-out risky recall was 0.8495 for phishing_pot and 0.7982 for Smishtank. Full details and caveats are in `05_dataset.md`. These cannot be presented as after-change results.

## Blind-set freeze procedure

1. Prepare at least 100 distinct, manually labeled modern messages, including safe service notices, receipts, OTPs, newsletters and work/personal mail, plus scam messages such as bank/KYC/UPI, delivery, job, gift-card and wire fraud.
2. Use only messages the submitter is authorized to share. Remove personal and secret content before saving. Keep the resulting CSV at `backend/data/clean/blind_test.csv`; it is excluded from training.
3. Freeze the finalized file before tuning by running `python -m scripts.freeze_blind_test` from `backend/`. The script checks the minimum count, labels, duplicates and overlap, then writes `data/clean/blind_test.freeze.json`.
4. Do not edit the frozen file after tuning begins. If it must change, create a new blind set and freeze it before continuing. Training refuses to treat an absent or invalid freeze record as a valid blind evaluation.

User captures in `backend/data/clean/user_labeled.csv` are training candidates, not blind examples. Never move a blind example into training.

## Required reporting

For baseline and upgraded model, report evaluation set and sample counts, precision, recall, F1, false-alarm rate on safe examples, ROC-AUC, and confusion matrix. Keep separate results for:

- Temporal phishing_pot test: train on older samples, test on the newest samples.
- Leave-one-source-out evaluation, identifying each held-out source.
- The frozen modern blind set, untouched during fitting and threshold selection.

Also report calibration quality and the selected operating threshold. The desired operating point is safe-mail false alarms at or below 2% while scam recall is at least 90%; if the held-out validation data cannot satisfy both, report that plainly rather than claiming the target.

Threshold selection and fusion stacking belong on validation data only. Do not use any of the evaluation sets to select features, models, or thresholds. Compare confusion matrices and headline metrics against the baseline under matching data and split definitions wherever possible.

## Current known weaknesses

- Genuine email training data is dominated by old mailing-list content; user capture has not yet supplied modern examples.
- Existing legitimate SMS data has no links, making link presence a source shortcut.
- The prior blind set has only 32 messages and is author-written.
- Sender-domain age, attachments, and HTML link/text mismatch are not reliably populated for all corpus rows.
- No DistilBERT fine-tuning has been validated; the environment used for this work did not have an available GPU.
- Automatic privacy masking cannot reliably remove names, account details, or all contextual personal information; captured messages require human review.
