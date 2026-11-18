# 5. Dataset: collection, cleaning and audit

Everything here is reproducible: `python -m pipeline.collect && python -m pipeline.clean && python -m app.ml.train` (run from `backend/`).
The cleaned dataset (`backend/data/clean/dataset.csv`) and the live domain feed ship with the project; the 1.7 GB of raw downloads do not.

## 5.1 Sources (all real, all public)
| Source | What | Raw | Used as | Notes / licence (verify before redistributing) |
|---|---|---|---|---|
| **phishing_pot** (rf-peixoto, GitHub) | Phishing/fraud emails from honeypot addresses, 2019-2026 | 12,271 | phishing, email | CC BY-NC 4.0, **non-commercial only**. Labels mean "malicious unsolicited mail", so some entries are fraud/spam rather than credential phishing |
| **Smishtank** (Timko & Rahman, arXiv 2402.18430) | Community-reported phishing SMS | 1,055 | phishing, SMS | Obtained through a GitHub mirror |
| **SpamAssassin public corpus** | 2002-2003 ham and spam email | 6,046 | legitimate / suspicious, email | Obtained via the `@stdlib/datasets-spam-assassin` npm package (CC0). Ham is **mailing-list traffic from 2002** |
| **UCI SMS Spam Collection** | Real SMS ham and spam | 5,574 | legitimate / suspicious, SMS | CC BY 4.0 |
| **NUS SMS Corpus** | Real chat SMS from Singapore | 55,801 | legitimate, SMS | Research use; sub-sampled to 5,000 |
| **SpamDam** (via the same GitHub mirror) | Large SMS set labelled "smish" | 76,577 | **external check only** | Labels are unverified (many are plain spam, most are not English), so it is never used for training |
| **Phishing.Database** (mitchellkrogza) | **Live feed**, about 386k active phishing domains, refreshed daily upstream | 386,074 | URL blocklist | Refresh any time: `python -m pipeline.collect --only phishing_domains --refresh` |
| Synthetic legit / BEC templates | Modern legitimate notifications; link-less gift-card/wire scams | 820 kept | training only, **never tested on** | Fills gaps no real source covers. Clearly tagged `synthetic_*` in the `source` column |
| User-labeled real-world messages | Messages the admin submits through the authenticated capture UI or `backend/scripts/add_labeled_message.py` | Not yet collected | training only, **never blind-tested** | Appended to `backend/data/clean/user_labeled.csv`; private inbox content is not a public dataset. Review and remove sensitive details before submission. |

Not reachable from the build environment (no internet beyond GitHub/npm/PyPI): Kaggle, PhishTank, OpenPhish, Mendeley. On a normal connection you can add them: drop CSVs with `text,label[,channel]` columns into `backend/data/raw/` and re-run `pipeline.clean`; or run `python -m app.ml.import_phishtank` for PhishTank domains.

No additional public dataset of modern legitimate email or legitimate linked SMS was added: the sources investigated did not meet the project's combined modernity, licensing, and privacy requirements. The user-labeled capture flow is the opt-in alternative; the training and blind-test files are kept separate.

> **Safety:** the dataset contains real phishing links and text. It is plain text, but never open the URLs.

## 5.2 Cleaning pipeline (`pipeline/clean.py`)
| Step | What it does | Why |
|---|---|---|
| Normalise | Unicode NFKC, HTML entities, zero-width / control characters, whitespace | Phishers hide text with invisible characters |
| Artifact removal | honeypot recipient (`phishing@pot`), mailing-list footers, quoted replies, signatures, `Re:`/`[list]` prefixes, corpus sanitiser strings, base64-like tokens, megabyte hash-busting padding, tracking-URL tails | Otherwise the model learns *which corpus* a message came from |
| PII masking | e-mail addresses to `user@example.com`, long phone numbers to `000-000-0000` | Privacy; the model's own normaliser masks them again |
| Length / quality | Drops empty, very short and mostly non-text messages | Image-only phishing has no text to learn from |
| English filter | Stop-word language ID across 8 languages | The model is English-only; 47% of phishing_pot was not English |
| ASCII-fold | Removes accents / emoji / symbols **after** language ID | 52% of phishing emails had non-ASCII characters versus 2% of 2002 ham: a character-set shortcut |
| Date sanity | Dates outside 2000-today blanked | Phishers forge `Date:` headers (one sample claimed 2033) |
| De-duplication | Exact (normalised) plus near-duplicate (MinHash, Jaccard 0.8) | Campaigns send thousands of near-identical emails; duplicates across train/test inflate scores |
| Label conflicts | Near-identical texts with different labels are dropped | Label noise |
| Down-sampling | NUS SMS capped at 5,000; synthetic legit at 700, BEC at 120 | Stop one source dominating |

Result: **19,292 messages** (13,457 legitimate, 1,720 suspicious, 4,115 phishing). The class-by-channel table and the full per-source cleaning funnel are in `backend/data/clean/report.md`.

## 5.3 Audit: what the data can and cannot teach
The audit found, and the cleaning fixed or reduced, several **shortcuts**. What remains:

1. **Legitimate email is dominated by 2002 tech-mailing-list traffic** (top tokens: `linux`, `perl`, `razor`, `yahoo groups`). Modern notifications, invoices and newsletters can look unfamiliar and be over-flagged. The legacy model includes 700 synthetic modern-legit messages; these are not a substitute for real messages. User-labeled capture is available, but no user examples have been collected for this evaluation.
2. **Real ham SMS contains no links** (0.0% versus 50% of smishing), so "has a link" is a strong, unrealistic cue. Same mitigation.
3. **Structure alone predicts a lot.** Gradient boosting on length, line count, URL count, capitals and digits reaches 0.68 (email) and 0.85 (SMS) balanced accuracy without reading any words. Random-split scores therefore flatter the model, and harsher evaluations are reported below.
4. **"Suspicious" vs "phishing" is partly defined by corpus** (old spam versus modern honeypot mail), so the exact 3-class label is less trustworthy than the risky-vs-safe split.

## 5.4 Legacy model results (baseline, not the upgraded pipeline)

The following are measured results for the shipped three-class TF-IDF + LogisticRegression baseline only. They are not results for the binary calibrated model, numeric features, learned fusion, or a modern blind set.

| Evaluation | Result |
|---|---|
| Random 80/20 split (de-duplicated, real data only) | 97.3% accuracy, macro-F1 0.956; risky-vs-safe F1 0.965, AUC 0.993, false-alarm rate 1.3%. **Optimistic** (see 5.3 point 3) |
| **Temporal**: train on phishing_pot up to 2026-05-17, test on the 639 newest emails | **86.4%** flagged risky (85.6% exact label), 1.3% false alarms on legitimate mail |
| **Leave-one-source-out**: unseen phishing_pot emails | 84.9% flagged risky |
| Leave-one-source-out: unseen Smishtank SMS | 79.8% flagged risky |
| Leave-one-source-out: unseen real ham SMS (UCI, NUS) | 98.7% / 99.2% correctly legitimate |
| Leave-one-source-out: SpamAssassin | **Not interpretable**: it is the only source of legitimate and spam *email*, so removing it removes those classes |
| External SpamDam SMS (labels unverified) | 81.1% flagged risky |
| Hand-written development set (24, rules tuned on it) | 24/24, **optimistic** |
| **Hand-written blind set (32, written after freezing the system)** | **30/32 = 93.8%**: 0 missed risky, 2 false alarms (Swiggy and Spotify notices; those brands are not in the 35-brand official-domain list). ML-only 81.2%, rules-only 81.2% |

For this legacy baseline, the temporal evaluation reports 86% recall on newer phishing and about 1% false alarms on the available legitimate data. Its 32-message blind set is too small to meet the requested 100-message evaluation and was written by the system author; do not treat it as the new frozen blind set.

## 5.5 Upgrade evaluation status

The upgraded training and inference path is under development and has not produced validated after-change metrics. Training requires a separately frozen blind set of at least 100 hand-labeled, modern messages. The existing 32-message set does not satisfy this gate. Until that set is collected and frozen, report after-change metrics as **not measured**, not as zero and not as inherited from the legacy model. See `model_evaluation.md` for the evaluation protocol and current status.

## 5.6 Live feed and the URL checker
`data/feeds/phishing_domains.txt` is loaded together with the hand-kept `blocklist.txt` and reloads automatically when the file changes. Registered domains of shared hosts (`netlify.app`, `sites.google.com`, `github.io`, ...) are never blocked wholesale, only the exact bad sub-domains the feed lists. Schedule a refresh, for example in cron:
```
0 3 * * *  cd /path/to/backend && python -m pipeline.collect --only phishing_domains --refresh
```
