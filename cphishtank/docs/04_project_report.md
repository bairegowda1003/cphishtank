# CPhishTank: Explainable Phishing Detection for Email and SMS
*Final project report*

## Abstract
CPhishTank is a web platform and browser extension that gives users an instant phishing risk score for an email or SMS together with a plain-language explanation of what triggered suspicion: urgency language, mismatched sender domains, look-alike links, requests for credentials. It fuses a TF-IDF + logistic-regression text classifier with a rule engine (sender, content and URL analysis, optional WHOIS / redirect / Safe Browsing / VirusTotal checks). Because the classifier is linear, its word-level explanations are exact. A built-in awareness survey, with statistical analysis, supports a research question on user trust in AI security tools.

## 1. Introduction and problem
Phishing remains a leading entry point for cyberattacks, yet spam filters give users a binary flag with no reasons. Users therefore neither learn to recognise attacks nor have grounds to trust the tool. See `01_problem_statement.md` for the gap analysis and scope.

**Objectives**
1. Score the risk of an email or SMS and classify it as legitimate, suspicious or phishing.
2. Explain every verdict with specific, human-readable evidence highlighted in the message.
3. Provide history, a personal "threats caught" dashboard and an admin view of aggregate patterns.
4. Collect survey data on phishing awareness and attitudes toward AI tools, with statistical analysis.

## 2. Related work
See the reading list in `01_problem_statement.md` (PhishTank, Safe Browsing, Abu-Nimeh et al., Kumaraguru et al., Sheng et al., LIME, SHAP, the UCI Phishing Websites dataset). Citations should be verified against the originals before submission.

## 3. System design
Architecture, ER diagram, requirements and module breakdown are in `02_SRS.md`. In short:

- **Input:** pasted text with automatic header parsing, `.eml` and `.txt` upload (including HTML anchor extraction), browser extension.
- **Rule engine:** about 35 named signals across sender, content and URL. Signals are probabilities merged by noisy-OR, giving a bounded score with diminishing returns.
- **ML model:** text is normalised (URLs replaced by tokens that keep their risk cues such as `urlfake`; numbers and addresses masked), vectorised with word 1-2-gram TF-IDF, and classified by multinomial logistic regression with balanced class weights.
- **Explainability:** per-signal explanations; highlighted spans in the original text; and per-n-gram contributions `(coef[phishing] - coef[legitimate]) x tfidf`, which equal the SHAP values of a linear model.
- **Fusion:** `risk = 0.5 x ML + 0.5 x rules`, with overrides for blocklist/Safe Browsing hits (at least 92) and strong rule scores. Thresholds: under 30 legitimate, 30-59 suspicious, 60 and above phishing.
- **Analytics:** per-user and admin dashboards; survey statistics (descriptives, Spearman correlation, Mann-Whitney U).

## 4. Implementation
Python 3.12, FastAPI, SQLAlchemy (SQLite/PostgreSQL), scikit-learn, React 18 + Vite, Chart.js, Chrome Manifest V3. See `03_environment_setup.md` for setup. Notable design decisions:

- **Real data pipeline.** Reproducible collection and cleaning with an explicit shortcut audit (`05_dataset.md`).
- **A linear model instead of BERT.** It trains in seconds, runs on any laptop, and gives exact explanations. A transformer would likely generalise better on real data but needs SHAP/LIME approximations and a GPU for practical training. The pipeline (`normalize` then `predict_proba`) is isolated in `services/ml.py`, so swapping the model is a local change.
- **Rules are first-class.** Look-alike domains, sender mismatches and shorteners are cheap to detect deterministically, are explainable by construction, and don't depend on training data.
- **Fail-open network checks.** WHOIS, redirects and API lookups are optional with 5 s timeouts so a slow service never blocks a scan.
- **Negation handling.** "Do not share your OTP" is a warning, not a credential request, so such matches are suppressed.

## 5. Evaluation

### 5.1 Data
The classifier is trained on **19,292 real, cleaned messages**: phishing emails (phishing_pot), phishing SMS (Smishtank), legitimate and spam email (SpamAssassin), and legitimate and spam SMS (UCI, NUS). A small synthetic patch (820 messages) covers modern legitimate notifications and link-less scams; it is never used for testing. Collection, cleaning steps, the shortcut audit and licences are in `05_dataset.md`.

### 5.2 Classifier results (real data)
| Evaluation | Result |
|---|---|
| Random 80/20 split, de-duplicated | 97.3% accuracy, macro-F1 0.956, risky-vs-safe F1 0.965, AUC 0.993, 1.3% false alarms. **Optimistic**: sources differ in style and era, and structural features alone reach 0.68 (email) / 0.85 (SMS) balanced accuracy |
| Temporal: train on older phishing emails, test on the 639 newest | **86.4%** flagged risky, 1.3% false alarms |
| Leave-one-source-out | unseen phishing_pot 84.9% and Smishtank 79.8% flagged risky; unseen real ham SMS 98.7-99.2% correctly legitimate |
| External SpamDam SMS (unverified labels) | 81.1% flagged risky |

Random-split three-class confusion matrix (rows = true, columns = predicted: legitimate, suspicious, phishing): legitimate 2519 / 15 / 17; suspicious 14 / 320 / 10; phishing 33 / 10 / 757.

**Reading the numbers.** The distinction between "suspicious" and "phishing" is partly defined by which corpus a message came from (old spam versus modern honeypot mail), so exact three-class labels are less reliable than the risky-versus-safe decision. Under leave-one-source-out only 39% of unseen phishing_pot emails received the exact label "phishing", though 85% were flagged risky.

### 5.3 End-to-end checks on hand-written messages
| Set | Fused system | ML only | Rules only |
|---|---|---|---|
| Development (24; the reassurance rule was tuned on it) | 24/24 | 87.5% | 87.5% |
| **Blind (32; written after the system was frozen)** | **30/32 = 93.8%** | 81.2% | 81.2% |

On the blind set there were no missed risky messages and two false alarms (Swiggy and Spotify notices; their brands are not in the 35-brand list used to recognise official domains). Fusing ML and rules beats either alone. Caveat: the author of the system wrote both sets, and 32 messages is small.

### 5.4 Software testing
16 automated tests pass: rule behaviour, scan correctness and explanations, validation, `.eml` upload, per-user data isolation, feedback, `save=false`, admin authorisation, survey scoring and statistics, and the data pipeline (language filter, artifact and PII removal, ASCII folding, near-duplicate keys, live-feed loading and the shared-host guard). The UI was exercised in a browser at desktop and phone widths.

### 5.5 Upgrade status (not yet validated)
The project now has an admin-only, privacy-conscious real-message capture path and an in-progress binary-model/fusion upgrade. These changes have not yet produced validated after-change metrics. The legacy results above describe the prior three-class baseline only. A frozen blind set of at least 100 modern hand-labeled messages is required before training/evaluation can produce the requested blind metrics; the existing 32-message set is insufficient. Do not interpret baseline measurements as upgrade results. See `model_evaluation.md`.

## 6. Limitations
1. **Legitimate email training data is 2002 mailing-list traffic.** Modern legitimate mail can look unfamiliar and be over-flagged. This was visible when training on real data first made the hand-written development check worse (70.8%) than the earlier synthetic-trained model (100%, which was circular). Mitigations: synthetic modern-legit patch and a reassurance rule. A modern real legitimate-email corpus is the most valuable missing input.
2. Real ham SMS contains no links, so link presence is an exaggerated cue. Same mitigations.
3. phishing_pot labels mean "malicious unsolicited mail"; some entries are fraud or spam rather than credential phishing.
4. English only. No image, QR-code or attachment-content analysis.
5. Rule weights and the 35-brand official-domain list are hand-set.
6. The Gmail integration depends on Gmail's current page structure.
7. Survey statistics need a real sample; results from a convenience sample cannot be generalised.
8. Live WHOIS / Safe Browsing / VirusTotal checks, Docker deployment and the browser extension were implemented but not exercised in the build environment. PhishTank, OpenPhish and Kaggle were unreachable from it.

## 7. Future work
Transformer classifier (DistilBERT) behind the same interface with SHAP; URL-feature model on the UCI Phishing Websites dataset; user-feedback loop that feeds corrected labels into retraining; multilingual support; QR-code and image analysis; Outlook/Thunderbird add-ins; rate limiting and audit logging for production.

## 8. Conclusion
The project delivers an end-to-end, explainable phishing checker trained on real, cleaned data: a fused ML + rules engine, highlighted evidence, user and admin analytics, a browser extension, and a research survey module. Its main weakness is the lack of modern real legitimate email in the training data. The architecture is built so that adding data or a stronger model does not change the rest of the system.

## References
See `01_problem_statement.md`.
