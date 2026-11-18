# 1. Problem statement, gap, scope and case studies

## Problem statement
Phishing emails and SMS messages remain one of the most common entry points for cyberattacks, yet most users have no reliable way to check whether a suspicious message is malicious. Existing spam filters usually return a binary flag with no reasoning, so users can't learn from them and have little reason to trust them.

## Research objective
Build and evaluate a web platform that (a) scores the phishing risk of an email or SMS and (b) explains the score in plain language, then study whether explanations improve user awareness and willingness to adopt AI-based security tools.

## Gap identified
| Existing approach | Limitation | How CPhishTank responds |
|---|---|---|
| Provider spam filters (Gmail, Outlook) | Opaque, binary; no explanation | Per-signal reasons and highlighted evidence |
| Blocklist services (PhishTank, Safe Browsing) | Cover only already-reported URLs; ignore message wording and sender | URL blocklists are *one* signal among many (wording, sender, link structure, ML) |
| Pure ML classifiers in papers | Black-box scores; rarely deployed to end users | Linear model with exact word-level attributions + rule engine; usable web app and extension |
| Awareness training (e.g. simulated phishing) | Teaches in advance, not at the moment of doubt | Explanations double as just-in-time education |
| Research on trust in AI security tools | Often separate from the tool itself | Built-in survey module linked to the same platform |

## Scope
**In scope:** email and SMS text; pasted text, `.eml`/`.txt` upload, browser extension (context menu, popup, Gmail button); 3-class verdict with risk score; explainability; URL checks (local rules, blocklist, optional WHOIS, redirects, Safe Browsing, VirusTotal); user accounts, history, personal dashboard; awareness survey with statistics; admin analytics.

**Out of scope:** blocking mail at the mail-server level; analysing attachment contents or images/QR codes; voice phishing; languages other than English (the model is trained on English text); guaranteeing detection.

## Case studies and prior work (to review and cite)
Verify each reference against the original before submitting; they are listed from memory of the literature.
1. **PhishTank** (community-verified phishing URL database): the standard open blocklist; relies on reports, so new campaigns slip through.
2. **Google Safe Browsing**: browser-level URL reputation; no message-level explanation.
3. Abu-Nimeh et al. (2007), *A comparison of machine learning techniques for phishing detection*: compares classifiers for phishing email; motivates ML + features.
4. Kumaraguru et al. (2007), *Protecting people from phishing: the design and evaluation of an embedded training email system*: shows in-context teaching works better than separate training, which motivates explanations at the moment of scanning.
5. Sheng et al. (2010), *Who falls for phish? A demographic analysis of phishing susceptibility*: demographic differences in susceptibility, which motivates the survey module.
6. Ribeiro, Singh & Guestrin (2016), *"Why should I trust you?" (LIME)* and Lundberg & Lee (2017), *A unified approach to interpreting model predictions (SHAP)*: the explainability techniques this project builds on.
7. Mohammad, Thabtah & McCluskey, *UCI Phishing Websites dataset*: URL/website feature data for extension work.
