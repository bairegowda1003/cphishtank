Drop real datasets here as CSV files and re-run `python -m app.ml.train`.

Each file needs a text column (text / body / message / email text / v2) and a label column
(label / class / category / email type / v1). Accepted labels:
  legitimate | ham | safe email   -> legitimate
  suspicious | spam               -> suspicious
  phishing | phishing email       -> phishing

Suggested sources: Kaggle "Phishing Email Dataset", Kaggle "SMS Spam Collection",
Nazario phishing corpus. For URL data see PhishTank (python -m app.ml.import_phishtank).
