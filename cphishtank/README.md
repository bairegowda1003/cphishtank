# CPhishTank: explainable phishing detection

Paste an email or SMS (or upload a `.eml`) and get a **risk score plus the exact words, links and sender details that raised suspicion**. Combines a TF-IDF + logistic-regression classifier with a rule engine (sender, wording, URL analysis, optional WHOIS / Safe Browsing / VirusTotal). Includes accounts and history, a personal "threats caught" dashboard, an admin analytics dashboard, a phishing-awareness survey with statistical analysis, and a Chrome extension.

## Quick start
```bash
# terminal 1: backend  (http://localhost:8000/docs)
cd backend && python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt && cp .env.example .env
uvicorn app.main:app --reload --port 8000

# terminal 2: frontend (http://localhost:5173)
cd frontend && npm install && npm run dev
```
Register with the email in `ADMIN_EMAILS` (default `admin@example.com`) to get the admin dashboard. A legacy trained model is included. The new calibrated model is deliberately not generated until a 100+ message blind set has been labelled and frozen; see `docs/05_dataset.md`. Or run everything with `docker compose up --build` (web app on port 8080).

## Project map (your notebook's 7 steps)
| Step | Deliverable | Where |
|---|---|---|
| 1. Problem statement, gap, scope, case studies | `docs/01_problem_statement.md` |
| 2. SRS, tools, datasets/APIs, ER diagram, modules | `docs/02_SRS.md` |
| 3. Environment setup (backend + frontend + DB) | `docs/03_environment_setup.md`, `docker-compose.yml`, `.env.example` |
| 4. Core modules | `backend/app/services/{analyzer,heuristics,url_checker}.py`, `routers/`, `frontend/src/pages/` |
| 5. Main module (ML) | `backend/app/ml/`, `backend/app/services/ml.py` |
| 6. Analytics dashboard and visualisation | `frontend/src/pages/{Dashboard,Admin}.jsx`, `routers/admin.py`, `routers/survey.py` |
| 4-5. Real data collection + cleaning | `docs/05_dataset.md`, `backend/pipeline/` |
| 7. Report and deployment | `docs/04_project_report.md`, `Dockerfile`s, `docker-compose.yml` |

## Layout
```
backend/   FastAPI app, ML pipeline, tests         (python -m pytest -q tests, 16 tests)
frontend/  React + Vite web app
extension/ Chrome MV3 extension (load unpacked)
docs/      problem statement, SRS + ER diagram, setup guide, report
```

## Real data (already included)
The shipped legacy model is trained on 19,292 cleaned rows across public corpora and a tagged synthetic patch. Its evaluation is not the new binary/calibrated evaluation. The project still has a public-source gap: modern real legitimate email and legitimate SMS with links. No source found that both fills that gap and has clear redistribution/privacy terms, so admin users can add sanitized examples from their own inbox. The URL checker uses the existing live feed of phishing domains. Rebuild or refresh public sources (needs internet):
```bash
cd backend
python -m pipeline.collect          # download + convert (phishing_pot alone is ~1 GB)
python -m pipeline.clean            # clean, de-duplicate, audit -> data/clean/{dataset.csv,report.md}
python -m app.ml.train              # retrain + evaluate -> models/metrics.json
python -m pipeline.collect --only phishing_domains --refresh   # refresh the live blocklist only
```

Admin users can paste a message in **Threat overview → Add a message for training**. Only cleaned text is stored in the git-ignored `backend/data/clean/user_labeled.csv`; `pipeline.clean` deduplicates it, enforces English, masks common PII and ASCII-folds it. The CLI alternative reads message content from standard input (not command-line arguments):
```bash
cd backend
python -m scripts.add_labeled_message --label safe --channel email < message.txt
```

Before any tuned model run, prepare at least 100 hand-labelled, modern messages in `backend/data/clean/blind_test.csv` with columns `text,label,channel` (`safe|scam`, `email|sms`). These must be held out from training, varied across the requested scenarios, and frozen with `python -m scripts.freeze_blind_test`. The freeze command sanitizes and checks for overlap. Details, license notes, the baseline-vs-after table, and remaining gaps are in `docs/05_dataset.md` and `docs/model_evaluation.md`.

## Quick API test
```bash
curl -s localhost:8000/api/scan -H 'content-type: application/json' \
  -d '{"text":"Urgent: verify your password at http://paypa1-login.top or your account will be suspended in 24 hours","channel":"sms"}'
```
