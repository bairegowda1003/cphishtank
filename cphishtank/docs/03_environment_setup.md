# 3. Environment setup: connecting backend, frontend and database

## Option A: local development (SQLite, no Docker)
Requirements: Python 3.11+ and Node 18+.

```bash
# 1. Backend
cd backend
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                   # set SECRET_KEY and ADMIN_EMAILS
python -m app.ml.train                                 # optional: the API trains a starter model on first start
uvicorn app.main:app --reload --port 8000              # API docs: http://localhost:8000/docs

# 2. Frontend (second terminal)
cd frontend
npm install
npm run dev                                            # http://localhost:5173
```
How the pieces connect:
- **Frontend to backend:** Vite proxies `/api` to `127.0.0.1:8000` (`vite.config.js`), so the browser sees one origin and no CORS setup is needed in development. For a separately hosted frontend, set `VITE_API_URL` and add the site to `CORS_ORIGINS`.
- **Backend to database:** `DATABASE_URL` in `.env`. Tables are created automatically on startup (`Base.metadata.create_all`).
- **Admin access:** register with an email listed in `ADMIN_EMAILS`; that account becomes admin.

## Option B: PostgreSQL
```bash
docker run -d --name cpt-db -e POSTGRES_USER=phish -e POSTGRES_PASSWORD=phish \
  -e POSTGRES_DB=cphishtank -p 5432:5432 postgres:16-alpine
# in backend/.env
DATABASE_URL=postgresql+psycopg2://phish:phish@localhost:5432/cphishtank
```
Restart the backend; no code change is needed. (Use Alembic migrations if you later change the schema on a live database.)

## Option C: everything in Docker
```bash
SECRET_KEY=$(openssl rand -hex 32) docker compose up --build
# web app: http://localhost:8080      API: http://localhost:8000/docs
```
Nginx serves the built React app and proxies `/api` to the backend; the backend talks to Postgres over the Compose network.

## Optional integrations
| Feature | Setting in `backend/.env` |
|---|---|
| WHOIS domain age | `ENABLE_WHOIS=true` |
| Redirect-chain check | `ENABLE_REDIRECT_CHECK=true` |
| Google Safe Browsing | `GOOGLE_SAFE_BROWSING_KEY=...` |
| VirusTotal | `VIRUSTOTAL_API_KEY=...` |
| PhishTank blocklist | `python -m app.ml.import_phishtank` |
| Real training data | `python -m pipeline.collect && python -m pipeline.clean && python -m app.ml.train`, or add your own CSVs to `backend/data/raw/` first |
| Refresh live phishing-domain feed | `python -m pipeline.collect --only phishing_domains --refresh` |

## Browser extension
1. Chrome to `chrome://extensions`, enable Developer mode, **Load unpacked**, choose the `extension/` folder.
2. Keep the backend running. Right-click selected text and choose **Check with CPhishTank**, click the toolbar icon, or open an email in Gmail and use the **Check with CPhishTank** button above the message.
3. Different server address: extension **Settings** page.

Gmail's page structure changes often; if the inline button stops appearing, update the selectors at the top of `extension/gmail.js`.

## Running the tests
```bash
cd backend
python -m pytest -q tests              # 16 API, rules and data-pipeline tests
python -m tests.eval_handwritten       # dev set (24) and blind set (32) of hand-written messages
```
