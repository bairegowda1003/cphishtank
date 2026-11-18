import os
import tempfile
from datetime import timedelta
from uuid import uuid4

# isolate the test DB before the app is imported
_tmp = tempfile.mkdtemp()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["ADMIN_EMAILS"] = "admin@test.io"
os.environ["SECRET_KEY"] = "test-only-signing-key-not-for-deployments-12345"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.auth import hash_password  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import OtpCode, User, utcnow  # noqa: E402
from app.routers import auth as auth_router  # noqa: E402
from app.services.rate_limit import limiter  # noqa: E402
from app.services import heuristics as H  # noqa: E402

PHISH = ("From: PayPal Support <help@paypa1-alerts.com>\nSubject: Urgent\n\nDear customer, your account will be "
         "suspended within 24 hours. Verify your password at http://paypa1-secure-login.com/verify")
LEGIT = "Hi Priya, are we still meeting at 3pm tomorrow to review the project report? Draft is in the shared folder."


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def clear_rate_limits():
    limiter.reset()


def auth(client, email, name="T"):
    password = "StrongSafe-Passphrase8!"
    with SessionLocal() as db:
        user = User(email=email, name=name, password_hash=hash_password(password),
                    is_admin=email.lower() in os.environ["ADMIN_EMAILS"].split(","),
                    email_verified=True)
        db.add(user)
        db.commit()
        db.refresh(user)
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}, r.json()["user"]


# ---------------------------------------------------------------- heuristics
def test_lookalike_and_official():
    assert "lookalike" in {s["id"] for s in H.analyze_url("http://paypa1-secure-login.com")["signals"]}
    assert H.analyze_url("https://www.paypal.com/signin")["risk"] == 0
    assert H.analyze_url("https://accounts.google.com")["risk"] == 0


def test_negated_otp_is_not_credential_request():
    s, _ = H.analyze_content("Your OTP is 123456. Do not share this OTP with anyone.")
    assert "credential" not in {x["id"] for x in s}


def test_ip_and_shortener():
    ids = {s["id"] for s in H.analyze_url("http://203.0.113.9/login")["signals"]}
    assert "ip_host" in ids
    assert "shortener" in {s["id"] for s in H.analyze_url("https://bit.ly/abc123")["signals"]}


# ---------------------------------------------------------------- api
def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_scan_phishing_explained(client):
    r = client.post("/api/scan", json={"text": PHISH, "channel": "email"})
    d = r.json()
    assert r.status_code == 200 and d["label"] == "phishing" and d["risk_score"] >= 60
    ids = {s["id"] for s in d["signals"]}
    assert {"name_domain_mismatch", "urgency", "lookalike"} <= ids
    assert d["highlights"] and d["advice"] and d["urls"][0]["domain"] == "paypa1-secure-login.com"


def test_scan_legit(client):
    d = client.post("/api/scan", json={"text": LEGIT}).json()
    assert d["label"] == "legitimate" and d["risk_score"] < 30


def test_validation(client):
    assert client.post("/api/scan", json={"text": "x"}).status_code == 422
    assert client.post("/api/scan", json={"text": "hello world", "channel": "fax"}).status_code == 422


def test_upload_eml(client):
    eml = (b"From: Netflix <billing@netflix-update.click>\nSubject: Payment failed\nContent-Type: text/plain\n\n"
           b"Your payment failed. Update your payment method immediately: http://netflix-update.click/pay")
    r = client.post("/api/scan/upload", files={"file": ("m.eml", eml, "message/rfc822")}, data={"channel": "email"})
    assert r.status_code == 200 and r.json()["label"] in ("suspicious", "phishing")
    assert client.post("/api/scan/upload", files={"file": ("a.exe", b"MZ", "application/octet-stream")}).status_code == 415


def test_user_flow_history_and_privacy(client):
    h1, _ = auth(client, "a@test.io")
    h2, _ = auth(client, "b@test.io")
    sid = client.post("/api/scan", json={"text": PHISH}, headers=h1).json()["id"]
    assert sid
    assert client.get("/api/scans", headers=h1).json()["total"] == 1
    assert client.get(f"/api/scans/{sid}", headers=h1).status_code == 200
    assert client.get(f"/api/scans/{sid}", headers=h2).status_code == 404       # not someone else's scan
    assert client.patch(f"/api/scans/{sid}/feedback", json={"feedback": "correct"}, headers=h1).status_code == 200
    st = client.get("/api/scans/stats/me", headers=h1).json()
    assert st["threats_caught"] == 1 and st["labels"]["phishing"] == 1
    # save=false stores nothing
    n = client.get("/api/scans", headers=h1).json()["total"]
    client.post("/api/scan", json={"text": PHISH, "save": False}, headers=h1)
    assert client.get("/api/scans", headers=h1).json()["total"] == n
    assert client.delete(f"/api/scans/{sid}", headers=h1).status_code == 204


def test_auth_rules(client):
    assert client.get("/api/scans").status_code == 401
    r = client.post("/api/auth/login", json={"email": "a@test.io", "password": "wrongpass1"})
    assert r.status_code == 401
    assert client.post("/api/auth/register", json={
        "name": "x", "email": "a@test.io", "password": "StrongSafe-Passphrase8!",
        "confirm_password": "StrongSafe-Passphrase8!", "accepted_terms": True,
    }).status_code == 409


def _registration(email):
    return {
        "name": "New user",
        "email": email,
        "password": "StrongSafe-Passphrase8!",
        "confirm_password": "StrongSafe-Passphrase8!",
        "accepted_terms": True,
    }


def _capture_mail(monkeypatch):
    limiter.reset()
    sent = []
    monkeypatch.setattr(auth_router, "send_otp_email", lambda to, code, purpose: sent.append((to, code, purpose)))
    return sent


def test_registration_verification_login_and_reused_otp(client, monkeypatch):
    sent = _capture_mail(monkeypatch)
    email = f"{uuid4().hex}@test.io"
    registered = client.post("/api/auth/register", json=_registration(email))
    assert registered.status_code == 201 and "access_token" not in registered.json()
    assert len(sent) == 1 and sent[0][2] == "verify" and len(sent[0][1]) == 6
    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).one()
        assert not user.email_verified
    assert client.post("/api/auth/login", json={
        "email": email, "password": "StrongSafe-Passphrase8!",
    }).status_code == 403
    code = sent[0][1]
    wrong_code = f"{(int(code) + 1) % 1_000_000:06d}"
    wrong = client.post("/api/auth/verify-email", json={"email": email, "otp": wrong_code})
    assert wrong.status_code == 400
    verified = client.post("/api/auth/verify-email", json={"email": email, "otp": code})
    assert verified.status_code == 200
    assert client.post("/api/auth/verify-email", json={"email": email, "otp": code}).status_code == 400
    assert client.post("/api/auth/login", json={
        "email": email, "password": "StrongSafe-Passphrase8!",
    }).status_code == 200


def test_otp_expiry_and_five_attempt_limit(client, monkeypatch):
    sent = _capture_mail(monkeypatch)
    expired_email = f"{uuid4().hex}@test.io"
    assert client.post("/api/auth/register", json=_registration(expired_email)).status_code == 201
    with SessionLocal() as db:
        user = db.query(User).filter(User.email == expired_email).one()
        otp = db.query(OtpCode).filter(OtpCode.user_id == user.id).one()
        otp.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert client.post("/api/auth/verify-email", json={
        "email": expired_email, "otp": sent[-1][1],
    }).status_code == 400

    limited_email = f"{uuid4().hex}@test.io"
    assert client.post("/api/auth/register", json=_registration(limited_email)).status_code == 201
    code = sent[-1][1]
    wrong_code = "000000" if code != "000000" else "000001"
    for _ in range(5):
        assert client.post("/api/auth/verify-email", json={
            "email": limited_email, "otp": wrong_code,
        }).status_code == 400
    assert client.post("/api/auth/verify-email", json={"email": limited_email, "otp": code}).status_code == 400
    with SessionLocal() as db:
        user = db.query(User).filter(User.email == limited_email).one()
        otp = db.query(OtpCode).filter(OtpCode.user_id == user.id).one()
        assert otp.used and otp.attempts == 5


def test_forgot_reset_invalidates_old_tokens(client, monkeypatch):
    sent = _capture_mail(monkeypatch)
    email = f"{uuid4().hex}@test.io"
    headers, _ = auth(client, email)
    response = client.post("/api/auth/forgot-password", json={"email": email})
    assert response.status_code == 200
    assert response.json()["message"] == "If this email exists, an OTP was sent"
    assert sent[-1][2] == "reset"
    unknown = client.post("/api/auth/forgot-password", json={"email": f"{uuid4().hex}@test.io"})
    assert unknown.json() == response.json()
    reset_password = "Another-Strong-Passphrase9!"
    reset = client.post("/api/auth/reset-password", json={
        "email": email, "otp": sent[-1][1], "new_password": reset_password,
        "confirm_password": reset_password,
    })
    assert reset.status_code == 200
    assert client.get("/api/auth/me", headers=headers).status_code == 401
    assert client.post("/api/auth/login", json={"email": email, "password": reset_password}).status_code == 200


def test_otp_and_login_rate_limits(client, monkeypatch):
    sent = _capture_mail(monkeypatch)
    limiter.reset()
    email = f"{uuid4().hex}@test.io"
    for _ in range(5):
        assert client.post("/api/auth/forgot-password", json={"email": email}).status_code == 200
    assert client.post("/api/auth/forgot-password", json={"email": email}).status_code == 429
    assert not sent

    limiter.reset()
    monkeypatch.setattr(auth_router, "verify_password", lambda password, stored: False)
    login_email = f"{uuid4().hex}@test.io"
    for _ in range(10):
        assert client.post("/api/auth/login", json={
            "email": login_email, "password": "incorrect",
        }).status_code == 401
    limited = client.post("/api/auth/login", json={"email": login_email, "password": "incorrect"})
    assert limited.status_code == 429


def test_admin_and_survey(client):
    hu, _ = auth(client, "plain@test.io")
    ha, u = auth(client, "admin@test.io", "Admin")
    assert u["is_admin"] is True
    assert client.get("/api/admin/overview", headers=hu).status_code == 403
    denied = client.post("/api/admin/labeled-message", headers=hu, json={
        "text": "Your weekly account statement is available for review.",
        "label": "safe", "channel": "email", "confirmed_own_inbox": True,
    })
    assert denied.status_code == 403
    missing_confirmation = client.post("/api/admin/labeled-message", headers=ha, json={
        "text": "Your weekly account statement is available for review.",
        "label": "safe", "channel": "email", "confirmed_own_inbox": False,
    })
    assert missing_confirmation.status_code == 422
    q = client.get("/api/survey/questions").json()
    assert len(q["quiz"]) >= 5 and "answer" not in q["quiz"][0]
    for i in range(8):
        client.post("/api/survey", json={"age_group": "18-24", "tech_level": 1 + i % 5, "trust_ai": 1 + (i * 2) % 5,
                                         "would_adopt": 1 + (i * 2 + 1) % 5, "fell_for_it": i % 2 == 0,
                                         "received_phishing": True, "quiz_answers": {"q1": "phishing", "q2": "legitimate"}})
    res = client.post("/api/survey", json={"quiz_answers": {"q1": "phishing", "q2": "phishing"}}).json()
    assert res["quiz_score"] == 1
    ov = client.get("/api/admin/overview", headers=ha).json()
    assert ov["totals"]["scans"] >= 3 and "top_signals" in ov and ov["model"]["algorithm"]
    sv = client.get("/api/survey/stats", headers=ha).json()
    assert sv["n"] == 9 and sv["quiz_mean_pct"] > 0 and isinstance(sv["tests"], list)
