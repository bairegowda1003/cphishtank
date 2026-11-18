import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


class Settings:
    DEV_MODE = _bool("DEV_MODE")
    DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'cphishtank.db'}")
    SECRET_KEY = os.getenv("SECRET_KEY", "").strip()
    if not SECRET_KEY or "change-me" in SECRET_KEY.lower() or len(SECRET_KEY) < 32:
        if not DEV_MODE:
            raise RuntimeError("Set SECRET_KEY to a random value of at least 32 characters in backend/.env.")
        SECRET_KEY = "local-development-only-secret-not-for-production"
    TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES", "720"))
    REMEMBER_TOKEN_EXPIRE_DAYS = int(os.getenv("REMEMBER_TOKEN_EXPIRE_DAYS", "30"))
    ADMIN_EMAILS = {e.strip().lower() for e in os.getenv("ADMIN_EMAILS", "").split(",") if e.strip()}
    CORS_ORIGINS = [o.strip() for o in os.getenv(
        "CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",") if o.strip()]
    ENABLE_WHOIS = _bool("ENABLE_WHOIS")
    ENABLE_REDIRECT_CHECK = _bool("ENABLE_REDIRECT_CHECK")
    GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    MODEL_PATH = BASE_DIR / "models" / "phish_model.joblib"
    METRICS_PATH = BASE_DIR / "models" / "metrics.json"
    BLOCKLIST_PATH = BASE_DIR / "data" / "blocklist.txt"
    RAW_DATA_DIR = BASE_DIR / "data" / "raw"
    USER_LABELED_PATH = BASE_DIR / "data" / "clean" / "user_labeled.csv"
    SMTP_HOST = os.getenv("SMTP_HOST", "").strip() or "smtp.gmail.com"
    SMTP_PORT = int(os.getenv("SMTP_PORT", "").strip() or "465")
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_APP_PASSWORD = os.getenv("SMTP_APP_PASSWORD", "")
    MAIL_FROM_NAME = os.getenv("MAIL_FROM_NAME", "").strip() or "CPhishTank"
    MAX_TEXT_CHARS = 20000


settings = Settings()
