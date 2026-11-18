import hashlib
import hmac
import secrets
from datetime import timedelta

from sqlalchemy.orm import Session

from ..config import settings
from ..models import OtpCode, User, utcnow

OTP_TTL_MINUTES = 10
MAX_OTP_ATTEMPTS = 5


def _code_hash(user_id: int, purpose: str, code: str) -> str:
    message = f"{user_id}:{purpose}:{code}".encode("utf-8")
    return hmac.new(settings.SECRET_KEY.encode("utf-8"), message, hashlib.sha256).hexdigest()


def issue_otp(db: Session, user: User, purpose: str) -> str:
    if purpose not in {"verify", "reset"}:
        raise ValueError("Unsupported OTP purpose.")
    db.query(OtpCode).filter(
        OtpCode.user_id == user.id,
        OtpCode.purpose == purpose,
        OtpCode.used.is_(False),
    ).update({"used": True}, synchronize_session=False)
    code = f"{secrets.randbelow(1_000_000):06d}"
    db.add(OtpCode(
        user_id=user.id,
        purpose=purpose,
        code_hash=_code_hash(user.id, purpose, code),
        expires_at=utcnow() + timedelta(minutes=OTP_TTL_MINUTES),
    ))
    db.commit()
    return code


def consume_otp(db: Session, user: User, purpose: str, code: str) -> bool:
    otp = (db.query(OtpCode)
           .filter(OtpCode.user_id == user.id, OtpCode.purpose == purpose, OtpCode.used.is_(False))
           .order_by(OtpCode.created_at.desc(), OtpCode.id.desc())
           .with_for_update()
           .first())
    if otp is None:
        return False
    if otp.expires_at <= utcnow() or otp.attempts >= MAX_OTP_ATTEMPTS:
        otp.used = True
        db.commit()
        return False
    matches = hmac.compare_digest(otp.code_hash, _code_hash(user.id, purpose, code))
    if not matches:
        otp.attempts += 1
        if otp.attempts >= MAX_OTP_ATTEMPTS:
            otp.used = True
        db.commit()
        return False
    otp.used = True
    db.commit()
    return True
