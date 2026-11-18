import hashlib
import hmac
import os
from datetime import timedelta

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import User, utcnow

bearer = HTTPBearer(auto_error=False)
ITERATIONS = 200_000


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt_hex, hash_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), ITERATIONS)
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def create_token(user: User) -> str:
    return create_token_with_duration(user, timedelta(minutes=settings.TOKEN_EXPIRE_MINUTES))


def create_token_with_duration(user: User, duration: timedelta) -> str:
    exp = utcnow() + duration
    return jwt.encode(
        {"sub": str(user.id), "exp": exp, "ver": user.token_version},
        settings.SECRET_KEY,
        algorithm="HS256",
    )


def _user_from_creds(creds, db: Session):
    if not creds:
        return None
    try:
        payload = jwt.decode(creds.credentials, settings.SECRET_KEY, algorithms=["HS256"])
        user = db.get(User, int(payload["sub"]))
    except (jwt.PyJWTError, KeyError, TypeError, ValueError):
        return None
    if user is None or payload.get("ver", 0) != user.token_version:
        return None
    return user


def get_optional_user(creds: HTTPAuthorizationCredentials = Depends(bearer),
                      db: Session = Depends(get_db)):
    return _user_from_creds(creds, db)


def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer),
                     db: Session = Depends(get_db)) -> User:
    user = _user_from_creds(creds, db)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in to continue.")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin access only.")
    return user
