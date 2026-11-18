import logging
import smtplib
import ssl
from datetime import timedelta

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import schemas
from ..auth import (
    create_token_with_duration,
    get_current_user,
    hash_password,
    verify_password,
)
from ..config import settings
from ..database import get_db
from ..models import User
from ..services.mailer import send_otp_email
from ..services.otp import consume_otp, issue_otp
from ..services.rate_limit import limiter

router = APIRouter(prefix="/api/auth", tags=["auth"])
logger = logging.getLogger("cphishtank.auth")
GENERIC_OTP_MESSAGE = "If this email can receive a code, one was sent."
GENERIC_RESET_MESSAGE = "If this email exists, an OTP was sent"
INVALID_OTP_MESSAGE = "The code is invalid or expired. Request a new one and try again."
DUMMY_PASSWORD_HASH = hash_password("not-a-real-user-password")


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _limit(request: Request, email: str, action: str, maximum: int, window: int) -> None:
    keys = (f"{action}:email:{email}", f"{action}:ip:{_client_ip(request)}")
    if not limiter.allow(keys, maximum, window):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many attempts. Please wait a while and try again.",
        )


def _deliver_otp(recipient: str, code: str, purpose: str) -> None:
    if settings.DEV_MODE:
        print(f"[DEV_MODE] {purpose} OTP: {code}")
        return
    try:
        send_otp_email(recipient, code, purpose)
    except (smtplib.SMTPException, OSError, RuntimeError, ssl.SSLError):
        logger.error("OTP email delivery failed for purpose=%s.", purpose)


def _queue_otp(
    db: Session,
    user: User,
    purpose: str,
    recipient: str,
    background_tasks: BackgroundTasks,
) -> None:
    code = issue_otp(db, user, purpose)
    background_tasks.add_task(_deliver_otp, recipient, code, purpose)


@router.post("/register", response_model=schemas.MessageOut, status_code=status.HTTP_201_CREATED)
def register(
    body: schemas.RegisterIn,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    email = str(body.email).strip().lower()
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists.")
    _limit(request, email, "otp", 5, 60 * 60)
    user = User(
        email=email,
        name=body.name.strip(),
        password_hash=hash_password(body.password),
        is_admin=email in settings.ADMIN_EMAILS,
        email_verified=False,
    )
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists.") from exc
    _queue_otp(db, user, "verify", email, background_tasks)
    return {"message": "Account created. Check your email for a verification code."}


@router.post("/verify-email", response_model=schemas.MessageOut)
def verify_email(body: schemas.VerifyEmailIn, db: Session = Depends(get_db)):
    email = str(body.email).strip().lower()
    user = db.query(User).filter(User.email == email).first()
    if not user or user.email_verified or not consume_otp(db, user, "verify", body.otp):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, INVALID_OTP_MESSAGE)
    user.email_verified = True
    db.commit()
    return {"message": "Email verified. You can now sign in."}


@router.post("/resend-otp", response_model=schemas.MessageOut)
def resend_otp(
    body: schemas.EmailPurposeIn,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    email = str(body.email).strip().lower()
    _limit(request, email, "otp", 5, 60 * 60)
    user = db.query(User).filter(User.email == email).first()
    if user and (body.purpose == "reset" or not user.email_verified):
        _queue_otp(db, user, body.purpose, email, background_tasks)
    return {"message": GENERIC_OTP_MESSAGE}


@router.post("/login", response_model=schemas.TokenOut)
def login(body: schemas.LoginIn, request: Request, db: Session = Depends(get_db)):
    email = str(body.email).strip().lower()
    _limit(request, email, "login", 10, 15 * 60)
    user = db.query(User).filter(User.email == email).first()
    stored_hash = user.password_hash if user else DUMMY_PASSWORD_HASH
    password_matches = verify_password(body.password, stored_hash)
    if not user or not password_matches:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Email or password is incorrect.")
    if not user.email_verified:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Verify your email before signing in.")
    duration = (
        timedelta(days=settings.REMEMBER_TOKEN_EXPIRE_DAYS)
        if body.remember_me
        else timedelta(minutes=settings.TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": create_token_with_duration(user, duration), "user": user}


@router.post("/forgot-password", response_model=schemas.MessageOut)
def forgot_password(
    body: schemas.ForgotPasswordIn,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    email = str(body.email).strip().lower()
    _limit(request, email, "otp", 5, 60 * 60)
    user = db.query(User).filter(User.email == email).first()
    if user:
        _queue_otp(db, user, "reset", email, background_tasks)
    return {"message": GENERIC_RESET_MESSAGE}


@router.post("/reset-password", response_model=schemas.MessageOut)
def reset_password(body: schemas.ResetPasswordIn, db: Session = Depends(get_db)):
    email = str(body.email).strip().lower()
    user = db.query(User).filter(User.email == email).first()
    if not user or not consume_otp(db, user, "reset", body.otp):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, INVALID_OTP_MESSAGE)
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1
    db.commit()
    return {"message": "Password reset. Sign in with your new password."}


@router.post("/change-password", response_model=schemas.MessageOut)
def change_password(
    body: schemas.ChangePasswordIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect.")
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1
    db.commit()
    return {"message": "Password changed. Sign in again with your new password."}


@router.get("/me", response_model=schemas.UserOut)
def me(user: User = Depends(get_current_user)):
    return user
