from datetime import datetime, timezone
from sqlalchemy import JSON, Boolean, CheckConstraint, Column, DateTime, Float, ForeignKey, Index, Integer, String, Text, text, true
from sqlalchemy.orm import relationship
from .database import Base


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    name = Column(String(120), nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    email_verified = Column(Boolean, default=True, server_default=true(), nullable=False)
    token_version = Column(Integer, default=0, server_default="0", nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    surveys = relationship("SurveyResponse", back_populates="user")
    otp_codes = relationship("OtpCode", back_populates="user", cascade="all, delete-orphan")


class OtpCode(Base):
    __tablename__ = "otp_codes"
    __table_args__ = (
        CheckConstraint("purpose IN ('verify', 'reset')", name="ck_otp_purpose"),
        CheckConstraint("attempts >= 0", name="ck_otp_attempts"),
        Index(
            "uq_otp_active_user_purpose",
            "user_id",
            "purpose",
            unique=True,
            sqlite_where=text("used = 0"),
            postgresql_where=text("used = false"),
        ),
    )
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    purpose = Column(String(10), nullable=False, index=True)
    code_hash = Column(String(64), nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    attempts = Column(Integer, default=0, nullable=False)
    used = Column(Boolean, default=False, nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    user = relationship("User", back_populates="otp_codes")


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    channel = Column(String(10), nullable=False, default="email")     # email | sms
    sender = Column(String(255))
    subject = Column(String(500))
    text_excerpt = Column(Text, nullable=False)
    label = Column(String(15), nullable=False, index=True)             # legitimate | suspicious | phishing
    risk_score = Column(Float, nullable=False)                         # 0-100
    confidence = Column(Float, nullable=False)                         # 0-1 (ML class probability)
    result = Column(JSON, nullable=False)                              # full explanation payload
    user_feedback = Column(String(10))                                 # correct | incorrect
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)

    user = relationship("User", back_populates="scans")
    urls = relationship("ScanUrl", back_populates="scan", cascade="all, delete-orphan")


class ScanUrl(Base):
    """One row per URL found in a scan; powers 'most common malicious domains'."""
    __tablename__ = "scan_urls"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(Text, nullable=False)
    domain = Column(String(255), index=True)
    risk = Column(Float, nullable=False, default=0.0)

    scan = relationship("Scan", back_populates="urls")


class SurveyResponse(Base):
    __tablename__ = "survey_responses"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    age_group = Column(String(20))
    occupation = Column(String(60))
    tech_level = Column(Integer)             # 1-5 self-rated
    received_phishing = Column(Boolean)
    fell_for_it = Column(Boolean)
    reports_phishing = Column(Boolean)
    quiz_score = Column(Integer, nullable=False)   # 0..quiz_total
    quiz_total = Column(Integer, nullable=False)
    trust_ai = Column(Integer)               # 1-5 Likert
    would_adopt = Column(Integer)            # 1-5 Likert
    comments = Column(Text)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    user = relationship("User", back_populates="surveys")
