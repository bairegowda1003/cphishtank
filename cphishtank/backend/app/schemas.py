from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field, model_validator

COMMON_PASSWORDS = {
    "password", "password1", "password123", "12345678", "123456789",
    "qwerty123", "qwertyuiop", "letmein123", "welcome123", "admin1234",
    "iloveyou", "abc12345", "11111111", "changeme123",
}


def validate_password_strength(value: str) -> str:
    if len(value) < 8:
        raise ValueError("Password must be at least 8 characters.")
    if value.strip().lower() in COMMON_PASSWORDS:
        raise ValueError("Choose a less common password.")
    return value


class RegisterIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    confirm_password: str = Field(min_length=8, max_length=128)
    accepted_terms: bool

    @model_validator(mode="after")
    def validate_registration(self):
        if not self.name.strip():
            raise ValueError("Name is required.")
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match.")
        validate_password_strength(self.password)
        if not self.accepted_terms:
            raise ValueError("You must accept the terms to register.")
        return self


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    remember_me: bool = False


class VerifyEmailIn(BaseModel):
    email: EmailStr
    otp: str = Field(pattern=r"^\d{6}$")


class EmailPurposeIn(BaseModel):
    email: EmailStr
    purpose: Literal["verify", "reset"] = "verify"


class ForgotPasswordIn(BaseModel):
    email: EmailStr


class ResetPasswordIn(BaseModel):
    email: EmailStr
    otp: str = Field(pattern=r"^\d{6}$")
    new_password: str = Field(min_length=8, max_length=128)
    confirm_password: str = Field(min_length=8, max_length=128)

    @model_validator(mode="after")
    def validate_new_password(self):
        if self.new_password != self.confirm_password:
            raise ValueError("Passwords do not match.")
        validate_password_strength(self.new_password)
        return self


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)
    confirm_password: str = Field(min_length=8, max_length=128)

    @model_validator(mode="after")
    def validate_new_password(self):
        if self.new_password != self.confirm_password:
            raise ValueError("Passwords do not match.")
        validate_password_strength(self.new_password)
        return self


class MessageOut(BaseModel):
    message: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    email: str
    is_admin: bool


class TokenOut(BaseModel):
    access_token: str
    user: UserOut


class ScanIn(BaseModel):
    text: str = Field(min_length=3, max_length=20000)
    sender: Optional[str] = Field(default=None, max_length=255)
    subject: Optional[str] = Field(default=None, max_length=500)
    channel: Literal["email", "sms"] = "email"
    save: bool = True


class FeedbackIn(BaseModel):
    feedback: Literal["correct", "incorrect"]


class LabeledMessageIn(BaseModel):
    text: str = Field(min_length=12, max_length=20000)
    label: Literal["safe", "scam"]
    channel: Literal["email", "sms"] = "email"
    confirmed_own_inbox: bool


class SurveyIn(BaseModel):
    age_group: Optional[str] = None
    occupation: Optional[str] = None
    tech_level: Optional[int] = Field(default=None, ge=1, le=5)
    received_phishing: Optional[bool] = None
    fell_for_it: Optional[bool] = None
    reports_phishing: Optional[bool] = None
    trust_ai: Optional[int] = Field(default=None, ge=1, le=5)
    would_adopt: Optional[int] = Field(default=None, ge=1, le=5)
    comments: Optional[str] = Field(default=None, max_length=2000)
    quiz_answers: dict[str, Literal["phishing", "legitimate"]] = {}
