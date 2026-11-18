import html
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr

from ..config import settings

APP_NAME = "CPhishTank"


def _message(recipient: str, subject: str, plain: str, markup: str) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = formataddr((settings.MAIL_FROM_NAME, settings.SMTP_USER))
    message["To"] = recipient
    message.set_content(plain)
    message.add_alternative(markup, subtype="html")
    return message


def _send(message: EmailMessage) -> None:
    if not settings.SMTP_USER or not settings.SMTP_APP_PASSWORD:
        raise RuntimeError("SMTP is not configured.")
    context = ssl.create_default_context()
    if settings.SMTP_PORT == 465:
        with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15, context=context) as server:
            server.login(settings.SMTP_USER, settings.SMTP_APP_PASSWORD)
            server.send_message(message)
    elif settings.SMTP_PORT == 587:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(settings.SMTP_USER, settings.SMTP_APP_PASSWORD)
            server.send_message(message)
    else:
        raise RuntimeError("SMTP_PORT must be 465 or 587.")


def send_otp_email(recipient: str, code: str, purpose: str) -> None:
    action = "verify your email" if purpose == "verify" else "reset your password"
    subject = f"{APP_NAME} verification code"
    safe_code = html.escape(code)
    plain = (
        f"{APP_NAME}\n\nYour code to {action} is {code}.\n"
        "It is valid for 10 minutes. If you did not request this, ignore this email."
    )
    markup = (
        "<!doctype html><html><body style=\"margin:0;background:#f4f5fb;color:#171a2b;"
        "font-family:Arial,sans-serif\"><main style=\"max-width:520px;margin:32px auto;"
        "padding:32px;background:#fff;border:1px solid #e3e5ee;border-radius:16px\">"
        f"<p style=\"color:#565c70;font-weight:700\">{APP_NAME}</p>"
        f"<h1 style=\"font-size:22px\">Your code to {action}</h1>"
        f"<p style=\"font-size:34px;letter-spacing:10px;font-weight:700;color:#4938cc\">{safe_code}</p>"
        "<p>This code is valid for 10 minutes.</p>"
        "<p style=\"color:#565c70\">If you did not request this, ignore this email.</p>"
        "</main></body></html>"
    )
    _send(_message(recipient, subject, plain, markup))


def send_test_email(recipient: str) -> None:
    plain = f"{APP_NAME} SMTP test\n\nYour configured mail delivery is working."
    markup = (
        "<!doctype html><html><body style=\"font-family:Arial,sans-serif;color:#171a2b\">"
        f"<h1>{APP_NAME} SMTP test</h1><p>Your configured mail delivery is working.</p></body></html>"
    )
    _send(_message(recipient, f"{APP_NAME} SMTP test", plain, markup))
