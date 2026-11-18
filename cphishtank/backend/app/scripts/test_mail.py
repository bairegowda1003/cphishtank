import argparse
import smtplib
import ssl
import sys

from pydantic import EmailStr, TypeAdapter, ValidationError

from ..services.mailer import send_test_email


def main() -> int:
    parser = argparse.ArgumentParser(description="Send a test email using the configured SMTP account.")
    parser.add_argument("recipient", help="Email address to receive the test message.")
    args = parser.parse_args()
    try:
        recipient = TypeAdapter(EmailStr).validate_python(args.recipient)
        send_test_email(str(recipient))
    except ValidationError:
        parser.error("Provide a valid recipient email address.")
    except (smtplib.SMTPException, OSError, RuntimeError, ssl.SSLError):
        print("Test email could not be sent. Check the SMTP configuration.", file=sys.stderr)
        return 1
    print("Test email sent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
