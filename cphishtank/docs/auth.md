# Authentication setup

## Backend configuration

From `backend/`, copy `.env.example` to `.env`. Set a unique signing key (at least 32 characters); for example, generate one with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Keep the generated value private and do not commit `.env`. The API refuses to start with a missing or placeholder key unless `DEV_MODE=true` is explicitly enabled.

The app uses the existing SQLite database by default and creates the `otp_codes` table at startup. Existing user rows receive `email_verified=true` during the compatibility migration so current accounts continue working; new registrations are unverified until the email code is checked. The migration also adds `token_version` to existing user tables.

## Gmail App Password setup

1. Sign in to the Google Account that will send application mail.
2. Open **Google Account → Security** and turn on **2-Step Verification**. Google App Passwords are available only when 2-Step Verification is enabled; some managed or Advanced Protection accounts may not offer them.
3. Open **App passwords** from the Security settings, reauthenticate if prompted, enter `CPhishTank` as the app name, and choose **Create**.
4. Copy the generated 16-character App Password. In `backend/.env`, set `SMTP_USER` to the sending Gmail address and `SMTP_APP_PASSWORD` to that App Password (omit any display spaces). Do **not** use your normal Google password.
5. Optionally set `MAIL_FROM_NAME=CPhishTank`. `SMTP_HOST` defaults to `smtp.gmail.com`, and an empty `SMTP_PORT` defaults to 465 (SMTP over SSL). Port 587 with STARTTLS is also supported.
6. Restart the backend. To verify delivery, run this from `backend/`:

   ```bash
   python -m app.scripts.test_mail you@gmail.com
   ```

Revoke the App Password from the Google Account security page if it is exposed or no longer needed. Store it only in the ignored `backend/.env`; never put it in frontend configuration or source control.

## Local development mode

Set `DEV_MODE=true` only on a local development server to print one-time codes to the backend console instead of sending email. Turn it off for deployment. OTPs are generated with `secrets`, stored as keyed HMAC-SHA256 hashes, expire after 10 minutes, allow at most five guesses, and become unusable after verification/reset or when replaced by a newer code. Do not retain console output.

Email verification and password-recovery requests are deliberately generic where account existence could otherwise be disclosed. OTP email requests are limited to five per email and client IP per hour; login attempts are limited to ten per email and client IP per 15 minutes. These limits are process-local and reset on restart. A multi-worker/replica production deployment should replace the in-memory limiter with shared storage such as Redis.

OTP delivery runs as an in-process FastAPI background task. Delivery failures are logged without message content, OTPs, or SMTP details; the response remains generic. For durable mail delivery in a production deployment, use a persistent queue.

## Browser session behavior

The browser stores the access token in `sessionStorage` by default and in `localStorage` only when **Keep me signed in** is selected. A 401 response clears both stores and resets the authenticated state. Both stores are accessible to same-origin JavaScript; deploy with a strict Content Security Policy and prevent script injection. The API continues to accept bearer tokens for existing clients.

Routes:

- `POST /api/auth/register`, `POST /api/auth/verify-email`, `POST /api/auth/resend-otp`
- `POST /api/auth/login`, `POST /api/auth/forgot-password`, `POST /api/auth/reset-password`
- `POST /api/auth/change-password`, `GET /api/auth/me`
