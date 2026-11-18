"""Build the training set.

1. Synthetic generator (template-based, three classes) so the project runs offline.
2. Real data: drop CSVs with `text,label` columns into backend/data/raw/ (Kaggle phishing
   email / SMS-spam datasets, etc.). Labels may be legitimate|suspicious|phishing or ham|spam|phishing.
"""
from __future__ import annotations

import random
from pathlib import Path

import pandas as pd  # noqa: F401  (only used if raw CSVs are present)

from ..config import settings

LABELS = ["legitimate", "suspicious", "phishing"]
rnd = random.Random(7)

BRANDS = ["PayPal", "Amazon", "Netflix", "Microsoft", "Apple", "HDFC Bank", "SBI", "ICICI Bank", "Paytm",
          "Google", "DHL", "FedEx", "LinkedIn", "Facebook", "Chase", "Wells Fargo", "Flipkart", "Instagram"]
NAMES = ["Priya", "Rahul", "Aisha", "John", "Maria", "Arjun", "Sneha", "David", "Kavya", "Omar", "Neha", "Tom"]
BAD_TLD = ["top", "xyz", "click", "icu", "tk", "buzz", "support", "work", "link"]
GOOD = {"PayPal": "paypal.com", "Amazon": "amazon.in", "Netflix": "netflix.com", "Microsoft": "microsoft.com",
        "Apple": "apple.com", "HDFC Bank": "hdfcbank.com", "SBI": "sbi.co.in", "ICICI Bank": "icicibank.com",
        "Paytm": "paytm.com", "Google": "google.com", "DHL": "dhl.com", "FedEx": "fedex.com",
        "LinkedIn": "linkedin.com", "Facebook": "facebook.com", "Chase": "chase.com",
        "Wells Fargo": "wellsfargo.com", "Flipkart": "flipkart.com", "Instagram": "instagram.com"}


def _slug(b): return b.lower().replace(" ", "")


def bad_url(b=None):
    b = b or rnd.choice(BRANDS)
    s = _slug(b)
    k = rnd.randint(0, 6)
    tld = rnd.choice(BAD_TLD)
    leet = s.replace("a", "4", 1) if "a" in s else s + "1"
    leet = leet.replace("o", "0", 1) if rnd.random() < .5 and "o" in leet else leet
    return [f"http://{s}-secure-login.{tld}/verify?id={rnd.randint(1000, 99999)}",
            f"http://{leet}.com/account/update",
            f"http://{rnd.randint(11, 220)}.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}/{s}/login",
            f"https://bit.ly/{rnd.choice(['3xK', '4fG', '2pQ'])}{rnd.randint(10, 99)}z",
            f"http://{s}.account-verify.{tld}",
            f"http://login.{s}.security-check.{tld}/signin",
            f"https://{s}-kyc-update.{tld}"][k]


def good_url(b=None):
    b = b or rnd.choice(BRANDS)
    d = GOOD[b]
    return rnd.choice([f"https://www.{d}/", f"https://{d}/orders", f"https://accounts.{d}/", f"https://www.{d}/help"])


def promo_url():
    return rnd.choice([f"http://www.dealz{rnd.randint(1, 99)}.shop/offer", f"https://tinyurl.com/{rnd.choice(['a1b', 'z9y'])}{rnd.randint(10, 99)}",
                       f"http://best-offers-today.{rnd.choice(['online', 'site', 'club'])}", "https://bit.ly/hot-deal-" + str(rnd.randint(10, 99))])


def amount(): return rnd.choice(["$1,250", "$4,500", "₹25,000", "₹1,00,000", "$850", "Rs. 12,500", "$10,000"])


# --------------------------------------------------------------------------- templates
# Each template is (group_id, callable returning text). Group ids enable template-held-out evaluation.
def legit_templates():
    n = lambda: rnd.choice(NAMES)  # noqa: E731
    b = lambda: rnd.choice(BRANDS)  # noqa: E731
    return [
        lambda: f"Hi {n()}, are we still meeting at {rnd.randint(1, 5)}pm tomorrow to go through the project report? I've shared the draft in the team folder. Let me know if you want changes. Thanks, {n()}",
        lambda: f"Dear {n()}, thank you for your order #{rnd.randint(10000, 99999)}. Your package has shipped and should arrive by Friday. Track it anytime at {good_url('Amazon')}. Regards, Amazon Customer Service",
        lambda: f"Your OTP for the transaction of {amount()} is {rnd.randint(100000, 999999)}. It is valid for 10 minutes. Do not share this OTP with anyone, including bank staff. - {rnd.choice(['HDFC Bank', 'SBI', 'ICICI Bank'])}",
        lambda: f"Reminder: your appointment with Dr. {n()} is on Monday at {rnd.randint(9, 12)}:30 AM. Reply YES to confirm or call the clinic to reschedule.",
        lambda: f"Hi {n()}, the meeting notes from yesterday are attached for your reference. Action items: finalize the budget, update the timeline, send the invoice to accounts. Cheers, {n()}",
        lambda: f"Your {b()} statement for the month is now available. Sign in through the official app or {good_url()} to view it. We will never ask for your password by email.",
        lambda: f"Hey {n()}! Dinner at my place on Saturday? Bring your guitar. {n()} and {n()} are coming too. Let me know what you want me to cook :)",
        lambda: f"Thanks for registering for the webinar on cloud security. The session starts at {rnd.randint(2, 6)}pm. Join using the calendar invite you received. See you there! Organizing team",
        lambda: f"Your cab is arriving in 3 minutes. Driver {n()}, vehicle KA{rnd.randint(1, 60):02d}AB{rnd.randint(1000, 9999)}. Share OTP {rnd.randint(1000, 9999)} only with your driver.",
        lambda: f"Hi {n()}, please find the quarterly report attached. I need your comments by Thursday if possible, no rush before then. Let me know if the numbers look right. Best, {n()}",
        lambda: f"{amount()} was debited from your account ending {rnd.randint(1000, 9999)} on {rnd.randint(1, 28)}-Oct at a merchant. If this was not you, call the number on the back of your card.",
        lambda: f"Welcome to {b()}! Your account has been created successfully. You can manage preferences anytime from your profile settings at {good_url()}. Happy to have you with us.",
        lambda: f"Team, a reminder that the office will be closed on Friday for the holiday. Please submit pending timesheets by Thursday evening. Thanks, HR",
        lambda: f"Your delivery from {b()} is out for delivery today between {rnd.randint(10, 12)}am and {rnd.randint(2, 6)}pm. Someone should be available to receive it. Track here: {good_url()}",
        lambda: f"Hi {n()}, can you review my pull request when you get a chance? It fixes the login bug we discussed. Tests are passing. Thanks!",
        lambda: f"Your password was changed successfully on {rnd.randint(1, 28)} Oct. If you made this change, no action is needed. If not, contact support through the official website.",
        lambda: f"Invoice #{rnd.randint(1000, 9999)} for {amount()} is due next month. You can pay via bank transfer using the details on your contract. Questions? Reply to this email. Thanks, Accounts team",
        lambda: f"Congrats {n()} on the new job! Let's celebrate this weekend. Free on Saturday evening? Also send me the new office address. Proud of you.",
    ]


def suspicious_templates():
    n = lambda: rnd.choice(NAMES)  # noqa: E731
    return [
        lambda: f"CONGRATULATIONS! You have been selected for an exclusive offer. Get 80% OFF on premium watches today only. Shop now: {promo_url()}",
        lambda: f"Need a loan? Get instant personal loan up to {amount()} with no documents and no credit check. Apply in 2 minutes: {promo_url()}",
        lambda: f"Make {amount()} per week working from home. No experience needed. Limited seats available. Message us on WhatsApp to join. {promo_url()}",
        lambda: f"Earn passive income with our crypto trading bot. Guaranteed 300% returns in 30 days. Join {rnd.randint(2, 9)}000+ happy investors: {promo_url()}",
        lambda: f"Hot singles in your area are waiting to meet you! Click to chat now. 100% free registration: {promo_url()}",
        lambda: f"Buy cheap medicines online without prescription. Best prices, discreet shipping, free delivery on orders above {amount()}. Visit {promo_url()}",
        lambda: f"Dear friend, I am a prince with {amount()} to transfer and need a trustworthy partner. You will receive 30 percent of the funds. Reply with your name and phone number.",
        lambda: f"Complete a 2-minute survey and receive a free gift voucher worth {amount()}. Offer ends this week, only a few vouchers left! {promo_url()}",
        lambda: f"Lose 10 kg in 10 days with this miracle pill. Doctors hate this one trick! Order today and get a free bottle: {promo_url()}",
        lambda: f"You are pre-approved for a platinum credit card. Special festive deal, zero fees for life. Call now or apply here: {promo_url()}",
        lambda: f"Win a brand new iPhone! Enter our free giveaway before midnight. Just share this message with {rnd.randint(5, 20)} friends and click: {promo_url()}",
        lambda: f"Hiring! Part-time data entry jobs, earn {amount()} monthly. A small registration fee is refundable after your first week. Contact us now.",
        lambda: f"SALE SALE SALE!!! Flat 70% off on all electronics, only today. Limited stock, hurry before it's gone! Shop at {promo_url()}",
        lambda: f"Hello, we noticed your car's extended warranty may be expiring. Speak to an advisor now to get a free quote. Reply STOP to opt out. {promo_url()}",
    ]


def phishing_templates():
    n = lambda: rnd.choice(NAMES)  # noqa: E731
    b = lambda: rnd.choice(BRANDS)  # noqa: E731

    def acct():
        br = b()
        return rnd.choice([
            f"Dear customer, we detected unusual activity on your {br} account. Your account will be suspended within 24 hours unless you verify your identity. Click here to confirm your password: {bad_url(br)}",
            f"URGENT: Your {br} account has been limited. To restore full access you must update your billing information immediately. Failure to respond will result in permanent closure. Log in at {bad_url(br)}",
            f"{br} Security Alert: someone tried to sign in from a new device. If this wasn't you, secure your account now by verifying your details: {bad_url(br)}",
        ])

    def kyc():
        br = rnd.choice(["HDFC Bank", "SBI", "ICICI Bank", "Paytm"])
        return rnd.choice([
            f"Dear {br} customer, your KYC has expired and your account will be blocked today. Update your PAN and Aadhaar immediately: {bad_url(br)}",
            f"{br}: Your net banking is suspended due to incomplete KYC. Complete verification within 2 hours to avoid deactivation. Click {bad_url(br)} and enter your login details and OTP.",
            f"ALERT! {amount()} debited from your {br} account. If not you, login now to cancel the transaction: {bad_url(br)} Enter card number and CVV to secure your account.",
        ])

    def delivery():
        br = rnd.choice(["DHL", "FedEx", "Amazon", "Flipkart"])
        return rnd.choice([
            f"{br}: Your package could not be delivered due to an incomplete address. Pay a small redelivery fee of $1.99 within 24 hours or it will be returned: {bad_url(br)}",
            f"Your {br} parcel is on hold. Confirm your address and pay customs charges now to release it. Final notice: {bad_url(br)}",
        ])

    def invoice():
        return rnd.choice([
            f"Hi, please find the attached invoice #{rnd.randint(1000, 9999)} for {amount()}. Open the attached document and log in with your Microsoft credentials to view it: {bad_url('Microsoft')}",
            f"Dear user, a shared document is waiting for you. Sign in to your email account to view 'Salary_Revision.pdf': {bad_url('Google')} This link expires in 24 hours.",
            f"You have a new voicemail message. Click to listen, you may need to verify your email password: {bad_url('Microsoft')}",
        ])

    def refund():
        br = rnd.choice(["IRS", "Income Tax Department", "PayPal", "Amazon"])
        return rnd.choice([
            f"{br}: You are eligible for a tax refund of {amount()}. Submit your bank details and card number to claim your refund within 48 hours: {bad_url(b())}",
            f"Dear taxpayer, a refund of {amount()} is pending. Verify your identity and enter your social security number or PAN to receive it: {bad_url(b())}",
        ])

    def pwd():
        return rnd.choice([
            f"Your email password expires today. Click below to keep the same password and avoid losing access to your mailbox: {bad_url('Microsoft')}",
            f"IT Helpdesk: Your mailbox is almost full and will be disabled. Verify your account and enter your username and password to upgrade storage now: {bad_url('Google')}",
            f"Action required: confirm your {b()} login credentials immediately to prevent your account from being deleted. Verify here: {bad_url()}",
        ])

    def bec():
        return rnd.choice([
            f"Hi {n()}, I'm in a meeting and can't talk. I need you to buy {rnd.randint(3, 8)} gift cards of $100 each for a client urgently. Send me the codes by email as soon as possible. Keep this confidential.",
            f"Urgent request from the CEO: please process a wire transfer of {amount()} to the new vendor account today. Do not discuss with anyone. I will send the bank details. Reply immediately.",
            f"Hello, this is {n()} from finance. Our bank details have changed. Please update the payment details and make the pending transfer of {amount()} to the new account immediately.",
        ])

    def prize():
        return rnd.choice([
            f"Congratulations! You have won {amount()} in the {b()} lottery. To claim your prize, confirm your name, address and bank account details within 24 hours at {bad_url()}",
            f"Dear winner, you were selected for a {amount()} reward. Claim your reward now and enter your card number to cover the processing fee: {bad_url()}",
        ])

    def social():
        br = rnd.choice(["Facebook", "Instagram", "LinkedIn", "Netflix", "Apple"])
        return rnd.choice([
            f"{br}: Your account violates our community policy and will be disabled in 24 hours. Appeal now by verifying your login: {bad_url(br)}",
            f"Your {br} payment failed. Update your payment method immediately to avoid cancellation of your membership: {bad_url(br)}",
            f"Dear user, your Apple ID was locked for security reasons. Verify your Apple ID and password now: {bad_url('Apple')}",
        ])
    return [acct, kyc, delivery, invoice, refund, pwd, bec, prize, social]


def _wrap_sms(text: str) -> str:
    return text[:300]


def generate(per_class: int = 1200, seed: int = 7) -> "pd.DataFrame":
    rnd.seed(seed)
    import pandas as pd
    rows = []
    makers = {"legitimate": legit_templates(), "suspicious": suspicious_templates(), "phishing": phishing_templates()}
    for label, fns in makers.items():
        for i in range(per_class):
            gi = i % len(fns)
            text = fns[gi]()
            if rnd.random() < 0.25:
                text = text.upper() if (label != "legitimate" and rnd.random() < .15) else text
            if rnd.random() < 0.3:
                text = rnd.choice(["Hi, ", "Hello, ", "", "FYI: ", "Notice: "]) + text
            ch = "sms" if len(text) < 220 and rnd.random() < .5 else "email"
            rows.append({"text": text, "label": label, "group": f"{label}-{gi}", "source": "synthetic", "channel": ch})
    return pd.DataFrame(rows)


def load_real() -> "pd.DataFrame":
    import pandas as pd
    frames = []
    mapping = {"ham": "legitimate", "legit": "legitimate", "legitimate": "legitimate", "safe email": "legitimate",
               "spam": "suspicious", "suspicious": "suspicious",
               "phishing": "phishing", "phish": "phishing", "phishing email": "phishing", "smishing": "phishing"}
    raw = Path(settings.RAW_DATA_DIR)
    if not raw.exists():
        return pd.DataFrame(columns=["text", "label", "group", "source"])
    for f in raw.glob("*.csv"):
        try:
            df = pd.read_csv(f, encoding_errors="ignore")
        except Exception:
            continue
        cols = {c.lower().strip(): c for c in df.columns}
        tcol = next((cols[c] for c in ("text", "email text", "body", "message", "v2") if c in cols), None)
        lcol = next((cols[c] for c in ("label", "email type", "class", "category", "v1") if c in cols), None)
        if not tcol or not lcol:
            print(f"skip {f.name}: needs text+label columns")
            continue
        out = pd.DataFrame({"text": df[tcol].astype(str), "label": df[lcol].astype(str).str.lower().str.strip().map(mapping)})
        out = out.dropna()
        out["group"] = f.stem
        out["source"] = f.name
        frames.append(out)
        print(f"loaded {len(out)} rows from {f.name}")
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=["text", "label", "group", "source"])


CLEAN_PATH = Path(settings.BLOCKLIST_PATH).parent / "clean" / "dataset.csv"


def load_clean():
    """Cleaned real data produced by `python -m pipeline.collect && python -m pipeline.clean`."""
    import pandas as pd
    if not CLEAN_PATH.exists():
        return None
    df = pd.read_csv(CLEAN_PATH, keep_default_na=False)
    df["group"] = df["source"]
    return df[["text", "label", "group", "source", "channel", "date"]]


def build_dataset(per_class: int = 1200, force_synthetic: bool = False):
    """Real cleaned data when available; otherwise the synthetic starter set (+ any drop-in CSVs)."""
    import pandas as pd
    real = None if force_synthetic else load_clean()
    if real is not None and len(real):
        return real
    return pd.concat([generate(per_class), load_real()], ignore_index=True)


# ----------------------------------------------------------------------------------------------
# Extra synthetic coverage for gaps the REAL corpora cannot fill (see data report):
#   * modern legitimate transactional / workplace / notification mail and SMS (real ham is 2002 mailing lists)
#   * business-email-compromise scams that contain no link at all
# Tagged source=synthetic_* and used for training only, never for evaluation.
# ----------------------------------------------------------------------------------------------
_pick = lambda *xs: rnd.choice(xs)  # noqa: E731
_name = lambda: rnd.choice(NAMES)  # noqa: E731
_site = lambda: rnd.choice(["amazon.in", "github.com", "linkedin.com", "google.com", "microsoft.com", "paypal.com", "swiggy.com",
                            "zomato.com", "irctc.co.in", "airtel.in", "jio.com", "hdfcbank.com", "icicibank.com", "uber.com",
                            "flipkart.com", "apple.com", "zoom.us", "slack.com", "dropbox.com", "spotify.com", "netflix.com"])
_day = lambda: rnd.choice(["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"])
_t = lambda: f"{rnd.randint(1, 12)}:{rnd.choice(['00', '15', '30', '45'])} {rnd.choice(['AM', 'PM'])}"


def legit_templates_v2():
    return [
        lambda: f"{_pick('Hi', 'Hello', 'Hey')} {_name()}, {_pick('your order', 'your package', 'the parcel you ordered')} {_pick('has shipped', 'is on its way', 'left our warehouse today')} and {_pick('should arrive', 'is expected', 'will be delivered')} by {_day()}. {_pick('Track it', 'You can follow its progress', 'See live status')} at https://www.{_site()}/orders/{rnd.randint(1000, 99999)}.",
        lambda: f"{_pick('New sign-in', 'A new login', 'Sign-in alert')}: we noticed a sign-in to your account from {_pick('Chrome on Windows', 'Safari on iPhone', 'Firefox on Linux', 'the mobile app')}. {_pick('If this was you, no action is needed.', 'If this was you, you can ignore this message.')} {_pick('Otherwise, review recent activity at', 'To review your devices, visit')} https://{_site()}/settings/security.",
        lambda: f"{_pick('Your verification code is', 'Use code', 'Your one-time code:')} {rnd.randint(100000, 999999)}. {_pick('It expires in 10 minutes.', 'It is valid for 5 minutes.')} {_pick('Never share this code with anyone.', 'Do not give this code to anybody, we will never ask for it.')}",
        lambda: f"Hi {_name()}, {_pick('thanks for your payment of', 'we received your payment of', 'your receipt for')} {_pick('$24.99', 'Rs 499', '$129.00', 'Rs 1,299')}. {_pick('Your receipt is attached.', 'A copy of the invoice is attached for your records.')} {_pick('Questions? Just reply to this email.', 'If anything looks wrong, reply and we will sort it out.')}",
        lambda: f"{_pick('Reminder:', 'Heads up:', 'Just a reminder,')} {_pick('our weekly sync', 'the design review', 'the sprint planning meeting', 'tomorrow\'s standup')} is {_pick('on', 'scheduled for')} {_day()} at {_t()}. {_pick('The agenda is in the shared doc.', 'Notes will be posted in the channel afterwards.', 'Please add your updates before the call.')} Join: https://{_pick('meet.google.com', 'zoom.us', 'teams.microsoft.com')}/{rnd.randint(100, 999)}-{rnd.randint(100, 999)}",
        lambda: f"{_pick('Hi', 'Dear')} {_name()}, {_pick('your appointment', 'your booking', 'your reservation')} {_pick('is confirmed for', 'has been scheduled for', 'is set for')} {_day()} at {_t()}. {_pick('Please arrive ten minutes early.', 'Bring a valid photo ID.', 'Reply to this message if you need to reschedule.')}",
        lambda: f"{_name()} {_pick('commented on', 'mentioned you in', 'assigned you to', 'approved')} {_pick('pull request #', 'issue #', 'ticket #')}{rnd.randint(10, 9999)}: \"{_pick('Looks good to me, merging after tests pass.', 'Can you add a unit test for the edge case?', 'Thanks for the fix, this resolves the crash.')}\" View it at https://github.com/acme/app/pull/{rnd.randint(10, 999)}",
        lambda: f"{_pick('Your bill', 'Your statement', 'Your monthly invoice')} for {_pick('September', 'October', 'November')} is {_pick('ready', 'now available')}. {_pick('Amount due', 'Total payable')}: {_pick('Rs 799', 'Rs 1,149', '$32.40')} by {rnd.randint(1, 28)} {_pick('Oct', 'Nov', 'Dec')}. {_pick('Pay securely in the official app or at', 'View and pay at')} https://www.{_site()}/billing. {_pick('Autopay customers need to do nothing.', 'Thank you for being a customer.')}",
        lambda: f"{_pick('Welcome to', 'Thanks for joining', 'Your account is ready on')} {_pick('Spotify', 'Dropbox', 'Slack', 'Notion', 'Canva')}, {_name()}! {_pick('Get started by exploring your dashboard.', 'Here are three tips to get the most out of your plan.')} {_pick('Need help?', 'Questions?')} Visit our help centre at https://help.{_site()}.",
        lambda: f"{_pick('Hi team,', 'Hello all,', 'Dear colleagues,')} {_pick('the office will be closed on', 'a quick note: the building is closed on', 'please note that we are off on')} {_day()} {_pick('for the public holiday', 'for maintenance work', 'due to the festival')}. {_pick('Please submit timesheets before then.', 'Remote work is fine as usual.', 'Reach out to HR if you have questions.')} Thanks, {_name()}",
        lambda: f"{_pick('Dear parent,', 'Hello parents,', 'Dear students,')} {_pick('the term exams begin on', 'the parent-teacher meeting is on', 'the annual day rehearsal is on')} {_day()}. {_pick('Please ensure the fee is paid at the school office.', 'Timetable is attached.', 'Kindly confirm attendance by replying.')} Regards, Principal",
        lambda: f"Hi {_name()}, {_pick('I attached the revised proposal', 'attaching the report you asked for', 'here are the slides from today')}. {_pick('Let me know what you think by Friday.', 'Happy to jump on a call if anything is unclear.', 'No rush, whenever you get a chance.')} {_pick('Best', 'Thanks', 'Cheers')}, {_name()}",
        lambda: f"{_pick('Your flight', 'Your train', 'Your bus')} {_pick('to Mumbai', 'to Delhi', 'to Bengaluru', 'to Chennai')} {_pick('departs', 'leaves')} on {_day()} at {_t()}. {_pick('PNR', 'Booking ref')}: {rnd.choice('ABCDEFGH')}{rnd.randint(10000, 99999)}. {_pick('Web check-in opens 48 hours before departure at', 'Manage your booking at')} https://www.{_site()}/trips.",
        lambda: f"{_pick('Rs', 'INR')} {rnd.randint(100, 9999)} {_pick('debited from', 'credited to')} {_pick('your account', 'A/c')} XX{rnd.randint(1000, 9999)} {_pick('on', 'dated')} {rnd.randint(1, 28)}-{_pick('Oct', 'Nov')}. {_pick('Available balance', 'Avl bal')}: Rs {rnd.randint(1000, 99999)}. {_pick('Not you? Call the number printed on your card.', 'If you did not make this transaction, contact your branch.')}",
        lambda: f"{_pick('Your order', 'Your delivery')} from {_pick('Swiggy', 'Zomato', 'Amazon', 'Flipkart')} {_pick('is out for delivery', 'will arrive in 15 minutes', 'has been delivered')}. {_pick('Hope you enjoy it!', 'Rate your experience in the app.', 'Thank you for ordering.')}",
        lambda: f"{_pick('Hey', 'Hi')} {_name()}, {_pick('are you free for lunch', 'want to grab coffee', 'shall we catch up')} {_pick('tomorrow', 'on Saturday', 'this week')}? {_pick('I found a nice place near the metro.', 'My treat this time!', 'Let me know what time works.')}",
        lambda: f"{_pick('Doctor', 'Clinic', 'Lab')} {_pick('reminder:', 'notice:')} your {_pick('test results are ready', 'follow-up visit is due', 'prescription refill is ready')}. {_pick('Please collect them at the front desk.', 'Call us to book a slot.', 'You can pick it up any weekday before 6 PM.')}",
        lambda: f"{_pick('Newsletter', 'Weekly digest', 'This week at')} {_pick('Tech Weekly', 'The Daily Brief', 'Product Hunt', 'Hacker Newsletter')}: {_pick('5 new tools for developers', 'the top stories you missed', 'what we are reading')}. Read online at https://news.{_site()}/issue/{rnd.randint(10, 400)}. {_pick('You can unsubscribe at any time from your account settings.', 'Manage your email preferences in your profile.')}",
        lambda: f"{_pick('Password reset:', 'Reset request:')} {_pick('you asked to reset your password.', 'we received a request to change your password.')} {_pick('If you made this request, use the link below within one hour:', 'Use this link to choose a new password, it expires in 60 minutes:')} https://accounts.{_site()}/reset/{rnd.randint(100000, 999999)}. {_pick('If you did not ask for this, you can safely ignore this email.', 'If this was not you, no changes were made to your account.')}",
    ]


def bec_templates():
    """Business-email-compromise: urgent money / gift-card requests with no link (real corpora lack these)."""
    return [
        lambda: f"{_pick('Hi', 'Hello')} {_name()}, {_pick('I am in a meeting', 'I am travelling', 'I am tied up in a conference')} and cannot take calls. {_pick('I need you to', 'Can you quickly')} {_pick('buy', 'purchase', 'get')} {rnd.randint(3, 10)} {_pick('Amazon', 'Apple', 'Google Play', 'Steam')} gift cards of {_pick('$100', '$50', 'Rs 5000')} each {_pick('for a client', 'as a surprise for the team', 'for an urgent project')}. {_pick('Send me the codes by reply as soon as possible.', 'Scratch them and email me the numbers today.')} {_pick('I will reimburse you.', 'Keep this confidential for now.')}",
        lambda: f"{_pick('Urgent:', 'Important:', 'Quick favour:')} {_pick('this is your CEO.', 'this is the director.', 'it is your manager.')} {_pick('Please process', 'I need you to arrange', 'Kindly make')} a {_pick('wire transfer', 'bank transfer', 'payment')} of {_pick('$18,500', 'Rs 4,50,000', '$9,800')} to {_pick('a new vendor', 'our supplier', 'a client account')} {_pick('today', 'immediately', 'before noon')}. {_pick('I will send the account details separately.', 'Do not discuss this with anyone until it is done.')} {_pick('Reply as soon as you see this.', 'Confirm when it is completed.')}",
        lambda: f"{_pick('Hello', 'Hi')} {_name()}, {_pick('our bank details have changed.', 'we have changed banks.', 'please note our new account.')} {_pick('Please update your records and send the pending invoice payment to the new account below.', 'All future payments, including the outstanding balance, should go to the new details attached.')} {_pick('Kindly confirm once the transfer is made.', 'This is time sensitive.')}",
        lambda: f"{_pick('Are you at your desk?', 'Are you available?', 'Do you have a minute?')} {_pick('I need a quick favour,', 'I have a task for you,')} {_pick('and I cannot call right now.', 'it is confidential.')} {_pick('Reply as soon as you get this.', 'Please respond here only.')}",
    ]
