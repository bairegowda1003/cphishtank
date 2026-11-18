"""Independent sanity evaluation on hand-written messages (NOT produced by the training templates).
Run:  python -m tests.eval_handwritten
Compares ML-only, rules-only and the fused system on binary 'risky vs safe' detection."""
from app.services import analyzer, heuristics as H, ml

PHISH = [
    ("sms", "Dear SBI user, your YONO account is blocked. Click http://sbi-yono-verify.top to reactivate now."),
    ("sms", "Your Netflix subscription could not be renewed. Update payment details here: https://netflix-billing-help.click/pay"),
    ("sms", "Income Tax Dept: refund of Rs 18,450 approved. Submit bank account at http://incometax-refund.icu/claim"),
    ("sms", "USPS: your parcel is held due to unpaid postage of $2.99. Pay within 12 hours: https://usps-redeliver.xyz"),
    ("email", "From: Microsoft 365 <no-reply@m1crosoft-support.com>\nSubject: Password expires today\n\nYour password expires in 2 hours. Keep your password: http://m1crosoft-support.com/keep"),
    ("email", "From: HR Department <hr.payroll@gmail.com>\nSubject: Salary revision\n\nPlease review the attached revised salary document and sign in with your office email password to open it: https://bit.ly/3salary"),
    ("email", "From: Apple ID <support@apple-id-locked.xyz>\n\nYour Apple ID has been locked because of suspicious activity. Verify your identity immediately or your account will be disabled."),
    ("email", "Hello, I am travelling and need a favour. Please buy 5 Amazon gift cards worth $100 each and send me the codes. I will reimburse you. Don't tell anyone."),
    ("email", "From: Bank Alert <alert@hdfcbank-secure.top>\n\nUnusual sign-in detected on your account. Confirm your card number, CVV and OTP at http://hdfcbank-secure.top/confirm to avoid suspension."),
    ("email", "Dear customer, DocuSign: you have 1 document waiting. Log in to view and sign: http://docusign-review.online/login?id=88213"),
    ("sms", "Congratulations! You won a Samsung phone in our lucky draw. Claim your prize now: http://bit.ly/prize-claim-77 Send your address."),
    ("email", "From: IT Support <helpdesk@company-mail-update.work>\n\nYour mailbox quota is full. Re-enter your username and password to upgrade storage or messages will be deleted within 24 hours."),
]
SAFE = [
    ("sms", "Your OTP for login is 553821. Valid for 5 minutes. Do not share it with anyone. - Zomato"),
    ("sms", "Your Uber is arriving in 2 min. Driver Ramesh, KA01AB1234."),
    ("sms", "Rs 450 debited from A/c XX1234 at Swiggy on 12-Oct. Avl bal Rs 12,300. Not you? Call 1800 on the card."),
    ("email", "From: Anita <anita@startup.io>\nSubject: Standup moved\n\nHi all, tomorrow's standup is at 10:30 instead of 10. Same Meet link as always. Thanks!"),
    ("email", "From: Amazon.in <shipment-tracking@amazon.in>\nSubject: Your package has shipped\n\nHi Karan, your order of 'USB-C cable' shipped and will arrive Thursday. Track: https://www.amazon.in/progress-tracker"),
    ("email", "From: GitHub <noreply@github.com>\n\nA new sign-in to your account from Chrome on Linux. If this was you, there's nothing to do. Review activity at https://github.com/settings/security-log"),
    ("email", "Hey Meera, loved your talk! Could you share the slides? Also coffee next week? - Dev"),
    ("email", "From: Library <desk@citylibrary.org>\n\nThe book you reserved, 'Deep Work', is ready for pickup until Saturday. Please bring your membership card."),
    ("sms", "Reminder: dentist appointment tomorrow at 4:30 PM at Smile Clinic. Reply C to confirm."),
    ("email", "From: Rahul <rahul@acme.com>\nSubject: Invoice\n\nHi, attached is invoice 2231 for October as discussed. Payment terms are net 30. Let me know if you need anything changed."),
    ("email", "From: LinkedIn <jobs-listings@linkedin.com>\n\n5 new jobs match your search for 'data analyst' in Bengaluru. See them at https://www.linkedin.com/jobs"),
    ("sms", "Your Amazon Pay balance was topped up by Rs 500. View: https://www.amazon.in/pay"),
]


# ---- BLIND SET: written AFTER the model and rules were frozen; never used for tuning -----------------
BLIND_RISKY = [
    ("sms", "Wells Fargo Alert: your debit card has been temporarily restricted. Restore access at wf-secure-restore.top/verify or call within 1 hr."),
    ("sms", "Hi, it's DPD. We couldn't deliver your parcel today, please reschedule and pay the 1.45 handling fee: https://dpd-reschedule.click/p/88213"),
    ("sms", "(Axis Bank) Dear customer your net-banking will be deactivated today due to pending PAN update. Update now http://axis-pan-update.xyz"),
    ("sms", "You've been selected for a 5000 rs Amazon voucher! Complete the 1 minute survey to claim: bit.ly/amz-reward-9"),
    ("email", "From: Coinbase Support <support@coinbase-wallet-help.com>\nSubject: Wallet suspended\n\nWe detected a suspicious withdrawal. To keep your funds safe, verify your 12-word recovery phrase at https://coinbase-wallet-help.com/recover within 24 hours."),
    ("email", "From: Netflix <info@account-netflix.support>\nSubject: Your membership is on hold\n\nWe're having trouble with your current billing information. Please update your payment details to continue watching: http://account-netflix.support/billing"),
    ("email", "From: John Peters <jpeters.ceo@gmail.com>\nSubject: Quick task\n\nAre you available? I need you to pick up some Google Play gift cards for a client today. I'm in a meeting so just reply here, I'll explain more after. Keep it between us."),
    ("email", "From: DocuSign <dse@docusign-secure-mail.net>\nSubject: Completed: Please review and sign\n\nYour colleague has sent you a document. Review and sign here: http://docusign-secure-mail.net/review?id=44821\nThis link expires in 24 hours."),
    ("email", "Dear Sir/Madam, I am Barrister Okoro, a lawyer. A late client of mine left $12.5 million with no next of kin. I need your assistance to transfer the funds and you will receive 40%. Reply with your full name, address and bank details."),
    ("email", "From: IRS Refund <refunds@irs-gov-claims.org>\n\nAfter the last annual calculation of your fiscal activity we determined you are eligible for a tax refund of $842.60. Submit the refund request form and your card details here: https://irs-gov-claims.org/refund"),
    ("email", "From: Microsoft Teams <no-reply@teams-notice.top>\nSubject: You have 3 missed messages\n\nSign in with your work account to read your messages: https://teams-notice.top/login. Messages are deleted after 24 hours."),
    ("email", "From: Apple Support <appleid@icloud-locked.info>\n\nYour Apple ID has been locked for security reasons. Confirm your identity and password immediately to unlock it: http://icloud-locked.info/unlock"),
    ("email", "From: HR Payroll <payroll@acme-hr-portal.xyz>\nSubject: Updated salary structure\n\nPlease log in to the HR portal with your employee ID and password to acknowledge your updated salary structure before Friday: https://acme-hr-portal.xyz"),
    ("sms", "FedEx: Your package is held at our facility. Confirm your address and pay a $1.99 fee to release it: https://fedex-hold.icu/r"),
    ("email", "From: Dropbox <share@dropbox-files-view.com>\nSubject: Alex shared 'Q3 Salaries.xlsx' with you\n\nTo view the file, sign in with your email password here: http://dropbox-files-view.com/signin"),
    ("sms", "Congratulations! Your number won 25,000 GBP in the Mega Mobile Draw. To claim send your name, bank account and ID to claims-desk@mobile-win.top"),
]
BLIND_SAFE = [
    ("sms", "Your IRCTC ticket PNR 4521896734 is confirmed. Train 12627 departs Sat 08:15 from SBC. Have a safe journey."),
    ("sms", "Use 418207 as your Google verification code. Do not share it with anyone."),
    ("sms", "Your Swiggy order #23811 is on its way! Arriving in about 20 mins. Track: https://www.swiggy.com/orders"),
    ("sms", "Hey, running 10 mins late, order me a coffee? Thanks!"),
    ("sms", "Rs 1,200.00 spent on HDFC Bank Card XX4421 at BigBasket on 14-Oct. Avl limit Rs 45,000. Not you? Call 18002586161."),
    ("email", "From: Priya Nair <priya.nair@corpmail.in>\nSubject: URGENT: staging server down\n\nHi all, the staging server went down at 3pm and QA is blocked. Please join the incident call now: https://meet.google.com/abc-defg-hij. I need everyone's logs within the hour."),
    ("email", "From: Spotify <no-reply@spotify.com>\nSubject: Your receipt from Spotify\n\nThanks for being a Premium member. We charged Rs 119 to your card ending 4421. See your plan at https://www.spotify.com/account. Questions? Visit https://support.spotify.com."),
    ("email", "From: Dr. Mehta's Clinic <reception@mehtaclinic.in>\n\nDear Mr. Rao, this is a reminder of your appointment on Thursday at 11:30 AM. Please bring your previous reports. Call us to reschedule."),
    ("email", "From: Sam <sam.lee@startupmail.com>\nSubject: Feedback on the deck\n\nHey, read through the deck last night. Slide 7 needs a clearer chart and the pricing slide could use a comparison. Overall really strong. Can we chat Monday?"),
    ("email", "From: Zoom <no-reply@zoom.us>\nSubject: Meeting reminder\n\nYour meeting 'Weekly sync' starts in 30 minutes. Join: https://zoom.us/j/9283746501"),
    ("email", "From: Registrar Office <registrar@university.edu>\nSubject: Fee payment deadline\n\nDear students, the last date to pay the semester fee is 30 October. Please pay through the official student portal. Late fines apply after this date."),
    ("email", "From: Airtel <noreply@airtel.in>\nSubject: Your October bill is ready\n\nHi Karan, your bill of Rs 599 is due on 5 Nov. Pay via the Airtel Thanks app or at https://www.airtel.in/pay. Thank you for choosing Airtel."),
    ("email", "From: Mom <maria.d@gmail.com>\nSubject: Sunday\n\nHi beta, are you coming home this Sunday? I'm making your favourite biryani. Also don't forget to call grandma, she was asking about you."),
    ("email", "From: LinkedIn <invitations@linkedin.com>\n\nAnanya Rao wants to connect with you on LinkedIn. View their profile: https://www.linkedin.com/comm/mynetwork. You are receiving invitation emails."),
    ("email", "From: PayPal <service@paypal.com>\nSubject: You sent a payment of $45.00 USD\n\nYou sent $45.00 USD to Daniel Cruz. View the transaction details in your account at https://www.paypal.com/myaccount/transactions."),
    ("email", "From: Library Desk <desk@bangalorelibrary.org>\n\nThe book you reserved, 'Atomic Habits', is ready for pickup until Saturday. Please bring your membership card."),
]


def run_set(name, risky, safe, verbose=True):
    rows = [(c, t, 1) for c, t in risky] + [(c, t, 0) for c, t in safe]
    res = {"ml_only": 0, "rules_only": 0, "fused": 0}
    errs = []
    for ch, t, y in rows:
        r = analyzer.analyze(t, channel=ch)
        pred = {"ml_only": r["scores"]["ml_risk"] >= 50, "rules_only": r["scores"]["heuristic_risk"] >= 30,
                "fused": r["label"] != "legitimate"}
        for k, v in pred.items():
            res[k] += int(v == bool(y))
        if pred["fused"] != bool(y):
            errs.append(("MISSED RISKY" if y else "FALSE ALARM", r["label"], r["risk_score"], t.replace("\n", " ")[:90]))
    n = len(rows)
    print(f"\n{name}: n={n} ({len(risky)} risky, {len(safe)} safe)")
    for k, v in res.items():
        print(f"  {k:11s} {v}/{n} = {v / n:.1%}")
    for e in errs:
        print("   ", e)
    return res


def main():
    run_set("DEVELOPMENT set (rules were tuned against it, so this number is optimistic)", PHISH, SAFE)
    run_set("BLIND set (written after the system was frozen)", BLIND_RISKY, BLIND_SAFE)


def _old_main():
    rows = [(c, t, 1) for c, t in PHISH] + [(c, t, 0) for c, t in SAFE]
    res = {"ml_only": 0, "rules_only": 0, "fused": 0}
    errs = []
    for ch, t, y in rows:
        r = analyzer.analyze(t, channel=ch)
        pred = {"ml_only": r["scores"]["ml_risk"] >= 50, "rules_only": r["scores"]["heuristic_risk"] >= 30,
                "fused": r["label"] != "legitimate"}
        for k, v in pred.items():
            res[k] += int(v == bool(y))
        if pred["fused"] != bool(y):
            errs.append((y, r["label"], r["risk_score"], t[:70]))
    n = len(rows)
    print(f"n={n} (12 phishing, 12 safe)  threshold: risky = fused label != legitimate / ml>=50 / rules>=30")
    for k, v in res.items():
        print(f"  {k:11s} accuracy {v}/{n} = {v / n:.1%}")
    for e in errs:
        print("  fused error:", e)


if __name__ == "__main__":
    main()
