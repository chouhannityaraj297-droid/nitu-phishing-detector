"""
Generates small synthetic CSV/TSV files matching the real dataset formats,
so you can run the full pipeline end-to-end before downloading the real datasets.
Run: python make_sample_data.py
"""

import csv
import random
from pathlib import Path

RAW_DIR = Path("../data/raw")
RAW_DIR.mkdir(parents=True, exist_ok=True)

PHISHING_SUBJECTS = [
    "Your account has been suspended",
    "Urgent: Verify your payment information",
    "Action required: Unusual sign-in activity",
    "You have won a prize! Claim now",
    "Final notice: Invoice overdue",
]

PHISHING_BODIES = [
    "Dear customer, we detected unusual activity on your account. "
    "Click here to verify your identity within 24 hours or your account will be locked: "
    "http://secure-paypa1-verify.com/login",

    "Your package could not be delivered. Confirm your address and pay a small fee here: "
    "http://usps-redelivery-confirm.net/track",

    "Congratulations! You have been selected for a $500 gift card. "
    "Claim your reward before it expires: http://amaz0n-rewards.com/claim",

    "We noticed a login from a new device. If this wasn't you, secure your account immediately: "
    "http://appleid-security-check.com/signin",

    "Your invoice #88213 is overdue. Pay now to avoid service interruption: "
    "http://billing-update-now.info/pay",
]

LEGIT_SUBJECTS = [
    "Q3 planning meeting notes",
    "Lunch tomorrow?",
    "Re: Project timeline update",
    "Weekly team sync agenda",
    "Follow-up from yesterday's call",
]

LEGIT_BODIES = [
    "Hi team, attaching the notes from today's planning meeting. Let me know if I missed anything.",
    "Hey, are you free for lunch tomorrow around noon? Was thinking that new place on 5th.",
    "Following up on the project timeline — looks like we're on track for the Friday deadline.",
    "Agenda for this week's sync: 1) sprint review 2) blockers 3) next sprint planning.",
    "Thanks for hopping on the call yesterday, sending over the summary doc we discussed.",
]

SMS_SPAM = [
    "URGENT! Your bank account has been locked. Verify now: bit.ly/3xk9fake",
    "You've won a free iPhone! Claim here: tinyurl.com/prizewin",
    "Your OTP is required to unlock account, reply with code sent to your phone",
    "Final reminder: unpaid toll balance. Pay now to avoid legal action: pay-toll-now.com",
]

SMS_HAM = [
    "Hey, running 10 mins late, see you soon",
    "Can you pick up milk on the way home?",
    "Meeting moved to 3pm tomorrow",
    "Happy birthday! Hope you have a great day",
]


def make_email_csv(path, subjects, bodies, sender_domain, n=200):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["sender", "subject", "body"])
        writer.writeheader()
        for i in range(n):
            writer.writerow({
                "sender": f"user{i}@{sender_domain}",
                "subject": random.choice(subjects),
                "body": random.choice(bodies),
            })


def make_sms_tsv(path, spam_list, ham_list, n=200):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter="\t")
        for _ in range(n // 2):
            writer.writerow(["spam", random.choice(spam_list)])
            writer.writerow(["ham", random.choice(ham_list)])


if __name__ == "__main__":
    make_email_csv(RAW_DIR / "nazario_phishing.csv", PHISHING_SUBJECTS, PHISHING_BODIES,
                    "mail-security-alerts.com", n=200)
    make_email_csv(RAW_DIR / "enron_legit.csv", LEGIT_SUBJECTS, LEGIT_BODIES,
                    "enron.com", n=200)
    make_sms_tsv(RAW_DIR / "sms_spam_collection.tsv", SMS_SPAM, SMS_HAM, n=200)
    print(f"Sample data written to {RAW_DIR.resolve()}")