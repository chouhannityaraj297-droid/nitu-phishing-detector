"""
Engine 3: Sender & Behavior.
Scores how suspicious a message's sender identity and behavior pattern look,
independent of content or URLs. This is the strongest defense against zero-day
attacks, since it flags deviation from "normal" rather than known bad patterns.

Uses a simple local JSON file as a stand-in "relationship graph" (who has this
user received mail from before, and how often). In the real backend, this would
be a database table instead.
"""

import json
import re
from datetime import datetime
from pathlib import Path

HISTORY_FILE = Path("../data/processed/sender_history.json")

# Brand names commonly spoofed in the "display name" field
# (e.g. display name says "PayPal Support" but the actual address is unrelated).
KNOWN_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "facebook", "bankofamerica", "chase", "wellsfargo", "usps", "fedex",
]


def load_history() -> dict:
    """Load the sender relationship history from disk (empty dict if none yet)."""
    if HISTORY_FILE.exists():
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_history(history: dict):
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)


def record_sender_seen(sender_address: str, history: dict = None) -> dict:
    """
    Update (or create) a sender's history entry with a new 'seen' event.
    Call this AFTER scoring a message as legitimate/handled, not before —
    otherwise a first-time phishing sender would count as "known" on its own message.
    """
    if history is None:
        history = load_history()

    key = sender_address.lower().strip()
    now = datetime.utcnow().isoformat()

    if key not in history:
        history[key] = {"first_seen": now, "last_seen": now, "message_count": 1}
    else:
        history[key]["last_seen"] = now
        history[key]["message_count"] += 1

    save_history(history)
    return history


def parse_display_name_mismatch(raw_sender: str) -> dict:
    """
    Detect when a display name claims a known brand but the actual email
    address domain doesn't match that brand.
    e.g. raw_sender = '"PayPal Support" <security@random-domain.com>'
    """
    match = re.match(r'^"?([^"<]*)"?\s*<?([\w.+-]+@[\w.-]+)>?$', raw_sender.strip())
    if not match:
        return {"display_name": None, "address": raw_sender, "mismatch": False, "claimed_brand": None}

    display_name, address = match.group(1).strip(), match.group(2).strip().lower()
    domain = address.split("@")[-1]

    display_lower = display_name.lower()
    for brand in KNOWN_BRANDS:
        if brand in display_lower and brand not in domain:
            return {
                "display_name": display_name,
                "address": address,
                "mismatch": True,
                "claimed_brand": brand,
            }

    return {"display_name": display_name, "address": address, "mismatch": False, "claimed_brand": None}


def check_auth_headers(headers: dict) -> dict:
    """
    Parse SPF/DKIM/DMARC results from an email's Authentication-Results header.
    Most mail servers already stamp this — we just read it, not re-implement the checks.
    Expects headers dict with a key like 'Authentication-Results' containing text such as:
      "spf=pass dkim=pass dmarc=pass"
    """
    auth_text = (headers or {}).get("Authentication-Results", "").lower()

    def extract_result(mechanism):
        match = re.search(rf"{mechanism}=(\w+)", auth_text)
        return match.group(1) if match else "none"

    return {
        "spf": extract_result("spf"),
        "dkim": extract_result("dkim"),
        "dmarc": extract_result("dmarc"),
    }


def score_sender_behavior(raw_sender: str, headers: dict = None, history: dict = None) -> dict:
    """
    Combine sender identity + history + auth checks into a 0-100 risk score.
    Higher score = more suspicious.
    """
    if history is None:
        history = load_history()

    score = 0
    reasons = []

    # 1. Display name vs. address mismatch (brand impersonation)
    identity = parse_display_name_mismatch(raw_sender)
    if identity["mismatch"]:
        score += 35
        reasons.append(
            f"Display name claims to be '{identity['claimed_brand']}' but the address domain doesn't match"
        )

    # 2. First-contact check
    address = identity["address"] or raw_sender.lower().strip()
    is_first_contact = address not in history
    if is_first_contact:
        score += 15
        reasons.append("First time this user has received a message from this sender")
    else:
        msg_count = history[address]["message_count"]
        if msg_count < 3:
            score += 5
            reasons.append("Sender has very limited message history with this user")

    # 3. Auth header checks (SPF/DKIM/DMARC)
    auth = check_auth_headers(headers)
    if auth["spf"] == "fail":
        score += 20
        reasons.append("SPF authentication failed")
    if auth["dkim"] == "fail":
        score += 20
        reasons.append("DKIM authentication failed")
    if auth["dmarc"] == "fail":
        score += 15
        reasons.append("DMARC authentication failed")
    if auth["spf"] == "none" and auth["dkim"] == "none":
        score += 5
        reasons.append("No authentication headers present to verify sender")

    score = min(score, 100)
    return {
        "score": score,
        "reasons": reasons,
        "identity": identity,
        "auth": auth,
        "is_first_contact": is_first_contact,
    }


if __name__ == "__main__":
    test_cases = [
        {
            "raw_sender": '"PayPal Support" <security@random-domain.com>',
            "headers": {"Authentication-Results": "spf=fail dkim=fail dmarc=fail"},
        },
        {
            "raw_sender": '"Jane Smith" <jane.smith@enron.com>',
            "headers": {"Authentication-Results": "spf=pass dkim=pass dmarc=pass"},
        },
        {
            "raw_sender": '"Amazon" <no-reply@amazon.com>',
            "headers": {"Authentication-Results": "spf=pass dkim=pass dmarc=pass"},
        },
    ]

    for case in test_cases:
        result = score_sender_behavior(case["raw_sender"], case["headers"])
        print(f"\nSender: {case['raw_sender']}")
        print(f"  Score: {result['score']}/100")
        for r in result["reasons"]:
            print(f"  - {r}")