"""
Engine 3: Sender & Behavior.
Scores how suspicious a message's sender identity and behavior pattern look,
independent of content or URLs. Uses persistent SQLite-based tracking
(sender_db.py), and includes writing-style deviation detection to catch
possible compromised accounts once enough history exists for a sender.
"""

import re
from sender_db import check_style_deviation, get_sender

KNOWN_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "facebook", "bankofamerica", "chase", "wellsfargo", "usps", "fedex",
]


def parse_display_name_mismatch(raw_sender: str) -> dict:
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
    auth_text = (headers or {}).get("Authentication-Results", "").lower()

    def extract_result(mechanism):
        match = re.search(rf"{mechanism}=(\w+)", auth_text)
        return match.group(1) if match else "none"

    return {
        "spf": extract_result("spf"),
        "dkim": extract_result("dkim"),
        "dmarc": extract_result("dmarc"),
    }


def score_sender_behavior(raw_sender: str, body_text: str = "", headers: dict = None) -> dict:
    """
    Combine sender identity + auth checks + writing-style deviation into a
    0-100 risk score. Higher score = more suspicious.
    """
    score = 0
    reasons = []

    identity = parse_display_name_mismatch(raw_sender)
    if identity["mismatch"]:
        score += 35
        reasons.append(f"Display name claims to be '{identity['claimed_brand']}' but the address domain doesn't match")

    address = identity["address"] or raw_sender.lower().strip()

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

    # Is this genuinely the first message ever seen from this address?
    existing_sender = get_sender(address)
    is_first_contact = existing_sender is None

    if is_first_contact:
        score += 15
        reasons.append("First time this user has received a message from this sender")
    elif existing_sender["message_count"] < 3:
        # Established but not enough history yet for a style baseline - low risk, no penalty
        pass
    else:
        style_check = check_style_deviation(address, body_text)
        score += style_check["deviation_score"]
        reasons.extend(style_check["reasons"])

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
            "body_text": "Verify your account now.",
            "headers": {"Authentication-Results": "spf=fail dkim=fail dmarc=fail"},
        },
        {
            "raw_sender": '"Jane Smith" <jane.smith@enron.com>',
            "body_text": "Quick update on the timeline.",
            "headers": {"Authentication-Results": "spf=pass dkim=pass dmarc=pass"},
        },
    ]

    for case in test_cases:
        result = score_sender_behavior(case["raw_sender"], case["body_text"], case["headers"])
        print(f"\nSender: {case['raw_sender']}")
        print(f"  Score: {result['score']}/100")
        for r in result["reasons"]:
            print(f"  - {r}")
