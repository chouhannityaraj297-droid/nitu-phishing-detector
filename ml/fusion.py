"""
Fusion Layer: combines Engine 1 (NLP content), Engine 2 (URL/domain reputation),
and Engine 3 (sender/behavior) into a single 0-100 risk score with a plain-language
explanation.
"""

from url_features import score_url
from sender_behavior import score_sender_behavior

WEIGHTS = {
    "content": 0.30,
    "url": 0.30,
    "sender": 0.40,
}

THRESHOLDS = {
    "safe": 30,
    "caution": 70,
}


def classify_score(score: float) -> str:
    if score < THRESHOLDS["safe"]:
        return "Safe"
    elif score < THRESHOLDS["caution"]:
        return "Caution"
    else:
        return "Dangerous"


def score_message(content_score: float, urls: list, raw_sender: str, body_text: str = "", headers: dict = None) -> dict:
    url_results = [score_url(u) for u in urls] if urls else []
    worst_url_score = max((r["score"] for r in url_results), default=0)
    url_reasons = []
    if url_results:
        worst = max(url_results, key=lambda r: r["score"])
        url_reasons = worst.get("reasons", [])

    sender_result = score_sender_behavior(raw_sender, body_text=body_text, headers=headers)
    sender_score = sender_result["score"]
    sender_reasons = sender_result["reasons"]

    final_score = (
        content_score * WEIGHTS["content"]
        + worst_url_score * WEIGHTS["url"]
        + sender_score * WEIGHTS["sender"]
    )
    final_score = round(min(final_score, 100), 1)
    verdict = classify_score(final_score)

    all_reasons = []
    if content_score >= 50:
        all_reasons.append("The message text uses language typical of phishing attempts")
    all_reasons += url_reasons
    all_reasons += sender_reasons

    return {
        "final_score": final_score,
        "verdict": verdict,
        "sub_scores": {
            "content": content_score,
            "url": worst_url_score,
            "sender": sender_score,
        },
        "reasons": all_reasons,
    }


if __name__ == "__main__":
    test_message = {
        "content_score": 85,
        "urls": ["http://secure-paypa1-verify.com/login"],
        "raw_sender": '"PayPal Support" <security@random-domain.com>',
        "body_text": "Verify your account now.",
        "headers": {"Authentication-Results": "spf=fail dkim=fail dmarc=fail"},
    }

    result = score_message(**test_message)
    print(f"Final score: {result['final_score']}/100 -> {result['verdict']}")
    print(f"Sub-scores: {result['sub_scores']}")
    print("Why flagged:")
    for r in result["reasons"]:
        print(f"  - {r}")

    print("\n" + "=" * 50)

    test_message_2 = {
        "content_score": 5,
        "urls": [],
        "raw_sender": '"Jane Smith" <jane.smith@enron.com>',
        "body_text": "Quick update on the timeline.",
        "headers": {"Authentication-Results": "spf=pass dkim=pass dmarc=pass"},
    }
    result2 = score_message(**test_message_2)
    print(f"Final score: {result2['final_score']}/100 -> {result2['verdict']}")
    print(f"Sub-scores: {result2['sub_scores']}")
    print("Why flagged:")
    for r in result2["reasons"]:
        print(f"  - {r}")
