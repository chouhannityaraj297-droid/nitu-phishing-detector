"""
Fusion Layer: combines Engine 1 (NLP content), Engine 2 (URL/domain reputation),
and Engine 3 (sender/behavior) into a single 0-100 risk score with a plain-language
explanation.

For now this uses a weighted-average approach (simple, interpretable, no extra
training data needed). Once you have real labeled data with all 3 sub-scores,
you can swap this for a trained LightGBM/XGBoost meta-model — see the note at
the bottom of this file for how that upgrade would slot in.
"""

from url_features import score_url
from sender_behavior import score_sender_behavior

# Weights reflect roughly how much each engine's signal should count.
# Sender/behavior is weighted highest since it's the strongest zero-day defense.
WEIGHTS = {
    "content": 0.30,
    "url": 0.30,
    "sender": 0.40,
}

THRESHOLDS = {
    "safe": 30,
    "caution": 70,
    # anything above "caution" threshold = "dangerous"
}


def classify_score(score: float) -> str:
    if score < THRESHOLDS["safe"]:
        return "Safe"
    elif score < THRESHOLDS["caution"]:
        return "Caution"
    else:
        return "Dangerous"


def score_message(content_score: float, urls: list, raw_sender: str, headers: dict = None) -> dict:
    """
    content_score: 0-100 score from Engine 1 (NLP model). Pass this in after
                   running your trained model's prediction — see note below on
                   how to plug in the real model's output instead of a placeholder.
    urls: list of URLs found in the message body.
    raw_sender: the raw "From" header string, e.g. '"PayPal" <a@b.com>'.
    headers: dict of email headers, used for SPF/DKIM/DMARC checks.
    """
    # --- Engine 2: score every URL in the message, take the worst one ---
    url_results = [score_url(u) for u in urls] if urls else []
    worst_url_score = max((r["score"] for r in url_results), default=0)
    url_reasons = []
    if url_results:
        worst = max(url_results, key=lambda r: r["score"])
        url_reasons = worst.get("reasons", [])

    # --- Engine 3: sender/behavior ---
    sender_result = score_sender_behavior(raw_sender, headers)
    sender_score = sender_result["score"]
    sender_reasons = sender_result["reasons"]

    # --- Fusion: weighted combination ---
    final_score = (
        content_score * WEIGHTS["content"]
        + worst_url_score * WEIGHTS["url"]
        + sender_score * WEIGHTS["sender"]
    )
    final_score = round(min(final_score, 100), 1)
    verdict = classify_score(final_score)

    # --- Plain-language explanation, built from top contributing reasons ---
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
    # Example: a fake PayPal phishing email
    test_message = {
        "content_score": 85,  # placeholder — normally comes from Engine 1's model
        "urls": ["http://secure-paypa1-verify.com/login"],
        "raw_sender": '"PayPal Support" <security@random-domain.com>',
        "headers": {"Authentication-Results": "spf=fail dkim=fail dmarc=fail"},
    }

    result = score_message(**test_message)
    print(f"Final score: {result['final_score']}/100 -> {result['verdict']}")
    print(f"Sub-scores: {result['sub_scores']}")
    print("Why flagged:")
    for r in result["reasons"]:
        print(f"  - {r}")

    print("\n" + "=" * 50)

    # Example: a legitimate colleague email
    test_message_2 = {
        "content_score": 5,
        "urls": [],
        "raw_sender": '"Jane Smith" <jane.smith@enron.com>',
        "headers": {"Authentication-Results": "spf=pass dkim=pass dmarc=pass"},
    }
    result2 = score_message(**test_message_2)
    print(f"Final score: {result2['final_score']}/100 -> {result2['verdict']}")
    print(f"Sub-scores: {result2['sub_scores']}")
    print("Why flagged:")
    for r in result2["reasons"]:
        print(f"  - {r}")