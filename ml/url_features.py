"""
Engine 2: URL & Domain Reputation.
Extracts lexical/structural features from a URL to score how suspicious it looks,
without needing a live network call (fast, works offline, catches zero-day domains
that no blocklist has seen yet).
"""

import re
from urllib.parse import urlparse

# A small list of commonly impersonated brands, for typosquatting checks.
# Extend this list over time with brands relevant to your users.
KNOWN_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "facebook", "instagram", "bankofamerica", "chase", "wellsfargo",
    "usps", "fedex", "dhl", "linkedin", "dropbox",
]

SUSPICIOUS_TLDS = {".info", ".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".cf"}


def levenshtein(a: str, b: str) -> int:
    """Classic edit-distance calculation, used for typosquatting detection."""
    if len(a) < len(b):
        return levenshtein(b, a)
    if len(b) == 0:
        return len(a)

    previous_row = range(len(b) + 1)
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def closest_brand_distance(domain: str):
    """
    Return (brand, distance) for the closest known brand found anywhere in the domain.
    Checks each hyphen/dot-separated chunk individually, so "secure-paypa1-verify.com"
    correctly matches the "paypa1" chunk against "paypal", not the whole domain string.
    """
    domain_core = domain.split(".")[0].lower()
    chunks = re.split(r"[-_]", domain_core)

    best_brand, best_dist = None, 999
    for chunk in chunks:
        for brand in KNOWN_BRANDS:
            dist = levenshtein(chunk, brand)
            if dist < best_dist:
                best_brand, best_dist = brand, dist
    return best_brand, best_dist


def extract_url_features(url: str) -> dict:
    """Return a dict of structural/lexical features for a single URL."""
    features = {}
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
    except Exception:
        return {"parse_error": True}

    domain = parsed.netloc.lower()
    path = parsed.path or ""

    features["url_length"] = len(url)
    features["domain_length"] = len(domain)
    features["path_length"] = len(path)
    features["subdomain_count"] = max(domain.count("."), 0)
    features["has_ip_literal"] = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))
    features["has_punycode"] = "xn--" in domain
    features["has_at_symbol"] = "@" in url
    features["uses_https"] = parsed.scheme == "https"
    features["hyphen_count_domain"] = domain.count("-")
    features["digit_count_domain"] = sum(c.isdigit() for c in domain)

    tld = "." + domain.split(".")[-1] if "." in domain else ""
    features["suspicious_tld"] = tld in SUSPICIOUS_TLDS

    brand, dist = closest_brand_distance(domain)
    features["closest_brand"] = brand
    features["brand_edit_distance"] = dist
    # Distance of 1-2 from a real brand name (but not an exact match) is the
    # classic typosquat signature, e.g. "paypa1" vs "paypal".
    features["likely_typosquat"] = 0 < dist <= 2

    return features


def score_url(url: str) -> dict:
    """
    Combine features into a 0-100 risk score for a single URL.
    Higher score = more suspicious. This is a simple weighted rule set for now —
    swap in a trained ML classifier later once you have labeled URL data.
    """
    features = extract_url_features(url)
    if features.get("parse_error"):
        return {"score": 50, "reason": "Could not parse URL", "features": features}

    score = 0
    reasons = []

    if features["has_ip_literal"]:
        score += 30
        reasons.append("URL uses a raw IP address instead of a domain name")
    if features["has_punycode"]:
        score += 25
        reasons.append("Domain uses punycode (can hide look-alike characters)")
    if features["has_at_symbol"]:
        score += 20
        reasons.append("URL contains an '@' symbol (can hide the real destination)")
    if features["likely_typosquat"]:
        score += 35
        reasons.append(f"Domain looks like a misspelling of '{features['closest_brand']}'")
    if features["suspicious_tld"]:
        score += 15
        reasons.append("Domain uses a TLD commonly abused for phishing")
    if features["subdomain_count"] >= 3:
        score += 10
        reasons.append("Unusually high number of subdomains")
    if not features["uses_https"]:
        score += 10
        reasons.append("Connection is not encrypted (no HTTPS)")
    if features["hyphen_count_domain"] >= 3:
        score += 10
        reasons.append("Domain contains an unusual number of hyphens")

    score = min(score, 100)
    return {"score": score, "reasons": reasons, "features": features}


if __name__ == "__main__":
    test_urls = [
        "http://secure-paypa1-verify.com/login",
        "https://www.google.com/search?q=test",
        "http://192.168.1.1/admin",
        "http://amaz0n-rewards.info/claim",
        "https://accounts.google.com/signin",
    ]
    for u in test_urls:
        result = score_url(u)
        print(f"\nURL: {u}")
        print(f"  Score: {result['score']}/100")
        for r in result.get("reasons", []):
            print(f"  - {r}")