"""
Engine 2: URL & Domain Reputation.
Extracts lexical/structural features from a URL, follows redirect chains to
find the real destination, and checks Google Safe Browsing for known threats.
"""

import re
import os
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")

KNOWN_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "facebook", "instagram", "bankofamerica", "chase", "wellsfargo",
    "usps", "fedex", "dhl", "linkedin", "dropbox",
]

SUSPICIOUS_TLDS = {".info", ".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".cf"}


def levenshtein(a: str, b: str) -> int:
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
    features["likely_typosquat"] = 0 < dist <= 2

    return features


def follow_redirects(url: str, max_redirects: int = 5, timeout: int = 5) -> dict:
    """Follow a URL's redirect chain to find its real final destination."""
    try:
        response = requests.head(
            url, allow_redirects=True, timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        chain = [r.url for r in response.history] + [response.url]
        return {
            "final_url": response.url,
            "redirect_count": len(response.history),
            "chain": chain,
            "error": None,
        }
    except requests.RequestException as e:
        return {"final_url": url, "redirect_count": 0, "chain": [url], "error": str(e)}


def check_safe_browsing(url: str) -> dict:
    """Check a URL against Google's Safe Browsing database of known malicious sites."""
    if not SAFE_BROWSING_API_KEY:
        return {"checked": False, "flagged": False, "threat_types": []}

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=5)
        response.raise_for_status()
        data = response.json()
        matches = data.get("matches", [])
        threat_types = [m.get("threatType") for m in matches]
        return {"checked": True, "flagged": len(matches) > 0, "threat_types": threat_types}
    except requests.RequestException as e:
        return {"checked": False, "flagged": False, "threat_types": [], "error": str(e)}


def score_url(url: str, follow_redirect: bool = True) -> dict:
    """Combine structural features + live threat intelligence into a 0-100 risk score."""
    reasons = []
    score = 0

    final_url = url
    if follow_redirect:
        redirect_info = follow_redirects(url)
        final_url = redirect_info["final_url"]
        if redirect_info["redirect_count"] > 0:
            score += min(redirect_info["redirect_count"] * 8, 25)
            reasons.append(f"URL redirects {redirect_info['redirect_count']} time(s) before reaching its final destination")

    safe_browsing = check_safe_browsing(final_url)
    if safe_browsing.get("flagged"):
        score += 60
        reasons.append(f"Flagged by Google Safe Browsing as: {', '.join(safe_browsing['threat_types'])}")

    features = extract_url_features(final_url)
    if features.get("parse_error"):
        return {"score": max(score, 50), "reasons": reasons or ["Could not parse URL"], "features": features}

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
    return {"score": score, "reasons": reasons, "features": features, "final_url": final_url}


if __name__ == "__main__":
    test_urls = [
        "http://secure-paypa1-verify.com/login",
        "https://www.google.com/search?q=test",
        "http://192.168.1.1/admin",
        "http://amaz0n-rewards.info/claim",
        "https://accounts.google.com/signin",
        "http://malware.testing.google.test/testing/malvertising/",
    ]
    for u in test_urls:
        result = score_url(u)
        print(f"\nURL: {u}")
        print(f"  Score: {result['score']}/100")
        for r in result.get("reasons", []):
            print(f"  - {r}")
