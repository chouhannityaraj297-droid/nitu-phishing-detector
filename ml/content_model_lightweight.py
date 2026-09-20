"""
Lightweight Engine 1 inference wrapper, using TF-IDF + Logistic Regression
instead of DistilBERT. Uses only a few MB of memory, making it suitable for
free-tier cloud deployment where the full transformer model doesn't fit.
"""

import joblib
from pathlib import Path

MODEL_PATH = Path(__file__).parent / "lightweight_model.joblib"
VECTORIZER_PATH = Path(__file__).parent / "lightweight_vectorizer.joblib"

print("Loading lightweight Engine 1 model...")
_model = joblib.load(MODEL_PATH)
_vectorizer = joblib.load(VECTORIZER_PATH)
print("Lightweight Engine 1 model loaded.")


def score_content(subject: str, body_text: str) -> float:
    """
    Run the lightweight model on a subject+body pair and return a 0-100 phishing score.
    """
    text = f"{subject or ''} {body_text or ''}".strip()
    X = _vectorizer.transform([text])
    phishing_prob = _model.predict_proba(X)[0][1]
    return round(phishing_prob * 100, 1)


if __name__ == "__main__":
    test_cases = [
        ("Urgent: Verify your account", "Click here immediately to avoid suspension: http://fake-link.com"),
        ("Lunch tomorrow?", "Hey, are you free for lunch tomorrow around noon?"),
    ]
    for subject, body in test_cases:
        score = score_content(subject, body)
        print(f"\nSubject: {subject}")
        print(f"Score: {score}/100")
