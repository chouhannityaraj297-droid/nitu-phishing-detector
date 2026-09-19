"""
Engine 1: NLP Content Model — inference wrapper.
Loads the fine-tuned DistilBERT model (trained in Colab, Phase 2) and exposes
a simple function to score a piece of text as phishing (0-100).

The model is loaded ONCE at import time (not per-request), since loading a
transformer model is slow (~1-2 seconds) — reusing one loaded instance is what
makes real-time scoring fast enough for a live API.
"""

import torch
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification

MODEL_DIR = Path(__file__).parent / "phishing_nlp_model"

print("Loading Engine 1 NLP model... (this happens once, at startup)")
_tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR))
_model = AutoModelForSequenceClassification.from_pretrained(str(MODEL_DIR))
_model.eval()  # inference mode, not training mode
print("Engine 1 model loaded.")


def score_content(subject: str, body_text: str) -> float:
    """
    Run the trained model on a subject+body pair and return a 0-100 phishing score.
    """
    text = f"{subject or ''} {body_text or ''}".strip()
    inputs = _tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=256)

    with torch.no_grad():
        outputs = _model(**inputs)
        probs = torch.softmax(outputs.logits, dim=1)
        phishing_prob = probs[0][1].item()  # index 1 = "phishing" class

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