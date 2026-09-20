"""
Trains a lightweight TF-IDF + Logistic Regression phishing classifier.
Uses only a few MB of memory (vs. hundreds of MB for the transformer model),
making it suitable for free-tier cloud hosting.
"""

import json
import joblib
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report

PROCESSED_DIR = Path("../data/processed")
MODEL_OUT = Path("lightweight_model.joblib")
VECTORIZER_OUT = Path("lightweight_vectorizer.joblib")


def load_jsonl(path):
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            records.append(json.loads(line))
    return records


def prepare(records):
    texts = [f"{r.get('subject') or ''} {r.get('body_text') or ''}".strip() for r in records]
    labels = [r["label"] for r in records]
    return texts, labels


if __name__ == "__main__":
    train_records = load_jsonl(PROCESSED_DIR / "train.jsonl")
    test_records = load_jsonl(PROCESSED_DIR / "test.jsonl")

    train_texts, train_labels = prepare(train_records)
    test_texts, test_labels = prepare(test_records)

    print(f"Training on {len(train_texts)} examples...")

    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
    X_train = vectorizer.fit_transform(train_texts)
    X_test = vectorizer.transform(test_texts)

    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, train_labels)

    preds = model.predict(X_test)
    print("\nTest set performance:")
    print(classification_report(test_labels, preds, target_names=["Legitimate", "Phishing"]))

    joblib.dump(model, MODEL_OUT)
    joblib.dump(vectorizer, VECTORIZER_OUT)
    print(f"\nSaved model to {MODEL_OUT} and vectorizer to {VECTORIZER_OUT}")