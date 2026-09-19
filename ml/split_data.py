"""
Splits loaded messages into stratified train/val/test sets and writes them
to data/processed/ as JSONL, ready for Phase 2 model training.
"""

import json
import logging
import random
from collections import defaultdict
from pathlib import Path

from data_loaders import load_all

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

RANDOM_SEED = 42
TRAIN_RATIO = 0.70
VAL_RATIO = 0.15

PROCESSED_DIR = Path("../data/processed")


def stratified_split(messages, train_ratio=TRAIN_RATIO, val_ratio=VAL_RATIO, seed=RANDOM_SEED):
    """Split messages into train/val/test, preserving label balance in each split."""
    random.seed(seed)

    by_label = defaultdict(list)
    for m in messages:
        by_label[m.label].append(m)

    train, val, test = [], [], []
    for label, group in by_label.items():
        shuffled = group[:]
        random.shuffle(shuffled)
        n = len(shuffled)
        n_train = int(n * train_ratio)
        n_val = int(n * val_ratio)

        train += shuffled[:n_train]
        val += shuffled[n_train:n_train + n_val]
        test += shuffled[n_train + n_val:]

        logger.info(f"Label {label}: {n} total -> train {n_train}, val {n_val}, test {n - n_train - n_val}")

    random.shuffle(train)
    random.shuffle(val)
    random.shuffle(test)
    return train, val, test


def write_jsonl(messages, path):
    with open(path, "w", encoding="utf-8") as f:
        for m in messages:
            f.write(json.dumps(m.to_dict()) + "\n")
    logger.info(f"Wrote {len(messages)} records to {path}")


if __name__ == "__main__":
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    messages = load_all()
    if not messages:
        raise SystemExit("No messages loaded — run make_sample_data.py first or add real datasets to data/raw/")

    train, val, test = stratified_split(messages)

    write_jsonl(train, PROCESSED_DIR / "train.jsonl")
    write_jsonl(val, PROCESSED_DIR / "val.jsonl")
    write_jsonl(test, PROCESSED_DIR / "test.jsonl")

    total = len(train) + len(val) + len(test)
    logger.info(f"Split complete: {len(train)} train / {len(val)} val / {len(test)} test ({total} total)")
    