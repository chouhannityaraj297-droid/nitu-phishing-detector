"""
Loaders that convert raw dataset files into a list[Message] using the unified schema.
Each loader is defensive: it skips malformed rows and logs a count of skipped
rows rather than crashing the whole pipeline on one bad line.
"""

import csv
import logging
import sys
import uuid
from pathlib import Path
from typing import List

from schema import Message, validate_message

# Some real-world email exports contain very large fields (long HTML bodies,
# embedded content). Raise the CSV module's default limit so these don't crash.
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def load_nazario_phishing(path: str) -> List[Message]:
    """Load the Nazario phishing corpus (real Kaggle CSV export with its own label column)."""
    messages, skipped = [], 0
    p = Path(path)
    if not p.exists():
        logger.warning(f"File not found, skipping: {path}")
        return messages

    with open(p, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                raw_label = row.get("label", "1").strip()
                label = int(raw_label) if raw_label in ("0", "1") else 1

                msg = Message(
                    message_id=_new_id("naz"),
                    channel="email",
                    sender=(row.get("sender") or "").strip() or None,
                    subject=(row.get("subject") or "").strip() or None,
                    body_text=(row.get("body") or "").strip(),
                    label=label,
                    source_dataset="nazario_phishing",
                )
                problems = validate_message(msg)
                if problems:
                    skipped += 1
                    continue
                messages.append(msg)
            except Exception as e:
                logger.debug(f"Skipping malformed row: {e}")
                skipped += 1

    logger.info(f"Loaded {len(messages)} emails from Nazario file ({skipped} skipped)")
    return messages


def load_enron_legit(path: str, max_rows: int = 20000) -> List[Message]:
    """Load Enron emails (real Kaggle CSV export with its own label column)."""
    messages, skipped = [], 0
    p = Path(path)
    if not p.exists():
        logger.warning(f"File not found, skipping: {path}")
        return messages

    with open(p, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            try:
                raw_label = row.get("label", "0").strip()
                label = int(raw_label) if raw_label in ("0", "1") else 0

                msg = Message(
                    message_id=_new_id("enr"),
                    channel="email",
                    sender=(row.get("sender") or "").strip() or None,
                    subject=(row.get("subject") or "").strip() or None,
                    body_text=(row.get("body") or "").strip(),
                    label=label,
                    source_dataset="enron_legit",
                )
                problems = validate_message(msg)
                if problems:
                    skipped += 1
                    continue
                messages.append(msg)
            except Exception as e:
                logger.debug(f"Skipping malformed row: {e}")
                skipped += 1

    logger.info(f"Loaded {len(messages)} emails from Enron file ({skipped} skipped)")
    return messages


def load_sms_spam_collection(path: str) -> List[Message]:
    """Load the UCI SMS Spam Collection (tab-separated: label \t text)."""
    messages, skipped = [], 0
    p = Path(path)
    if not p.exists():
        logger.warning(f"File not found, skipping: {path}")
        return messages

    with open(p, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f, delimiter="\t")
        for row in reader:
            try:
                if len(row) < 2:
                    skipped += 1
                    continue
                label_raw, text = row[0].strip().lower(), row[1].strip()
                label = 1 if label_raw == "spam" else 0
                msg = Message(
                    message_id=_new_id("sms"),
                    channel="sms",
                    sender=None,
                    subject=None,
                    body_text=text,
                    label=label,
                    source_dataset="sms_spam_collection",
                )
                problems = validate_message(msg)
                if problems:
                    skipped += 1
                    continue
                messages.append(msg)
            except Exception as e:
                logger.debug(f"Skipping malformed row: {e}")
                skipped += 1

    logger.info(f"Loaded {len(messages)} SMS messages ({skipped} skipped)")
    return messages


def load_all(raw_dir: str = "../data/raw") -> List[Message]:
    """Convenience entrypoint: load every available dataset and combine."""
    raw = Path(raw_dir)
    all_msgs = []
    all_msgs += load_nazario_phishing(str(raw / "nazario_phishing.csv"))
    all_msgs += load_enron_legit(str(raw / "enron_legit.csv"))
    all_msgs += load_sms_spam_collection(str(raw / "sms_spam_collection.tsv"))

    if not all_msgs:
        logger.warning(
            "No raw datasets found. Run `python make_sample_data.py` to generate "
            "synthetic sample data for testing the pipeline end-to-end."
        )
    return all_msgs