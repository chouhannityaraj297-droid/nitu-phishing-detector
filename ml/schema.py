"""
Unified schema for all ingested messages (email or SMS), regardless of source dataset.
Every loader in data_loaders.py must output records matching this shape.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional
import re

URL_REGEX = re.compile(r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+', re.IGNORECASE)


@dataclass
class Message:
    """Unified representation of an email or SMS for the phishing pipeline."""
    message_id: str
    channel: str  # "email" or "sms"
    sender: Optional[str]  # raw sender address/number as it appeared
    subject: Optional[str]  # None for SMS
    body_text: str
    urls: List[str] = field(default_factory=list)
    headers: dict = field(default_factory=dict)  # raw headers, e.g. Authentication-Results
    label: Optional[int] = None  # 1 = phishing, 0 = legitimate, None = unlabeled
    source_dataset: str = ""  # which raw dataset this came from, for traceability

    def __post_init__(self):
        # Auto-extract URLs from body if not already provided
        if not self.urls:
            self.urls = extract_urls(self.body_text)

    def to_dict(self):
        return asdict(self)


def extract_urls(text: str) -> List[str]:
    """Pull all URL-like substrings out of a text blob."""
    if not text:
        return []
    return URL_REGEX.findall(text)


def validate_message(msg: Message) -> List[str]:
    """Return a list of validation problems (empty list = valid)."""
    problems = []
    if not msg.body_text or not msg.body_text.strip():
        problems.append("empty body_text")
    if msg.channel not in ("email", "sms"):
        problems.append(f"invalid channel: {msg.channel}")
    if msg.label is not None and msg.label not in (0, 1):
        problems.append(f"invalid label: {msg.label}")
    return problems