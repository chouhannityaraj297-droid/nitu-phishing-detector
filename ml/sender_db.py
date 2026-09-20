"""
Persistent sender/behavior tracking using SQLite.
Replaces the old JSON-file approach with a real database, and adds
writing-style fingerprinting to detect possible compromised accounts.
"""

import sqlite3
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(__file__).parent / "sender_history.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS senders (
            address TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            message_count INTEGER NOT NULL DEFAULT 0,
            avg_length REAL NOT NULL DEFAULT 0,
            avg_exclamation_rate REAL NOT NULL DEFAULT 0,
            avg_uppercase_rate REAL NOT NULL DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


def _style_features(text: str) -> dict:
    text = text or ""
    length = len(text)
    exclam_rate = text.count("!") / max(length, 1)
    letters = [c for c in text if c.isalpha()]
    upper_rate = sum(1 for c in letters if c.isupper()) / max(len(letters), 1)
    return {"length": length, "exclam_rate": exclam_rate, "upper_rate": upper_rate}


def get_sender(address: str):
    conn = get_connection()
    row = conn.execute("SELECT * FROM senders WHERE address = ?", (address.lower().strip(),)).fetchone()
    conn.close()
    return dict(row) if row else None


def record_sender_seen(address: str, body_text: str = ""):
    address = address.lower().strip()
    now = datetime.now(timezone.utc).isoformat()
    style = _style_features(body_text)

    conn = get_connection()
    existing = conn.execute("SELECT * FROM senders WHERE address = ?", (address,)).fetchone()

    if existing is None:
        conn.execute(
            "INSERT INTO senders (address, first_seen, last_seen, message_count, avg_length, avg_exclamation_rate, avg_uppercase_rate) VALUES (?, ?, ?, 1, ?, ?, ?)",
            (address, now, now, style["length"], style["exclam_rate"], style["upper_rate"]),
        )
    else:
        n = existing["message_count"]
        new_n = n + 1
        new_len = existing["avg_length"] + (style["length"] - existing["avg_length"]) / new_n
        new_exc = existing["avg_exclamation_rate"] + (style["exclam_rate"] - existing["avg_exclamation_rate"]) / new_n
        new_upp = existing["avg_uppercase_rate"] + (style["upper_rate"] - existing["avg_uppercase_rate"]) / new_n
        conn.execute(
            "UPDATE senders SET last_seen = ?, message_count = ?, avg_length = ?, avg_exclamation_rate = ?, avg_uppercase_rate = ? WHERE address = ?",
            (now, new_n, new_len, new_exc, new_upp, address),
        )

    conn.commit()
    conn.close()


def check_style_deviation(address: str, body_text: str) -> dict:
    sender = get_sender(address)
    if sender is None or sender["message_count"] < 3:
        return {"has_baseline": False, "deviation_score": 0, "reasons": []}

    style = _style_features(body_text)
    reasons = []
    deviation = 0

    len_ratio = style["length"] / max(sender["avg_length"], 1)
    if len_ratio > 3 or len_ratio < 0.2:
        deviation += 15
        reasons.append("Message length is very different from this sender's usual messages")

    if style["exclam_rate"] > sender["avg_exclamation_rate"] * 4 and style["exclam_rate"] > 0.02:
        deviation += 15
        reasons.append("Unusually high use of exclamation marks compared to this sender's normal style")

    if style["upper_rate"] > sender["avg_uppercase_rate"] * 3 and style["upper_rate"] > 0.15:
        deviation += 15
        reasons.append("Unusually high use of capital letters compared to this sender's normal style")

    return {
        "has_baseline": True,
        "deviation_score": min(deviation, 45),
        "reasons": reasons,
        "message_count": sender["message_count"],
    }


init_db()

if __name__ == "__main__":
    print("Testing sender_db module...")
    test_address = "jane.smith@enron.com"

    for i in range(5):
        record_sender_seen(test_address, "Hey, just checking in about the project timeline.")

    print("Sender record after 5 normal messages:")
    print(get_sender(test_address))

    normal_check = check_style_deviation(test_address, "Quick update on the timeline.")
    print("Normal follow-up message deviation check:")
    print(normal_check)

    suspicious_check = check_style_deviation(test_address, "URGENT!!! CLICK HERE NOW TO VERIFY YOUR ACCOUNT IMMEDIATELY!!! http://fake-link.com")
    print("Suspicious message deviation check:")
    print(suspicious_check)
