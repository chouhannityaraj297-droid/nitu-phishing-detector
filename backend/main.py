"""
Backend API for the phishing detection system (local version).
Runs the full DistilBERT model for Engine 1.
"""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent / "ml"))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict

from fusion import score_message
from content_model import score_content
from sender_db import record_sender_seen
from sender_behavior import parse_display_name_mismatch

app = FastAPI(title="Phishing Detection API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://mail.google.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    body_text: str
    subject: Optional[str] = None
    urls: List[str] = []
    raw_sender: str
    headers: Dict[str, str] = {}


class AnalyzeResponse(BaseModel):
    final_score: float
    verdict: str
    sub_scores: Dict[str, float]
    reasons: List[str]


@app.get("/")
def root():
    return {"status": "ok", "message": "Phishing Detection API is running"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_message(request: AnalyzeRequest):
    content_score = score_content(request.subject, request.body_text)

    result = score_message(
        content_score=content_score,
        urls=request.urls,
        raw_sender=request.raw_sender,
        body_text=request.body_text,
        headers=request.headers,
    )

    identity = parse_display_name_mismatch(request.raw_sender)
    address = identity["address"] or request.raw_sender
    record_sender_seen(address, request.body_text)

    return result
