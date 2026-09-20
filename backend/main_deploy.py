"""
Deployment version of the backend API — uses the lightweight TF-IDF model
instead of DistilBERT, to fit within free-tier cloud memory limits.
"""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent / "ml"))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict

from fusion import score_message
from content_model_lightweight import score_content

app = FastAPI(title="Phishing Detection API (Lightweight)", version="0.1.0")

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
    return {"status": "ok", "message": "Phishing Detection API (Lightweight) is running"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_message(request: AnalyzeRequest):
    content_score = score_content(request.subject, request.body_text)

    result = score_message(
        content_score=content_score,
        urls=request.urls,
        raw_sender=request.raw_sender,
        headers=request.headers,
    )
    return result
