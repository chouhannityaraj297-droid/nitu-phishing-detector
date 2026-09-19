"""
Backend API for the phishing detection system.
Exposes a single endpoint that runs a message through all 3 engines + fusion layer
and returns a risk score with a plain-language explanation.

Run locally with: uvicorn main:app --reload --port 8000
Then test at: http://127.0.0.1:8000/docs (interactive API docs, auto-generated)
"""

import sys
from pathlib import Path

# Allow importing the ml/ folder's modules from here
sys.path.append(str(Path(__file__).parent.parent / "ml"))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict

from fusion import score_message
from content_model import score_content

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
    """
    Analyze a single email/SMS message and return a risk score.
    Now uses the real trained Engine 1 model to score message content.
    """
    content_score = score_content(request.subject, request.body_text)

    result = score_message(
        content_score=content_score,
        urls=request.urls,
        raw_sender=request.raw_sender,
        headers=request.headers,
    )
    return result