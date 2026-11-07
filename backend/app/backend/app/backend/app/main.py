from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="TrustShield-AI API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str
    deep: bool = False

@app.get("/api/health")
def health():
    return {"status": "ok"}

@app.post("/api/scan")
def scan(req: ScanRequest):
    return {
        "url": req.url,
        "domain": "example.com",
        "trust_score": 23,
        "verdict": "dangerous",
        "reasons": [
            "Domain registered 3 days ago",
            "Login form posts to another domain",
        ],
        "modules": {
            "threat": {"risk": 80, "checks": []},
            "web_security": {"risk": 40, "checks": []},
            "certificate": {"risk": 60, "checks": []},
            "community": {"risk": 0, "checks": []},
        },
    }