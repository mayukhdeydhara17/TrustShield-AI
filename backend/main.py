
import os
import socket
import ipaddress

from urllib.parse import urlparse, urlunparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.security.phishing_engine import PhishingDetectionEngine
from backend.security.website_security import analyze_website_security
from backend.security.ssl_checker import check_ssl as analyze_ssl


app = FastAPI(title="TrustShield AI API")


# CORS configuration
allowed_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

deployed_frontend = os.getenv("FRONTEND_URL")

if deployed_frontend:
    allowed_origins.append(deployed_frontend.rstrip("/"))


app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str
    
SSL_FALLBACK = {
    "https_available": False,
    "ssl_valid": False,
    "status": "unavailable",
    "message": "SSL check could not be completed.",
}

WEBSITE_SECURITY_FALLBACK = {
    "issues": [],
    "errors": ["unavailable"],
    "risk_points": 0,
    "rating": "UNKNOWN",
    "summary": "Website security analysis unavailable.",
}


def run_safely(function, fallback, *args):
    """Run an analysis step; if it crashes, return a fallback so /scan still works."""
    try:
        return function(*args)
    except Exception as error:
        print(f"[TrustShield] {function.__name__} failed: {error}")
        return fallback


# STEP 1: Normalize and validate URL
def validate_url(url: str):

    url = url.strip()

    if not url:
        raise ValueError("Please enter a website URL.")

    # Add HTTPS if scheme is missing
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme not in ["http", "https"]:
        raise ValueError("Only HTTP and HTTPS URLs are allowed.")

    if not parsed.hostname:
        raise ValueError("Invalid website URL.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed.")

    host = parsed.hostname.lower()

    # Validate port
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid port number.")

    if port not in [None, 80, 443]:
        raise ValueError("Only standard HTTP and HTTPS ports are allowed.")

    # Block local addresses
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("Local addresses cannot be scanned.")

    try:
        addresses = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ValueError("Website domain could not be resolved.")

    # Block private and restricted IP addresses
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])

        if not ip.is_global:
            raise ValueError(
                "Private or restricted addresses are blocked."
            )

    normalized_url = urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.params,
            parsed.query,
            parsed.fragment
        )
    )

    return normalized_url, host


@app.get("/")
def home():
    return {
        "message": "TrustShield AI backend is working!"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


# STEP 2: Main website scanning endpoint
@app.post("/scan")
def scan_website(request: ScanRequest):

    try:

        # Normalize and validate URL
        normalized_url, host = validate_url(request.url)

        parsed = urlparse(normalized_url)

        # STEP 3: Phishing detection engine
        engine = PhishingDetectionEngine(normalized_url)

        phishing_report = engine.generate_risk_assessment()

        score = phishing_report["risk_score"]

        reasons = phishing_report["reasons"].copy()

        # STEP 4: SSL assessment
        ssl_valid = None
        ssl_report = None

        if parsed.scheme == "https":

            ssl_report = run_safely(analyze_ssl, SSL_FALLBACK, normalized_url)

            ssl_valid = ssl_report["ssl_valid"]

            if ssl_report["status"] in [
                "invalid",
                "expired",
                "no_https",
                "error"
            ]:

                score += 25

                reasons.append(
                    f"SSL problem: {ssl_report['message']}"
                )

            elif ssl_report["status"] == "expiring_soon":

                score += 10

                reasons.append(
                    ssl_report["message"]
                )

        else:

            # HTTP does not provide encrypted transport
            score += 10

            reasons.append(
                "Website uses HTTP instead of encrypted HTTPS."
            )

        # STEP 5: Website security assessment
            website_security = run_safely(
            analyze_website_security,
            WEBSITE_SECURITY_FALLBACK,
            normalized_url,
            ssl_report
        )

        score += website_security["risk_points"]

        for issue in website_security["issues"]:

            if issue["points"] > 0:
                reasons.append(issue["message"])

        # Keep score within 0-100
        score = min(score, 100)

        # STEP 6: Calculate final risk level
        if score >= 60:
            level = "HIGH"

        elif score >= 30:
            level = "MEDIUM"

        else:
            level = "LOW"

        # STEP 7: Final scan report
        return {

            "url": normalized_url,

            "risk_score": score,

            "risk_level": level,

            "phishing_detected": score >= 60,

            "ssl_valid": ssl_valid,

            "ssl_details": ssl_report,

            "website_security": website_security,

            "phishing_analysis": phishing_report,

            "security_status": (
                "Needs attention"
                if score >= 30
                else "No major URL indicators"
            ),

            "explanation": (
                "; ".join(reasons)
                if reasons
                else "No suspicious URL indicators were detected."
            )
        }

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception:

        # Avoid exposing internal server details
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred during website analysis."
        )
