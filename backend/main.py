from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
import socket
import ssl
import ipaddress

app = FastAPI(title="TrustShield AI API")

# Allow React frontend to communicate with backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str


def validate_url(url):
    parsed = urlparse(url)

    if parsed.scheme not in ["http", "https"]:
        raise ValueError("Only HTTP and HTTPS URLs are allowed.")

    if not parsed.hostname:
        raise ValueError("Invalid website URL.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed.")

    host = parsed.hostname

    if host.lower() == "localhost":
        raise ValueError("Local addresses cannot be scanned.")

    try:
        addresses = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ValueError("Website domain could not be resolved.")

    # Block private, loopback and reserved IP addresses
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])

        if not ip.is_global:
            raise ValueError("Private or restricted addresses are blocked.")

    return host


def check_ssl(host):
    try:
        addresses = socket.getaddrinfo(
            host, 443, type=socket.SOCK_STREAM
        )

        context = ssl.create_default_context()

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            if not ip.is_global:
                continue

            connection = socket.socket(
                address[0], address[1], address[2]
            )
            connection.settimeout(4)

            try:
                connection.connect((address[4][0], 443))

                with context.wrap_socket(
                    connection, server_hostname=host
                ):
                    return True

            except (OSError, ssl.SSLError):
                connection.close()

        return False

    except Exception:
        return False


def analyze_url(url, host):
    score = 0
    reasons = []

    suspicious_words = [
        "login", "verify", "account", "password",
        "secure", "banking", "update", "confirm"
    ]

    lowered = url.lower()

    for word in suspicious_words:
        if word in lowered:
            score += 10
            reasons.append(f"Contains suspicious keyword: {word}")

    if "@" in url:
        score += 25
        reasons.append("Contains an unusual @ symbol.")

    if len(url) > 100:
        score += 10
        reasons.append("Unusually long URL.")

    if host.count(".") > 3:
        score += 15
        reasons.append("Contains multiple subdomains.")

    try:
        ipaddress.ip_address(host)
        score += 30
        reasons.append("Uses an IP address instead of a domain.")
    except ValueError:
        pass

    if host.startswith("xn--"):
        score += 20
        reasons.append("Uses an internationalized domain encoding.")

    return min(score, 100), reasons


@app.get("/")
def home():
    return {"message": "TrustShield AI backend is working!"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/scan")
def scan_website(request: ScanRequest):

    try:
        host = validate_url(request.url)
        score, reasons = analyze_url(request.url, host)

        ssl_valid = None

        if urlparse(request.url).scheme == "https":
            ssl_valid = check_ssl(host)

            if ssl_valid is False:
                score = min(score + 25, 100)
                reasons.append("SSL certificate validation failed.")

        if score >= 60:
            level = "HIGH"
        elif score >= 30:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "risk_score": score,
            "risk_level": level,
            "phishing_detected": score >= 60,
            "ssl_valid": ssl_valid,
            "security_status": (
                "Needs attention" if score >= 30 else "No major URL indicators"
            ),
            "explanation": (
                "; ".join(reasons)
                if reasons
                else "No suspicious URL indicators were detected."
            )
        }

    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
