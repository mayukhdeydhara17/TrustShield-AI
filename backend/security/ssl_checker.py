"""
ssl_checker.py - SSL & website security analysis module.

Checks:
  1. HTTPS availability
  2. SSL certificate validity
  3. Certificate expiry
  4. Returns a certificate status report (dict)
"""

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

EXPIRY_WARNING_DAYS = 30


def extract_hostname(url: str) -> str:
    """Turn 'https://example.com/path' or 'example.com' into 'example.com'."""
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    return urlparse(url).hostname or ""


def check_https_available(hostname: str, timeout: int = 5) -> bool:
    """Return True if the host accepts connections on port 443."""
    try:
        with socket.create_connection((hostname, 443), timeout=timeout):
            return True
    except OSError:
        return False


def _name_to_dict(name_tuple) -> dict:
    """Convert the certificate issuer/subject format into a simple dict."""
    return {key: value for rdn in name_tuple for key, value in rdn}


def check_ssl(url: str, timeout: int = 5) -> dict:
    """Analyze the SSL certificate of a website and return a status report."""
    hostname = extract_hostname(url)

    result = {
        "url": url,
        "hostname": hostname,
        "https_available": False,
        "ssl_valid": False,
        "issuer": None,
        "valid_from": None,
        "expires_on": None,
        "days_remaining": None,
        "status": "unknown",
        "message": "",
    }

    if not hostname:
        result["status"] = "error"
        result["message"] = "Invalid URL."
        return result

    # 1. HTTPS availability
    if not check_https_available(hostname, timeout):
        result["status"] = "no_https"
        result["message"] = "HTTPS is not available on this website."
        return result
    result["https_available"] = True

    # 2. Validate the certificate (default context verifies chain + hostname)
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        result["ssl_valid"] = True
    except ssl.SSLCertVerificationError as e:
        result["status"] = "invalid"
        result["message"] = f"Certificate is not valid: {e.verify_message}"
        return result
    except (ssl.SSLError, OSError) as e:
        result["status"] = "error"
        result["message"] = f"Could not complete SSL check: {e}"
        return result

    # 3. Check expiry
    issuer = _name_to_dict(cert.get("issuer", ()))
    result["issuer"] = issuer.get("organizationName") or issuer.get("commonName")

    not_before = datetime.fromtimestamp(
        ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc
    )
    not_after = datetime.fromtimestamp(
        ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc
    )
    days_left = (not_after - datetime.now(timezone.utc)).days

    result["valid_from"] = not_before.strftime("%Y-%m-%d")
    result["expires_on"] = not_after.strftime("%Y-%m-%d")
    result["days_remaining"] = days_left

    # 4. Final certificate status
    if days_left < 0:
        result["status"] = "expired"
        result["message"] = f"Certificate expired {abs(days_left)} days ago."
    elif days_left <= EXPIRY_WARNING_DAYS:
        result["status"] = "expiring_soon"
        result["message"] = f"Certificate expires in {days_left} days."
    else:
        result["status"] = "valid"
        result["message"] = f"Certificate is valid ({days_left} days remaining)."

    return result


if __name__ == "__main__":
    import json

    for site in ["google.com", "expired.badssl.com", "http.badssl.com"]:
        print(json.dumps(check_ssl(site), indent=2))