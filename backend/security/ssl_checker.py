"""
ssl_checker.py - SSL & website security analysis module (Member 2).

Checks:
  1. HTTPS availability
  2. SSL certificate validity (chain + hostname)
  3. Certificate details: issuer, subject, alternative names, TLS version
  4. Certificate expiry and remaining days
  5. A clear status the rest of the backend can use

Standard library only. Never raises: every failure becomes a status.
"""

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

EXPIRY_WARNING_DAYS = 30
HOSTNAME_MISMATCH_CODE = 62  # OpenSSL: X509_V_ERR_HOSTNAME_MISMATCH


def extract_hostname(url: str) -> str:
    """Turn 'https://example.com/path' or 'example.com' into 'example.com'."""
    url = (url or "").strip()
    if "://" not in url:
        url = "https://" + url
    try:
        return urlparse(url).hostname or ""
    except ValueError:
        return ""


def check_https_available(hostname: str, timeout: int = 5) -> bool:
    """Return True if the host accepts connections on port 443."""
    try:
        with socket.create_connection((hostname, 443), timeout=timeout):
            return True
    except (OSError, UnicodeError):
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
        "hostname_matches": None,   # True / False / None (unknown)
        "issuer": None,
        "subject": None,
        "san": [],                  # alternative names on the certificate
        "tls_version": None,
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
                result["tls_version"] = ssock.version()
        result["ssl_valid"] = True
        result["hostname_matches"] = True
    except ssl.SSLCertVerificationError as error:
        result["status"] = "invalid"
        result["hostname_matches"] = False if error.verify_code == HOSTNAME_MISMATCH_CODE else None
        result["message"] = f"Certificate is not valid: {error.verify_message}"
        return result
    except (ssl.SSLError, OSError, UnicodeError) as error:
        result["status"] = "error"
        result["message"] = f"Could not complete SSL check: {error}"
        return result

    # 3. Certificate details
    try:
        issuer = _name_to_dict(cert.get("issuer", ()))
        subject = _name_to_dict(cert.get("subject", ()))
        result["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
        result["subject"] = subject.get("commonName") or subject.get("organizationName")
        result["san"] = [value for kind, value in cert.get("subjectAltName", ())
                         if kind == "DNS"][:10]

        # 4. Expiry
        not_before = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc)
        not_after = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
    except (KeyError, ValueError):
        result["status"] = "error"
        result["message"] = "Certificate details could not be read."
        return result

    result["valid_from"] = not_before.strftime("%Y-%m-%d")
    result["expires_on"] = not_after.strftime("%Y-%m-%d")
    result["days_remaining"] = days_left

    # 5. Final certificate status
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

    for site in ["google.com", "expired.badssl.com", "wrong.host.badssl.com", "http.badssl.com"]:
        print(json.dumps(check_ssl(site), indent=2))