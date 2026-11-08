
"""
ssl_checker.py - SSL certificate analysis.

Uses the shared safe_network module to connect only to
validated public IP addresses while preserving TLS verification.
"""

import socket
import ssl

from datetime import datetime, timezone
from urllib.parse import urlparse

from backend.security.safe_network import (
    open_safe_connection,
    SafeNetworkError,
)

EXPIRY_WARNING_DAYS = 30
HOSTNAME_MISMATCH_CODE = 62


def extract_hostname(url: str) -> str:
    """Extract hostname from a URL."""

    url = (url or "").strip()

    if "://" not in url:
        url = "https://" + url

    try:
        return urlparse(url).hostname or ""
    except ValueError:
        return ""


def check_https_available(hostname: str, timeout: int = 5) -> bool:
    """Check HTTPS port connectivity using a validated IP."""

    connection = None

    try:
        connection = open_safe_connection(
            hostname,
            443,
            timeout=timeout,
            use_tls=False
        )

        return True

    except (SafeNetworkError, OSError, ssl.SSLError):
        return False

    finally:
        if connection is not None:
            connection.close()


def _name_to_dict(name_tuple) -> dict:
    """Convert certificate names into a dictionary."""

    return {
        key: value
        for rdn in name_tuple
        for key, value in rdn
    }


def check_ssl(url: str, timeout: int = 5) -> dict:
    """Analyze a website's SSL certificate safely."""

    hostname = extract_hostname(url)

    result = {
        "url": url,
        "hostname": hostname,
        "https_available": False,
        "ssl_valid": False,
        "hostname_matches": None,
        "issuer": None,
        "subject": None,
        "san": [],
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

    connection = None

    try:
        # Connect directly to a validated public IP.
        # TLS still verifies the original hostname.
        connection = open_safe_connection(
            hostname,
            443,
            timeout=timeout,
            use_tls=True
        )

        result["https_available"] = True

        cert = connection.getpeercert()

        result["tls_version"] = connection.version()

        result["ssl_valid"] = True
        result["hostname_matches"] = True

    except ssl.SSLCertVerificationError as error:

        # A certificate verification failure means the TLS
        # connection reached the certificate verification stage.
        result["https_available"] = True
        result["status"] = "invalid"

        result["hostname_matches"] = (
            False
            if error.verify_code == HOSTNAME_MISMATCH_CODE
            else None
        )

        result["message"] = (
            f"Certificate is not valid: {error.verify_message}"
        )

        return result

    except SafeNetworkError as error:

        result["status"] = "error"
        result["message"] = str(error)
        return result

    except ssl.SSLError as error:

        result["status"] = "error"
        result["message"] = f"Could not complete SSL check: {error}"
        return result

    except OSError as error:

        result["status"] = "no_https"
        result["message"] = (
            f"HTTPS connection could not be established: {error}"
        )
        return result

    finally:
        if connection is not None:
            connection.close()

    # Read certificate details.
    try:
        issuer = _name_to_dict(cert.get("issuer", ()))
        subject = _name_to_dict(cert.get("subject", ()))

        result["issuer"] = (
            issuer.get("organizationName")
            or issuer.get("commonName")
        )

        result["subject"] = (
            subject.get("commonName")
            or subject.get("organizationName")
        )

        result["san"] = [
            value
            for kind, value in cert.get("subjectAltName", ())
            if kind == "DNS"
        ][:10]

        not_before = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notBefore"]),
            timezone.utc
        )

        not_after = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notAfter"]),
            timezone.utc
        )

        days_left = (
            not_after - datetime.now(timezone.utc)
        ).days

    except (KeyError, ValueError):

        result["status"] = "error"
        result["message"] = (
            "Certificate details could not be read."
        )

        return result

    result["valid_from"] = not_before.strftime("%Y-%m-%d")
    result["expires_on"] = not_after.strftime("%Y-%m-%d")
    result["days_remaining"] = days_left

    # Certificate status.
    if days_left < 0:

        result["status"] = "expired"
        result["message"] = (
            f"Certificate expired {abs(days_left)} days ago."
        )

    elif days_left <= EXPIRY_WARNING_DAYS:

        result["status"] = "expiring_soon"
        result["message"] = (
            f"Certificate expires in {days_left} days."
        )

    else:

        result["status"] = "valid"
        result["message"] = (
            f"Certificate is valid ({days_left} days remaining)."
        )

    return result


if __name__ == "__main__":

    import json

    test_sites = [
        "google.com",
        "expired.badssl.com",
        "wrong.host.badssl.com",
        "http.badssl.com",
    ]

    for site in test_sites:

        print(f"\nTesting: {site}")

        print(
            json.dumps(
                check_ssl(site),
                indent=2
            )
        )
