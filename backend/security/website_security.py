"""
website_security.py - Phase 2: Website Security analysis (Member 2).

Covers the Phase 2 checklist:
  1. Analyze DNS information
  2. Check domain details
  3. Identify security issues
  4. Gather security indicators

Uses only the Python standard library (no extra installs).
Never raises: every check is best-effort and fails safely.
"""

import http.client
import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone

try:  # works when run via uvicorn from the project root
    from backend.security.ssl_checker import check_ssl, extract_hostname
except ImportError:  # works when this file is run directly
    from ssl_checker import check_ssl, extract_hostname

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq",
    "click", "work", "support", "loan", "icu", "buzz", "country",
}

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}

MAX_RISK_POINTS = 40


# ---------------------------------------------------------------- 1. DNS
def analyze_dns(hostname: str) -> dict:
    """Resolve the hostname and collect DNS information."""
    info = {
        "resolves": False,
        "ipv4": [],
        "ipv6": [],
        "reverse_dns": None,
        "all_public": None,
    }
    try:
        results = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, UnicodeError):
        return info

    ips = sorted({r[4][0].split("%")[0] for r in results})
    for ip in ips:
        addr = ipaddress.ip_address(ip)
        (info["ipv4"] if addr.version == 4 else info["ipv6"]).append(ip)

    info["resolves"] = bool(ips)
    info["all_public"] = all(ipaddress.ip_address(ip).is_global for ip in ips)

    try:
        info["reverse_dns"] = socket.gethostbyaddr(ips[0])[0]
    except (OSError, IndexError):
        pass
    return info


# ------------------------------------------------------ 2. Domain details
def analyze_domain(hostname: str) -> dict:
    """Structure-based details about the domain name."""
    host = hostname.lower().rstrip(".")
    labels = host.split(".")
    registered = ".".join(labels[-2:]) if len(labels) >= 2 else host

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    return {
        "hostname": host,
        "registered_domain": registered,  # simple guess (co.uk style not handled)
        "tld": labels[-1],
        "subdomain_count": max(len(labels) - 2, 0),
        "domain_length": len(registered),
        "hyphen_count": registered.count("-"),
        "digit_count": sum(c.isdigit() for c in registered),
        "is_punycode": any(label.startswith("xn--") for label in labels),
        "suspicious_tld": labels[-1] in SUSPICIOUS_TLDS,
        "is_ip_address": is_ip,
    }


def _whois_query(server: str, query: str, timeout: int) -> str:
    chunks, total = [], 0
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode())
        while total < 65536:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            total += len(data)
    return b"".join(chunks).decode("utf-8", errors="ignore")


def get_domain_age_days(registered_domain: str, timeout: int = 4):
    """Best-effort domain age in days using WHOIS. Returns None if unknown."""
    try:
        tld = registered_domain.split(".")[-1]
        iana = _whois_query("whois.iana.org", tld, timeout)
        server = None
        for line in iana.splitlines():
            key = line.split(":", 1)[0].strip().lower()
            if key in ("refer", "whois") and ":" in line:
                server = line.split(":", 1)[1].strip()
                break
        if not server:
            return None

        text = _whois_query(server, registered_domain, timeout)
        for line in text.splitlines():
            lowered = line.lower()
            if "creation date" in lowered or lowered.strip().startswith("created"):
                match = re.search(r"(\d{4}-\d{2}-\d{2})", line)
                if match:
                    created = datetime.strptime(match.group(1), "%Y-%m-%d")
                    created = created.replace(tzinfo=timezone.utc)
                    return (datetime.now(timezone.utc) - created).days
    except (OSError, ValueError):
        pass
    return None


# ------------------------------------------------ 3. Security headers etc.
def check_web_security(hostname: str, timeout: int = 4) -> dict:
    """Check security headers and HTTP -> HTTPS redirect (no redirects followed)."""
    result = {
        "headers_checked": False,
        "headers_present": [],
        "headers_missing": [],
        "http_redirects_to_https": None,
    }

    try:
        conn = http.client.HTTPSConnection(
            hostname, 443, timeout=timeout, context=ssl.create_default_context()
        )
        conn.request("HEAD", "/", headers={"User-Agent": "TrustShield-AI/1.0"})
        headers = {k.lower() for k, _ in conn.getresponse().getheaders()}
        conn.close()
        result["headers_checked"] = True
        for key, label in SECURITY_HEADERS.items():
            (result["headers_present"] if key in headers
             else result["headers_missing"]).append(label)
    except (OSError, ssl.SSLError, http.client.HTTPException):
        pass

    try:
        conn = http.client.HTTPConnection(hostname, 80, timeout=timeout)
        conn.request("HEAD", "/", headers={"User-Agent": "TrustShield-AI/1.0"})
        resp = conn.getresponse()
        location = resp.getheader("Location") or ""
        conn.close()
        result["http_redirects_to_https"] = (
            resp.status in (301, 302, 307, 308)
            and location.lower().startswith("https://")
        )
    except (OSError, http.client.HTTPException):
        pass

    return result


def _issue(message: str, severity: str, points: int, category: str) -> dict:
    return {
        "message": message,
        "severity": severity,
        "points": points,
        "category": category,
    }


# ------------------------------------------------------------- Main entry
def analyze_website_security(url: str, ssl_report: dict = None, timeout: int = 4) -> dict:
    """
    Run all Phase 2 checks and return one report.

    ssl_report: optional result of check_ssl(); pass it in to avoid a second
    SSL connection. SSL problems are listed but score 0 points here, because
    the /scan route already scores them.
    """
    hostname = extract_hostname(url)
    report = {
        "hostname": hostname,
        "dns": None,
        "domain": None,
        "domain_age_days": None,
        "web_security": None,
        "issues": [],
        "risk_points": 0,
        "rating": "UNKNOWN",
        "summary": "",
    }
    issues = report["issues"]

    if not hostname:
        report["summary"] = "Invalid URL."
        return report

    # 1. DNS
    dns = analyze_dns(hostname)
    report["dns"] = dns
    if not dns["resolves"]:
        issues.append(_issue("Domain does not resolve in DNS.", "high", 30, "dns"))
    elif dns["all_public"] is False:
        issues.append(_issue("Domain points to a private or reserved address.",
                             "high", 40, "dns"))
        # Safety: do not make any further requests to a non-public address.
        return _finish(report)

    # 2. Domain details
    domain = analyze_domain(hostname)
    report["domain"] = domain

    if domain["suspicious_tld"]:
        issues.append(_issue(f"Uses a TLD often seen in abuse (.{domain['tld']}).",
                             "medium", 10, "domain"))
    if domain["hyphen_count"] >= 3:
        issues.append(_issue("Domain name contains many hyphens.", "low", 5, "domain"))

    if dns["resolves"] and not domain["is_ip_address"]:
        age = get_domain_age_days(domain["registered_domain"], timeout)
        report["domain_age_days"] = age
        if age is not None and age < 30:
            issues.append(_issue(f"Domain is very new ({age} days old).",
                                 "high", 25, "domain"))
        elif age is not None and age < 180:
            issues.append(_issue(f"Domain is fairly new ({age} days old).",
                                 "medium", 10, "domain"))

    # 3. SSL (listed only; scored by /scan) and web security checks
    if ssl_report is None:
        ssl_report = check_ssl(hostname)
    if ssl_report.get("status") not in ("valid", None):
        issues.append(_issue(f"SSL: {ssl_report.get('message')}", "medium", 0, "ssl"))

    if dns["resolves"]:
        web = check_web_security(hostname, timeout)
        report["web_security"] = web

        missing = web["headers_missing"]
        if web["headers_checked"] and missing:
            points = min(len(missing) * 2, 10)
            issues.append(_issue(
                "Missing security headers: " + ", ".join(missing),
                "low", points, "headers"))
        if web["http_redirects_to_https"] is False:
            issues.append(_issue("HTTP does not redirect to HTTPS.", "low", 5, "web"))

    return _finish(report)


def _finish(report: dict) -> dict:
    """Total the points, set the rating and write a summary."""
    points = min(sum(i["points"] for i in report["issues"]), MAX_RISK_POINTS)
    report["risk_points"] = points
    report["rating"] = "POOR" if points >= 25 else "FAIR" if points >= 10 else "GOOD"
    count = len(report["issues"])
    report["summary"] = (
        "No website security issues found." if count == 0
        else f"{count} issue(s) found; website security rating {report['rating']}."
    )
    return report


if __name__ == "__main__":
    import json

    for site in ["google.com", "expired.badssl.com", "example.com"]:
        print(json.dumps(analyze_website_security(site), indent=2))