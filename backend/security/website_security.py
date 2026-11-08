
"""
website_security.py - Phase 2: Website Security Analysis (Member 2).

Checks:
1. DNS information
2. Domain details
3. Website security headers
4. HTTP to HTTPS redirect
5. SSL indicators
6. Domain age (WHOIS)

All checks are best-effort.
"""
import tldextract
import http.client
import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone

from backend.security.ssl_checker import check_ssl, extract_hostname


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
# Use the bundled public suffix list; don't download it at runtime.
DOMAIN_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=()
)


# ---------------------------------------------------------
# 1. DNS ANALYSIS
# ---------------------------------------------------------

def analyze_dns(hostname: str) -> dict:

    info = {
        "resolves": False,
        "ipv4": [],
        "ipv6": [],
        "reverse_dns": None,
        "all_public": None,
    }

    try:
        results = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, UnicodeError, OSError):
        return info

    ips = sorted({
        record[4][0].split("%")[0]
        for record in results
    })

    for ip in ips:
        addr = ipaddress.ip_address(ip)

        if addr.version == 4:
            info["ipv4"].append(ip)
        else:
            info["ipv6"].append(ip)

    info["resolves"] = bool(ips)

    info["all_public"] = all(
        ipaddress.ip_address(ip).is_global
        for ip in ips
    )

    try:
        if ips:
            info["reverse_dns"] = socket.gethostbyaddr(ips[0])[0]
    except (OSError, IndexError):
        pass

    return info


# ---------------------------------------------------------
# 2. DOMAIN DETAILS
# ---------------------------------------------------------

def analyze_domain(hostname: str) -> dict:

    host = hostname.lower().rstrip(".")
    labels = host.split(".")

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        registered = host
        subdomain_count = 0
        tld = None

    else:
        extracted = DOMAIN_EXTRACTOR(host)

        if extracted.domain and extracted.suffix:
            registered = (
                f"{extracted.domain}.{extracted.suffix}"
            )

            subdomain_count = (
                len(extracted.subdomain.split("."))
                if extracted.subdomain
                else 0
            )

            tld = extracted.suffix.split(".")[-1]

        else:
            registered = host
            subdomain_count = 0
            tld = labels[-1] if labels else None

    return {
        "hostname": host,
        "registered_domain": registered,
        "tld": tld,
        "subdomain_count": subdomain_count,
        "domain_length": len(registered),
        "hyphen_count": registered.count("-"),
        "digit_count": sum(
            c.isdigit() for c in registered
        ),
        "is_punycode": any(
            label.startswith("xn--")
            for label in labels
        ),
        "suspicious_tld": tld in SUSPICIOUS_TLDS
        if tld else False,
        "is_ip_address": is_ip,
    }

# ---------------------------------------------------------
# 3. WHOIS DOMAIN AGE
# ---------------------------------------------------------

def _whois_query(server: str, query: str, timeout: int) -> str:

    chunks = []
    total = 0

    with socket.create_connection(
        (server, 43),
        timeout=timeout
    ) as sock:

        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode())

        while total < 65536:

            data = sock.recv(4096)

            if not data:
                break

            chunks.append(data)
            total += len(data)

    return b"".join(chunks).decode(
        "utf-8",
        errors="ignore"
    )


def get_domain_age_days(
    registered_domain: str,
    timeout: int = 4
):

    try:

        tld = registered_domain.split(".")[-1]

        iana = _whois_query(
            "whois.iana.org",
            tld,
            timeout
        )

        server = None

        for line in iana.splitlines():

            key = line.split(":", 1)[0].strip().lower()

            if key in ("refer", "whois") and ":" in line:

                server = line.split(":", 1)[1].strip()
                break

        if not server:
            return None

        text = _whois_query(
            server,
            registered_domain,
            timeout
        )

        for line in text.splitlines():

            lowered = line.lower()

            if (
                "creation date" in lowered
                or lowered.strip().startswith("created")
            ):

                match = re.search(
                    r"(\d{4}-\d{2}-\d{2})",
                    line
                )

                if match:

                    created = datetime.strptime(
                        match.group(1),
                        "%Y-%m-%d"
                    )

                    created = created.replace(
                        tzinfo=timezone.utc
                    )

                    return (
                        datetime.now(timezone.utc) - created
                    ).days

    except (OSError, ValueError):
        pass

    return None


# ---------------------------------------------------------
# 4. WEBSITE SECURITY CHECKS
# ---------------------------------------------------------

def check_web_security(
    hostname: str,
    timeout: int = 4
) -> dict:

    result = {
        "headers_checked": False,
        "headers_present": [],
        "headers_missing": [],
        "http_check_completed": False,
        "http_redirects_to_https": None,
    }

    # Check HTTPS security headers

    conn = None

    try:

        conn = http.client.HTTPSConnection(
            hostname,
            443,
            timeout=timeout,
            context=ssl.create_default_context()
        )

        conn.request(
            "HEAD",
            "/",
            headers={
                "User-Agent": "TrustShield-AI/1.0"
            }
        )

        response = conn.getresponse()

        headers = {
            key.lower()
            for key, value in response.getheaders()
        }

        result["headers_checked"] = True

        for key, label in SECURITY_HEADERS.items():

            if key in headers:
                result["headers_present"].append(label)
            else:
                result["headers_missing"].append(label)

    except (
        OSError,
        ssl.SSLError,
        http.client.HTTPException
    ):
        pass

    finally:

        if conn:
            conn.close()

    # Check HTTP -> HTTPS redirect

    conn = None

    try:

        conn = http.client.HTTPConnection(
            hostname,
            80,
            timeout=timeout
        )

        conn.request(
            "HEAD",
            "/",
            headers={
                "User-Agent": "TrustShield-AI/1.0"
            }
        )

        response = conn.getresponse()

        result["http_check_completed"] = True

        location = response.getheader("Location") or ""

        result["http_redirects_to_https"] = (
            response.status in (301, 302, 307, 308)
            and location.lower().startswith("https://")
        )

    except (
        OSError,
        http.client.HTTPException
    ):
        pass

    finally:

        if conn:
            conn.close()

    return result


# ---------------------------------------------------------
# 5. ISSUE GENERATOR
# ---------------------------------------------------------

def _issue(
    message: str,
    severity: str,
    points: int,
    category: str
) -> dict:

    return {
        "message": message,
        "severity": severity,
        "points": points,
        "category": category,
    }


# ---------------------------------------------------------
# 6. MAIN WEBSITE SECURITY ANALYSIS
# ---------------------------------------------------------

def analyze_website_security(
    url: str,
    ssl_report: dict = None,
    timeout: int = 4
) -> dict:

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

    # 1. DNS ANALYSIS

    dns = analyze_dns(hostname)

    report["dns"] = dns

    if not dns["resolves"]:

        issues.append(
            _issue(
                "Domain does not resolve in DNS.",
                "high",
                30,
                "dns"
            )
        )

        return _finish(report)

    elif dns["all_public"] is False:

        issues.append(
            _issue(
                "Domain points to a private or reserved address.",
                "high",
                40,
                "dns"
            )
        )

        return _finish(report)

    # 2. DOMAIN ANALYSIS

    domain = analyze_domain(hostname)

    report["domain"] = domain

    if domain["suspicious_tld"]:

        issues.append(
            _issue(
                f"Uses a TLD often seen in abuse (.{domain['tld']}).",
                "medium",
                10,
                "domain"
            )
        )

    if domain["hyphen_count"] >= 3:

        issues.append(
            _issue(
                "Domain name contains many hyphens.",
                "low",
                5,
                "domain"
            )
        )

    # 3. DOMAIN AGE

    if not domain["is_ip_address"]:

        age = get_domain_age_days(
            domain["registered_domain"],
            timeout
        )

        report["domain_age_days"] = age

        if age is not None and age < 30:

            issues.append(
                _issue(
                    f"Domain is very new ({age} days old).",
                    "high",
                    25,
                    "domain"
                )
            )

        elif age is not None and age < 180:

            issues.append(
                _issue(
                    f"Domain is fairly new ({age} days old).",
                    "medium",
                    10,
                    "domain"
                )
            )

    # 4. SSL ANALYSIS
    # SSL risk points are scored by the /scan route.

    if ssl_report is None:
        ssl_report = check_ssl(url)

    if ssl_report.get("status") not in ("valid", None):

        issues.append(
            _issue(
                f"SSL: {ssl_report.get('message')}",
                "medium",
                0,
                "ssl"
            )
        )

    # 5. WEBSITE SECURITY HEADERS + HTTP REDIRECT

    web = check_web_security(
        hostname,
        timeout
    )

    report["web_security"] = web

    # Missing security headers

    missing = web["headers_missing"]

    if web["headers_checked"] and missing:

        points = min(
            len(missing) * 2,
            10
        )

        issues.append(
            _issue(
                "Missing security headers: "
                + ", ".join(missing),
                "low",
                points,
                "headers"
            )
        )

    # HTTP -> HTTPS redirect
    # Only report a problem if the HTTP check completed.

    if (
        web["http_check_completed"]
        and web["http_redirects_to_https"] is False
    ):

        issues.append(
            _issue(
                "HTTP does not redirect to HTTPS.",
                "low",
                5,
                "web"
            )
        )

    return _finish(report)


# ---------------------------------------------------------
# 7. FINAL REPORT
# ---------------------------------------------------------

def _finish(report: dict) -> dict:

    points = min(
        sum(issue["points"] for issue in report["issues"]),
        MAX_RISK_POINTS
    )

    report["risk_points"] = points

    if points >= 25:
        report["rating"] = "POOR"

    elif points >= 10:
        report["rating"] = "FAIR"

    else:
        report["rating"] = "GOOD"

    count = len(report["issues"])

    if count == 0:

        report["summary"] = (
            "No website security issues found."
        )

    else:

        report["summary"] = (
            f"{count} issue(s) found; "
            f"website security rating {report['rating']}."
        )

    return report


# ---------------------------------------------------------
# 8. DIRECT TEST
# ---------------------------------------------------------

if __name__ == "__main__":

    import json

    for site in [
        "google.com",
        "expired.badssl.com",
        "example.com"
    ]:

        print(f"\nTesting: {site}")

        print(
            json.dumps(
                analyze_website_security(site),
                indent=2
            )
        )
