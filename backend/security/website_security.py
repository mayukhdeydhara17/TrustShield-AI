"""
website_security.py - Website Security analysis (Member 2).

Covers:
  * Domain analysis : registered domain + TLD (handles co.in / co.uk style
                      suffixes), subdomain count, suspicious traits,
                      IP-address hostnames, domain age via RDAP (WHOIS fallback)
  * DNS analysis    : resolution, A/AAAA, reverse DNS, NS / MX / TXT / CNAME,
                      SPF and DMARC (via DNS-over-HTTPS, no extra packages)
  * Web security    : HTTP -> HTTPS redirect, security headers, missing headers
  * Issues          : every issue has a message, severity, points and a
                      "why it matters" explanation

Standard library only. analyze_website_security() NEVER raises: every stage is
isolated, failures are listed under report["errors"], and slow stages cannot
block the scan for long.
"""

import http.client
import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

try:  # works when run via uvicorn from the project root
    from backend.security.ssl_checker import check_ssl, extract_hostname
except ImportError:  # works when this file is run directly
    from ssl_checker import check_ssl, extract_hostname

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq",
    "click", "work", "support", "loan", "icu", "buzz", "country",
}

# Common two-part suffixes. (For complete coverage you would use the public
# suffix list; this list covers the most common cases, including India.)
TWO_PART_SUFFIXES = {
    "co.in", "ac.in", "gov.in", "nic.in", "org.in", "net.in", "edu.in",
    "res.in", "firm.in", "gen.in", "ind.in", "mil.in",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "ac.jp",
    "com.br", "com.cn", "com.sg", "com.hk", "com.my", "com.ph", "com.pk",
    "com.bd", "com.np", "com.lk", "com.tr", "com.mx", "com.ar", "com.sa",
    "com.eg", "com.ng", "co.za", "co.ke", "co.id", "co.kr", "co.th",
}

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}

DOH_ENDPOINTS = [
    ("https://dns.google/resolve", {}),
    ("https://cloudflare-dns.com/dns-query", {"Accept": "application/dns-json"}),
]
DNS_TYPE_NUMBERS = {"NS": 2, "CNAME": 5, "MX": 15, "TXT": 16}

MAX_RISK_POINTS = 40
STAGE_TIMEOUT = 15  # seconds to wait for any single stage

_RDAP_BOOTSTRAP = {}  # cache of IANA's TLD -> RDAP server list


def _http_get_json(url: str, timeout: int = 4, headers: dict = None):
    """GET a JSON document over HTTPS (small, bounded read)."""
    request_headers = {"User-Agent": "TrustShield-AI/1.0", "Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, headers=request_headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read(2_000_000).decode("utf-8"))


# ------------------------------------------------------------ DNS analysis
def analyze_dns(hostname: str) -> dict:
    """Resolve the hostname and collect basic DNS information."""
    info = {
        "resolves": False,
        "ipv4": [],
        "ipv6": [],
        "reverse_dns": None,
        "all_public": None,
        "records": None,
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


def query_dns(name: str, record_type: str, timeout: int = 4):
    """
    Look up one DNS record type using DNS-over-HTTPS.
    Returns a list of values (empty list = no such record) or None if the
    lookup itself failed.
    """
    wanted = DNS_TYPE_NUMBERS[record_type]
    for endpoint, headers in DOH_ENDPOINTS:
        try:
            query = urllib.parse.urlencode({"name": name, "type": record_type})
            data = _http_get_json(endpoint + "?" + query, timeout, headers)
        except (OSError, ValueError, http.client.HTTPException):
            continue
        return [
            str(answer.get("data", "")).strip().rstrip(".").strip('"')
            for answer in data.get("Answer", [])
            if answer.get("type") == wanted
        ]
    return None


def get_dns_records(hostname: str, registered_domain: str, timeout: int = 4) -> dict:
    """Collect NS, MX, TXT, CNAME records plus SPF / DMARC presence."""
    jobs = {
        "ns": (registered_domain, "NS"),
        "mx": (registered_domain, "MX"),
        "txt": (registered_domain, "TXT"),
        "cname": (hostname, "CNAME"),
        "dmarc": ("_dmarc." + registered_domain, "TXT"),
    }
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {key: pool.submit(query_dns, name, rtype, timeout)
                   for key, (name, rtype) in jobs.items()}
        found = {key: future.result() for key, future in futures.items()}

    lookup_ok = any(value is not None for value in found.values())
    txt = found["txt"] or []
    dmarc = found["dmarc"] or []
    return {
        "lookup_ok": lookup_ok,
        "ns": found["ns"] or [],
        "mx": found["mx"] or [],
        "cname": found["cname"] or [],
        "txt_count": len(txt),
        "has_spf": any(t.lower().startswith("v=spf1") for t in txt) if found["txt"] is not None else None,
        "has_dmarc": any(t.lower().startswith("v=dmarc1") for t in dmarc) if found["dmarc"] is not None else None,
    }


# ---------------------------------------------------------- Domain analysis
def split_domain(hostname: str) -> dict:
    """Split a hostname into subdomains, registered domain and suffix."""
    host = (hostname or "").lower().strip().rstrip(".")
    labels = [label for label in host.split(".") if label]
    if not labels:
        return {"registered_domain": host, "suffix": "", "tld": "", "subdomains": []}

    two_part = len(labels) >= 2 and ".".join(labels[-2:]) in TWO_PART_SUFFIXES
    suffix_len = 2 if two_part else 1

    if len(labels) <= suffix_len:
        registered, subdomains = host, []
    else:
        registered = ".".join(labels[-(suffix_len + 1):])
        subdomains = labels[:-(suffix_len + 1)]

    return {
        "registered_domain": registered,
        "suffix": ".".join(labels[-suffix_len:]),
        "tld": labels[-1],
        "subdomains": subdomains,
    }


def analyze_domain(hostname: str) -> dict:
    """Structure-based details about the domain name."""
    host = (hostname or "").lower().strip().rstrip(".")

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        return {
            "hostname": host, "registered_domain": host, "suffix": "", "tld": "",
            "subdomains": [], "subdomain_count": 0, "domain_length": len(host),
            "hyphen_count": 0, "digit_count": 0, "is_punycode": False,
            "suspicious_tld": False, "is_ip_address": True, "suspicious_traits": [],
        }

    parts = split_domain(host)
    name_label = parts["registered_domain"].split(".")[0]
    is_punycode = any(label.startswith("xn--") for label in host.split("."))
    suspicious_tld = parts["tld"] in SUSPICIOUS_TLDS

    domain = {
        "hostname": host,
        "registered_domain": parts["registered_domain"],
        "suffix": parts["suffix"],
        "tld": parts["tld"],
        "subdomains": parts["subdomains"],
        "subdomain_count": len(parts["subdomains"]),
        "domain_length": len(parts["registered_domain"]),
        "hyphen_count": name_label.count("-"),
        "digit_count": sum(c.isdigit() for c in name_label),
        "is_punycode": is_punycode,
        "suspicious_tld": suspicious_tld,
        "is_ip_address": False,
    }

    traits = []
    if suspicious_tld:
        traits.append(f"TLD .{parts['tld']} is often abused")
    if domain["hyphen_count"] >= 3:
        traits.append("many hyphens in the name")
    if domain["domain_length"] >= 30:
        traits.append("unusually long domain name")
    if domain["digit_count"] >= 4:
        traits.append("many digits in the name")
    if is_punycode:
        traits.append("internationalized (xn--) name")
    if domain["subdomain_count"] >= 3:
        traits.append("many subdomains")
    domain["suspicious_traits"] = traits
    return domain


# --------------------------------------------------------------- Domain age
def _days_since(date_text: str):
    match = re.match(r"(\d{4}-\d{2}-\d{2})", date_text or "")
    if not match:
        return None
    created = datetime.strptime(match.group(1), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    days = (datetime.now(timezone.utc) - created).days
    return days if days >= 0 else None


def _age_from_rdap_data(data: dict):
    for event in data.get("events", []):
        if event.get("eventAction") in ("registration", "reregistration"):
            return _days_since(event.get("eventDate"))
    return None


def _rdap_server(tld: str, timeout: int):
    if "data" not in _RDAP_BOOTSTRAP:
        _RDAP_BOOTSTRAP["data"] = _http_get_json("https://data.iana.org/rdap/dns.json", timeout)
    for tlds, urls in _RDAP_BOOTSTRAP["data"].get("services", []):
        if tld in tlds:
            secure = [u for u in urls if u.startswith("https://")]
            return secure[0] if secure else None
    return None


def _age_from_rdap_bootstrap(tld: str, quoted_domain: str, timeout: int):
    server = _rdap_server(tld, timeout)
    if not server:
        return None
    return _age_from_rdap_data(
        _http_get_json(server.rstrip("/") + "/domain/" + quoted_domain, timeout))


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


def _age_from_whois(registered_domain: str, timeout: int):
    tld = registered_domain.rsplit(".", 1)[-1]
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
            days = _days_since(line.split(":", 1)[-1].strip())
            if days is not None:
                return days
    return None


def get_domain_age(registered_domain: str, timeout: int = 4):
    """
    Domain age in days using registration data.
    Order: RDAP (IANA bootstrap) -> RDAP (rdap.org) -> WHOIS.
    Returns (days, source) or (None, None) when no source answers.
    """
    tld = registered_domain.rsplit(".", 1)[-1]
    quoted = urllib.parse.quote(registered_domain, safe=".-")
    attempts = (
        ("RDAP", lambda: _age_from_rdap_bootstrap(tld, quoted, timeout)),
        ("RDAP (rdap.org)", lambda: _age_from_rdap_data(
            _http_get_json("https://rdap.org/domain/" + quoted, timeout))),
        ("WHOIS", lambda: _age_from_whois(registered_domain, timeout)),
    )
    for source, attempt in attempts:
        try:
            age = attempt()
        except (OSError, ValueError, KeyError, IndexError, TypeError, http.client.HTTPException):
            age = None
        if age is not None:
            return age, source
    return None, None


# ------------------------------------------------------------- Web security
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
            hostname, 443, timeout=timeout, context=ssl.create_default_context())
        conn.request("HEAD", "/", headers={"User-Agent": "TrustShield-AI/1.0"})
        headers = {k.lower() for k, _ in conn.getresponse().getheaders()}
        conn.close()
        result["headers_checked"] = True
        for key, label in SECURITY_HEADERS.items():
            (result["headers_present"] if key in headers
             else result["headers_missing"]).append(label)
    except (OSError, ssl.SSLError, http.client.HTTPException, UnicodeError):
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
    except (OSError, http.client.HTTPException, UnicodeError):
        pass

    return result


# ------------------------------------------------------------------- Issues
def _issue(message: str, severity: str, points: int, category: str, why: str = "") -> dict:
    return {
        "message": message,
        "severity": severity,
        "points": points,
        "category": category,
        "why": why,
    }


def _collect(future, report: dict, name: str):
    """Get a stage result without ever raising."""
    try:
        return future.result(timeout=STAGE_TIMEOUT)
    except Exception:
        report["errors"].append(f"{name} check could not be completed.")
        return None


def analyze_website_security(url: str, ssl_report: dict = None, timeout: int = 4) -> dict:
    """
    Run all website-security checks and return one report. Never raises.

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
        "domain_age_source": None,
        "web_security": None,
        "issues": [],
        "errors": [],
        "risk_points": 0,
        "rating": "UNKNOWN",
        "summary": "",
    }

    if not hostname:
        report["summary"] = "Invalid URL."
        return report

    try:
        _run_checks(report, hostname, ssl_report, timeout)
    except Exception as error:  # last-resort safety net
        report["errors"].append(f"Unexpected error: {type(error).__name__}")
    return _finish(report)


def _run_checks(report: dict, hostname: str, ssl_report, timeout: int) -> None:
    issues = report["issues"]

    # --- DNS resolution
    dns = analyze_dns(hostname)
    report["dns"] = dns
    if not dns["resolves"]:
        issues.append(_issue(
            "Domain does not resolve in DNS.", "high", 30, "dns",
            "A website that cannot be found in DNS is either offline or fake."))
        return
    if dns["all_public"] is False:
        issues.append(_issue(
            "Domain points to a private or reserved address.", "high", 40, "dns",
            "Public websites should not point to internal addresses; this can be used to attack internal networks."))
        return  # Safety: make no further requests to a non-public address.

    # --- Domain analysis
    try:
        domain = analyze_domain(hostname)
    except Exception:
        report["errors"].append("Domain analysis could not be completed.")
        domain = None
    report["domain"] = domain

    if domain:
        if domain["is_ip_address"]:
            issues.append(_issue(
                "The website is addressed by an IP address, not a domain name.", "medium", 0, "domain",
                "Legitimate services almost always use a domain name. (Scored by the URL analysis.)"))
        if domain["suspicious_tld"]:
            issues.append(_issue(
                f"Uses a TLD often seen in abuse (.{domain['tld']}).", "medium", 10, "domain",
                "Some cheap TLDs are heavily used for phishing and spam."))
        if domain["hyphen_count"] >= 3:
            issues.append(_issue(
                "Domain name contains many hyphens.", "low", 5, "domain",
                "Phishing domains often chain words with hyphens, like login-secure-bank-verify."))
        if domain["domain_length"] >= 30:
            issues.append(_issue(
                "Domain name is unusually long.", "low", 3, "domain",
                "Long names are used to hide the real brand or imitate others."))

    # --- Slow lookups run in parallel
    pool = ThreadPoolExecutor(max_workers=3)
    futures = {"web security": pool.submit(check_web_security, hostname, timeout)}
    if domain and not domain["is_ip_address"]:
        futures["domain age"] = pool.submit(get_domain_age, domain["registered_domain"], timeout)
        futures["DNS records"] = pool.submit(
            get_dns_records, hostname, domain["registered_domain"], timeout)
    results = {name: _collect(future, report, name) for name, future in futures.items()}
    pool.shutdown(wait=False, cancel_futures=True)

    # --- Domain age
    age_result = results.get("domain age")
    if age_result:
        age, source = age_result
        report["domain_age_days"] = age
        report["domain_age_source"] = source
        if age is not None and age < 30:
            issues.append(_issue(
                f"Domain is very new ({age} days old).", "high", 25, "domain",
                "Phishing sites are often registered only days before they are used."))
        elif age is not None and age < 180:
            issues.append(_issue(
                f"Domain is fairly new ({age} days old).", "medium", 10, "domain",
                "Young domains have little history, so they deserve extra caution."))

    # --- DNS records
    records = results.get("DNS records")
    if records:
        dns["records"] = records
        if records["lookup_ok"] and not records["mx"] and records["has_spf"] is False:
            issues.append(_issue(
                "No email (MX/SPF) records found for the domain.", "info", 0, "dns",
                "Real organisations normally publish email records. This is only a weak signal."))

    # --- SSL (listed only; scored by /scan)
    if ssl_report is None:
        try:
            ssl_report = check_ssl(hostname)
        except Exception:
            report["errors"].append("SSL check could not be completed.")
    if ssl_report and ssl_report.get("status") not in ("valid", None):
        issues.append(_issue(
            f"SSL: {ssl_report.get('message')}", "medium", 0, "ssl",
            "An invalid or missing certificate means the connection cannot be trusted."))

    # --- Headers and redirect
    web = results.get("web security")
    if web:
        report["web_security"] = web
        missing = web["headers_missing"]
        if web["headers_checked"] and missing:
            issues.append(_issue(
                "Missing security headers: " + ", ".join(missing), "low",
                min(len(missing) * 2, 10), "headers",
                "Security headers help browsers block clickjacking, content sniffing and script injection."))
        if web["http_redirects_to_https"] is False:
            issues.append(_issue(
                "HTTP does not redirect to HTTPS.", "low", 5, "web",
                "Without a redirect, visitors can stay on an unencrypted page where data can be intercepted."))


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
    for site in ["google.com", "expired.badssl.com", "example.com"]:
        print(json.dumps(analyze_website_security(site), indent=2))