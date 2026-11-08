"""
threat_intel.py - Phase 3: Threat Intelligence (Member 2).

Covers the Phase 3 checklist:
  1. Research security APIs   -> Google Safe Browsing + abuse.ch URLhaus
  2. Integrate reputation check -> check_reputation()
  3. Generate security assessment -> build_security_assessment()

Standard library only. API keys are read from environment variables or from
backend/.env (never hard-code keys, never commit them):
    SAFE_BROWSING_API_KEY=...
    URLHAUS_AUTH_KEY=...

Every provider is optional. With no keys the module still works and the
assessment says reputation was not checked (it never claims "clean" falsely).
Nothing here raises: every network failure is reported as a status.
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


# ---------------------------------------------------------------- settings
def _load_env_file() -> None:
    """Load KEY=VALUE lines from backend/.env into os.environ (if present)."""
    path = Path(__file__).resolve().parents[1] / ".env"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_env_file()

SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"

THREAT_NAMES = {
    "MALWARE": "malware",
    "SOCIAL_ENGINEERING": "phishing / social engineering",
    "UNWANTED_SOFTWARE": "unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "potentially harmful application",
}


def _provider_result(name: str) -> dict:
    return {
        "provider": name,
        "status": "not_configured",  # clean | flagged | not_configured | error
        "flagged": False,
        "threats": [],
        "message": "",
    }


# ------------------------------------------------- Provider 1: Safe Browsing
def check_safe_browsing(url: str, api_key: str = None, timeout: int = 5) -> dict:
    """Ask Google Safe Browsing whether the URL is on a known threat list."""
    result = _provider_result("Google Safe Browsing")
    api_key = api_key or os.environ.get("SAFE_BROWSING_API_KEY")
    if not api_key:
        result["message"] = "No API key set (SAFE_BROWSING_API_KEY)."
        return result

    body = json.dumps({
        "client": {"clientId": "trustshield-ai", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": list(THREAT_NAMES),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }).encode("utf-8")

    request = urllib.request.Request(
        SAFE_BROWSING_ENDPOINT + "?key=" + urllib.parse.quote(api_key),
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        result["status"] = "error"
        result["message"] = f"Safe Browsing returned HTTP {error.code} (check the API key)."
        return result
    except (urllib.error.URLError, OSError, ValueError):
        result["status"] = "error"
        result["message"] = "Could not reach Safe Browsing."
        return result

    matches = data.get("matches", [])
    if matches:
        kinds = sorted({THREAT_NAMES.get(m.get("threatType"), m.get("threatType", "unknown"))
                        for m in matches})
        result.update(status="flagged", flagged=True, threats=kinds,
                      message="Listed by Google Safe Browsing: " + ", ".join(kinds) + ".")
    else:
        result.update(status="clean", message="Not found on Google Safe Browsing lists.")
    return result


# ------------------------------------------------------ Provider 2: URLhaus
def check_urlhaus(host: str, auth_key: str = None, timeout: int = 5) -> dict:
    """Ask abuse.ch URLhaus whether the host has distributed malware."""
    result = _provider_result("abuse.ch URLhaus")
    auth_key = auth_key or os.environ.get("URLHAUS_AUTH_KEY")
    if not auth_key:
        result["message"] = "No Auth-Key set (URLHAUS_AUTH_KEY)."
        return result

    request = urllib.request.Request(
        URLHAUS_ENDPOINT,
        data=urllib.parse.urlencode({"host": host}).encode("utf-8"),
        headers={"Auth-Key": auth_key, "User-Agent": "TrustShield-AI/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        result["status"] = "error"
        result["message"] = f"URLhaus returned HTTP {error.code} (check the Auth-Key)."
        return result
    except (urllib.error.URLError, OSError, ValueError):
        result["status"] = "error"
        result["message"] = "Could not reach URLhaus."
        return result

    query_status = data.get("query_status")
    if query_status == "ok":
        try:
            online = int(data.get("urls_online") or 0)
            total = int(data.get("url_count") or 0)
        except (TypeError, ValueError):
            online, total = 0, 1
        result.update(
            status="flagged", flagged=True, threats=["malware distribution"],
            message=(f"URLhaus lists {total} malicious URL(s) on this host "
                     f"({online} currently online)."),
        )
        result["urls_online"] = online
    elif query_status == "no_results":
        result.update(status="clean", message="Host not found in URLhaus.")
    else:
        result["status"] = "error"
        result["message"] = f"URLhaus replied: {query_status}."
    return result


# ------------------------------------------------ Reputation (both at once)
def check_reputation(url: str, host: str, timeout: int = 5) -> dict:
    """Run every reputation provider in parallel and combine the results."""
    with ThreadPoolExecutor(max_workers=2) as pool:
        sb = pool.submit(check_safe_browsing, url, None, timeout)
        uh = pool.submit(check_urlhaus, host, None, timeout)
        providers = [sb.result(), uh.result()]

    answered = [p for p in providers if p["status"] in ("clean", "flagged")]
    return {
        "providers": providers,
        "sources_answered": len(answered),
        "flagged": any(p["flagged"] for p in providers),
        "threats": sorted({t for p in providers for t in p["threats"]}),
    }


# ------------------------------------------------------ Security assessment
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _finding(severity: str, source: str, message: str) -> dict:
    return {"severity": severity, "source": source, "message": message}


def build_security_assessment(url: str, ssl_report, website_security, reputation) -> dict:
    """
    Combine SSL (Phase 1), website security (Phase 2) and reputation (Phase 3)
    into one assessment: safety score, grade, verdict, findings, recommendations.
    """
    score = 100
    findings = []
    recommendations = []

    # --- Reputation (strongest signal)
    for provider in (reputation or {}).get("providers", []):
        if provider["flagged"]:
            urlhaus_online = provider.get("urls_online", 0)
            penalty = 60 if provider["provider"].startswith("Google") or urlhaus_online else 40
            score -= penalty
            findings.append(_finding("critical", provider["provider"], provider["message"]))
        elif provider["status"] == "error":
            findings.append(_finding("info", provider["provider"], provider["message"]))
        elif provider["status"] == "not_configured":
            findings.append(_finding("info", provider["provider"],
                                     "Not checked: " + provider["message"]))

    # --- SSL
    if ssl_report:
        status = ssl_report.get("status")
        ssl_penalty = {"no_https": 25, "invalid": 25, "expired": 25,
                       "expiring_soon": 5, "error": 10}.get(status, 0)
        if ssl_penalty:
            score -= ssl_penalty
            severity = "high" if ssl_penalty >= 25 else "low"
            findings.append(_finding(severity, "SSL", ssl_report.get("message", "")))
    elif url.lower().startswith("http://"):
        score -= 25
        findings.append(_finding("high", "SSL", "The site is loaded over plain HTTP (no encryption)."))

    # --- Website security (Phase 2)
    if website_security:
        score -= min(website_security.get("risk_points", 0), 40)
        for issue in website_security.get("issues", []):
            if issue["category"] != "ssl":  # SSL already covered above
                findings.append(_finding(issue["severity"], "Website security", issue["message"]))

    score = max(score, 0)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))

    # --- Verdict, grade, confidence
    flagged = bool((reputation or {}).get("flagged"))
    answered = (reputation or {}).get("sources_answered", 0)
    grade = ("A" if score >= 90 else "B" if score >= 75 else
             "C" if score >= 60 else "D" if score >= 40 else "F")
    confidence = "HIGH" if answered >= 2 else "MEDIUM" if answered == 1 else "LIMITED"
    verdict = "DANGEROUS" if flagged or score < 40 else "CAUTION" if score < 75 else "SAFE"
    if verdict == "SAFE" and answered == 0:
        verdict = "UNVERIFIED"  # never call a site SAFE without checking reputation

    # --- Recommendations
    if flagged:
        recommendations.append("Do not enter passwords or personal information on this site.")
        recommendations.append("Do not download files from this site.")
    if any(f["source"] == "SSL" and f["severity"] == "high" for f in findings):
        recommendations.append("Avoid submitting sensitive data: the connection is not secure.")
    if any(f["source"] == "Website security" for f in findings):
        recommendations.append("Verify the website's owner before trusting it (new domains are a common phishing sign).")
    if confidence == "LIMITED":
        recommendations.append("Reputation databases were not checked, so treat this result with care.")
    if not recommendations:
        recommendations.append("No action needed. Stay cautious and double-check the address before logging in.")

    summary = (f"Verdict {verdict} (safety score {score}/100, grade {grade}, "
               f"confidence {confidence}); {len(findings)} finding(s).")

    return {
        "verdict": verdict,
        "safety_score": score,
        "grade": grade,
        "confidence": confidence,
        "findings": findings,
        "recommendations": recommendations,
        "summary": summary,
    }


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    hostname = urllib.parse.urlparse(target).hostname or target
    print(json.dumps(check_reputation(target, hostname), indent=2))