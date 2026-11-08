
from backend.security.url_analyzer import URLAnalyzer


class PhishingDetectionEngine:

    def __init__(self, url: str):
        self.analyzer = URLAnalyzer(url)

    def check_threat_intelligence(self) -> bool:
        """Check the demonstration-only malicious domain list."""

        return self.analyzer.is_known_malicious()

    def generate_risk_assessment(self) -> dict:

        domain = self.analyzer.extract_domain()

        is_ip = self.analyzer.detect_ip_based_url()
        is_long = self.analyzer.detect_long_url()

        keywords = self.analyzer.find_suspicious_keywords()

        subdomains = (
            self.analyzer.check_suspicious_subdomains()
        )

        misleading = (
            self.analyzer.identify_misleading_patterns()
        )

        is_known_malicious = (
            self.check_threat_intelligence()
        )

        is_trusted = self.analyzer.is_trusted_domain()

        # Unified 0-100 heuristic score

        risk_score = 0
        reasons = []

        # Known malicious demonstration domain

        if is_known_malicious:

            risk_score += 80

            reasons.append(
                "Domain matches the demonstration threat list."
            )

        # IP-based URL

        if is_ip:

            risk_score += 25

            reasons.append(
                "Website uses an IP address instead of a domain."
            )

        # Unusually long URL

        if is_long:

            risk_score += 5

            reasons.append(
                "URL is unusually long."
            )

        # Suspicious keywords

        if keywords:

            points = min(len(keywords) * 5, 15)

            risk_score += points

            reasons.append(
                "Suspicious URL keywords: "
                + ", ".join(keywords)
            )

        # Deep subdomain structure

        if subdomains:

            risk_score += 10

            reasons.append(
                "Unusually deep subdomain structure."
            )

        # Misleading URL patterns

        if misleading["has_at_symbol"]:

            risk_score += 20

            reasons.append(
                "URL contains an @ symbol."
            )

        if misleading["has_double_slash_redirect"]:

            risk_score += 10

            reasons.append(
                "URL path contains an unusual double slash."
            )

        if misleading["is_punycode"]:

            risk_score += 15

            reasons.append(
                "Domain contains punycode encoding."
            )

        # Keep score between 0 and 100

        risk_score = min(risk_score, 100)

        # Risk classification

        if risk_score >= 60:
            status = "HIGH"

        elif risk_score >= 30:
            status = "MEDIUM"

        else:
            status = "LOW"

        return {
            "url": self.analyzer.url,
            "domain": domain,

            "risk_score": risk_score,
            "risk_level": status,

            "is_known_malicious": is_known_malicious,
            "is_trusted_domain": is_trusted,

            "indicators": {
                "is_ip_based": is_ip,
                "is_long_url": is_long,
                "suspicious_keywords": keywords,
                "has_suspicious_subdomains": subdomains,
                "misleading_patterns": misleading
            },

            "reasons": reasons
        }
