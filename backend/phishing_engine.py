from url_analyzer import URLAnalyzer

class PhishingDetectionEngine:
    def __init__(self, url: str):
        self.analyzer = URLAnalyzer(url)

    def check_threat_intelligence(self) -> bool:
        """Checks against known malicious URL databases/sets."""
        domain = self.analyzer.extract_domain()
        return domain in self.analyzer.KNOWN_MALICIOUS_DOMAINS

    def generate_risk_assessment(self) -> dict:
        """Calculates risk probability score and aggregates detection metrics."""
        domain = self.analyzer.extract_domain()
        is_ip = self.analyzer.detect_ip_based_url()
        is_long = self.analyzer.detect_long_url()
        keywords = self.analyzer.find_suspicious_keywords()
        subdomains = self.analyzer.check_suspicious_subdomains()
        misleading = self.analyzer.identify_misleading_patterns()
        is_known_malicious = self.check_threat_intelligence()

        # Weighted risk scoring heuristic
        risk_score = 0.0
        if is_known_malicious:
            risk_score += 0.9
        if is_ip:
            risk_score += 0.4
        if is_long:
            risk_score += 0.2
        if keywords:
            risk_score += 0.15 * len(keywords)
        if subdomains:
            risk_score += 0.2
        if any(misleading.values()):
            risk_score += 0.3

        risk_probability = min(round(risk_score, 2), 1.0)
        status = "Phishing / High Risk" if risk_probability >= 0.5 else "Safe / Legitimate"

        return {
            "url": self.analyzer.url,
            "domain": domain,
            "risk_probability": risk_probability,
            "status": status,
            "indicators": {
                "is_known_malicious": is_known_malicious,
                "is_ip_based": is_ip,
                "is_long_url": is_long,
                "suspicious_keywords": keywords,
                "has_suspicious_subdomains": subdomains,
                "misleading_patterns": misleading
            }
        }