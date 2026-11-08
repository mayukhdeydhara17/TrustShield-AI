from backend.security.phishing_engine import PhishingDetectionEngine

def run_tests():
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login/verify-account",
        "https://secure-login.update-banking.com@phish-example.com/auth?redirect=true",
        "https://github.com/mayukhdeydhara17/TrustShield-AI"
    ]

    print("--- TrustShield AI: Member 1 Detection Engine Test Report ---\n")
    for url in test_urls:
        engine = PhishingDetectionEngine(url)
        report = engine.generate_risk_assessment()
        print(f"URL: {report['url']}")
        print(f"Domain: {report['domain']}")
        print(f"Risk Probability: {report['risk_probability']}")
        print(f"Status: {report['status']}")
        print(f"Indicators: {report['indicators']}")
        print("-" * 60)

if __name__ == "__main__":
    run_tests()