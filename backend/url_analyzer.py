import re
from urllib.parse import urlparse

class URLAnalyzer:
    SUSPICIOUS_KEYWORDS = [
        'login', 'verify', 'update', 'secure', 'account', 'banking',
        'signin', 'confirm', 'password', 'credential', 'auth', 'ebayisapi'
    ]
    
    KNOWN_MALICIOUS_DOMAINS = {
        'phish-example.com', 'malicious-login-verify.net', 'secure-update-banking.org'
    }

    def __init__(self, url: str):
        self.url = url.strip()
        self.parsed = urlparse(self.url if '://' in self.url else 'http://' + self.url)

    def extract_domain(self) -> str:
        """Extracts the base domain from the URL."""
        return self.parsed.netloc.split(':')[0]

    def detect_long_url(self) -> bool:
        """Detects if the URL length exceeds standard safety thresholds (>75 chars)."""
        return len(self.url) > 75

    def find_suspicious_keywords(self) -> list:
        """Finds suspicious security/banking keywords in the URL path or domain."""
        found = []
        full_text = (self.parsed.netloc + self.parsed.path + self.parsed.query).lower()
        for kw in self.SUSPICIOUS_KEYWORDS:
            if kw in full_text:
                found.append(kw)
        return found

    def detect_ip_based_url(self) -> bool:
        """Detects if the URL uses an IP address instead of a domain name."""
        domain = self.extract_domain()
        ipv4_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        ipv6_pattern = r'^\[?[0-9a-fA-F:]+\]?$'
        return bool(re.match(ipv4_pattern, domain) or re.match(ipv6_pattern, domain))

    def check_suspicious_subdomains(self) -> bool:
        """Checks for excessive subdomains or hyphenation tricks."""
        domain = self.extract_domain()
        parts = domain.split('.')
        return len(parts) > 3 or '-' in domain

    def identify_misleading_patterns(self) -> dict:
        """Identifies deceptive patterns like '@' symbols, double slashes, or punycode."""
        return {
            'has_at_symbol': '@' in self.url,
            'has_double_slash_redirect': '//' in self.parsed.path,
            'is_punycode': self.extract_domain().startswith('xn--')
        }