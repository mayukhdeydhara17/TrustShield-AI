
import ipaddress
from urllib.parse import urlparse


class URLAnalyzer:

    SUSPICIOUS_KEYWORDS = [
        "login",
        "verify",
        "update",
        "secure",
        "account",
        "banking",
        "signin",
        "confirm",
        "password",
        "credential",
        "auth",
        "ebayisapi"
    ]

    # Demonstration-only entries, NOT a verified threat feed.
    KNOWN_MALICIOUS_DOMAINS = {
        "phish-example.com",
        "malicious-login-verify.net",
        "secure-update-banking.org"
    }

    # Demonstration allowlist.
    # Add only domains you have independently verified.
    TRUSTED_DOMAINS = {
    "google.com",
    "google.co.in",
    "microsoft.com",
    "github.com",
    "amazon.com",
    "wikipedia.org",
    "example.com"
}

    def __init__(self, url: str):

        self.url = url.strip()

        self.parsed = urlparse(
            self.url if "://" in self.url
            else "https://" + self.url
        )

    def extract_domain(self) -> str:
        """Return hostname without port."""

        return (self.parsed.hostname or "").lower().rstrip(".")

    def is_ip_address(self) -> bool:

        try:
            ipaddress.ip_address(self.extract_domain())
            return True
        except ValueError:
            return False

    def is_trusted_domain(self) -> bool:
        """Exact domain or genuine subdomain match."""

        domain = self.extract_domain()

        return any(
            domain == trusted
            or domain.endswith("." + trusted)
            for trusted in self.TRUSTED_DOMAINS
        )

    def is_known_malicious(self) -> bool:
        """Exact match against demonstration-only threat entries."""

        domain = self.extract_domain()

        return domain in self.KNOWN_MALICIOUS_DOMAINS

    def detect_long_url(self) -> bool:

        return len(self.url) > 75

    def find_suspicious_keywords(self) -> list:
        """Check URL path and query, not hostname."""

        if self.is_trusted_domain():
            return []

        searchable_text = (
            self.parsed.path + "?" + self.parsed.query
        ).lower()

        return [
            word
            for word in self.SUSPICIOUS_KEYWORDS
            if word in searchable_text
        ]

    def detect_ip_based_url(self) -> bool:

        return self.is_ip_address()

    def check_suspicious_subdomains(self) -> bool:
        """Flag unusually deep subdomain structures."""

        domain = self.extract_domain()

        if self.is_ip_address():
            return False

        if self.is_trusted_domain():
            return False

        parts = domain.split(".")

        return len(parts) > 4

    def identify_misleading_patterns(self) -> dict:

        domain = self.extract_domain()

        return {
            "has_at_symbol": "@" in self.url,

            "has_double_slash_redirect": (
                "//" in self.parsed.path
            ),

            "is_punycode": any(
                label.startswith("xn--")
                for label in domain.split(".")
            )
        }
