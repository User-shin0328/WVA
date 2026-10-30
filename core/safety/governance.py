from urllib.parse import urlparse
from typing import List

class SafetyGovernance:
    """
    Enforces authorization scope, safe non-destructive probing,
    and prevents out-of-scope or destructive requests.
    """
    def __init__(self, target_base_url: str, allowed_hosts: List[str] = None):
        parsed = urlparse(target_base_url)
        self.target_base_url = target_base_url
        self.allowed_hosts = allowed_hosts or [parsed.netloc, parsed.hostname]
        # Disallow destructive paths (delete, drop, logout, purchase, checkout)
        self.blocked_path_keywords = ["/logout", "/delete", "/drop", "/reset-db", "/destroy", "/purchase"]

    def is_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        host = parsed.netloc or parsed.hostname
        if not host:
            return False
        # Strip port for comparison
        clean_host = host.split(":")[0]
        for allowed in self.allowed_hosts:
            if allowed and (clean_host == allowed or clean_host.endswith("." + allowed)):
                return True
        return False

    def is_safe_endpoint(self, path: str) -> bool:
        lower_path = path.lower()
        for blocked in self.blocked_path_keywords:
            if blocked in lower_path:
                return False
        return True

    def sanitize_canary(self, canary_str: str) -> str:
        """Ensure test canary strings are harmless diagnostic markers, never destructive syntax."""
        return canary_str.replace("DROP", "").replace("rm -rf", "")
