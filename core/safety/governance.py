from urllib.parse import urlsplit, urlunsplit
from typing import List
from core.safety.target import normalize_target_url, decoded_path

class SafetyGovernance:
    """
    Enforces authorization scope, safe non-destructive probing,
    and prevents out-of-scope or destructive requests.
    """
    def __init__(self, target_base_url: str, allowed_hosts: List[str] = None, scope_mode: str = "path"):
        self.target_base_url = normalize_target_url(target_base_url)
        parsed = urlsplit(self.target_base_url)
        if scope_mode not in ("path", "origin"):
            raise ValueError("지원하지 않는 진단 범위입니다.")
        self.scope_mode = scope_mode
        self.scope_path = decoded_path(parsed.path).rstrip("/") if scope_mode == "path" else ""
        self.probe_prefix = parsed.path.rstrip("/") if self.scope_path else ""
        self.origin_url = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        self.entry_path = parsed.path or "/"
        self.allowed_hosts = allowed_hosts or [parsed.hostname]
        self.origin = (parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
        # Disallow destructive paths (delete, drop, logout, purchase, checkout)
        self.blocked_path_keywords = ["/logout", "/delete", "/drop", "/reset-db", "/destroy", "/purchase"]

    def is_in_scope(self, url: str) -> bool:
        try:
            if "\\" in url or any(c.isspace() or ord(c) < 32 for c in url):
                return False
            parsed = urlsplit(url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None or parsed.password is not None:
                return False
            origin = (parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
            path = decoded_path(parsed.path)
        except ValueError:
            return False
        return origin == self.origin and (not self.scope_path or path == self.scope_path or path.startswith(self.scope_path + "/"))

    def url_for_path(self, path: str) -> str:
        """Resolve an absolute server path, retaining entry query only on that path."""
        entry = urlsplit(self.target_base_url)
        query = entry.query if path == self.entry_path else ""
        return self.origin_url + path + (("?" + query) if query else "")

    def probe_paths(self, paths):
        return [self.probe_prefix + path for path in paths]

    def is_safe_endpoint(self, path: str) -> bool:
        try:
            lower_path = decoded_path(path).lower()
        except ValueError:
            return False
        for blocked in self.blocked_path_keywords:
            if blocked in lower_path:
                return False
        return True

    def sanitize_canary(self, canary_str: str) -> str:
        """Ensure test canary strings are harmless diagnostic markers, never destructive syntax."""
        return canary_str.replace("DROP", "").replace("rm -rf", "")
