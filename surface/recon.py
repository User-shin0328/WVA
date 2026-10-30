import httpx
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

from core.models.asset import HttpEndpoint
from core.graph.blackboard import SecurityBlackboard
from core.safety.governance import SafetyGovernance

class SurfaceReconEngine:
    """
    Active & passive attack surface discovery engine.
    Probes common API endpoints, parses links/forms, detects tech stack,
    and inspects HTTP responses without destructive actions.
    """
    def __init__(self, blackboard: SecurityBlackboard, governance: SafetyGovernance):
        self.blackboard = blackboard
        self.governance = governance
        self.common_paths = [
            "/",
            "/api",
            "/api/v1",
            "/docs",
            "/swagger.json",
            "/openapi.json",
            "/debug/version",
            "/debug/config",
            "/robots.txt",
            "/api/v1/user/profile",
            "/api/v1/user/export",
            "/api/v1/admin/config",
            "/api/v1/admin/status",
        ]

    async def run_discovery(self, client: httpx.AsyncClient) -> List[HttpEndpoint]:
        base_url = self.blackboard.target_url.rstrip("/")
        discovered: List[HttpEndpoint] = []

        for path in self.common_paths:
            if not self.governance.is_safe_endpoint(path):
                continue

            target_url = urljoin(base_url, path)
            if not self.governance.is_in_scope(target_url):
                continue

            try:
                resp = await client.get(target_url, timeout=5.0)
                # Check status
                if resp.status_code in [200, 201, 301, 302, 401, 403]:
                    ep = HttpEndpoint(
                        url=target_url,
                        method="GET",
                        path=path,
                        auth_required=(resp.status_code in [401, 403]),
                        source="surface_discovery"
                    )
                    self.blackboard.add_endpoint(ep)
                    discovered.append(ep)

                    # Passive HTML parsing for additional links and forms
                    if "text/html" in resp.headers.get("content-type", ""):
                        self._parse_html_links_and_forms(resp.text, base_url)

                    # Check for tech stack headers
                    server = resp.headers.get("server")
                    if server and server not in self.blackboard.asset.tech_stack:
                        self.blackboard.asset.tech_stack.append(f"Server: {server}")
                    x_powered = resp.headers.get("x-powered-by")
                    if x_powered and x_powered not in self.blackboard.asset.tech_stack:
                        self.blackboard.asset.tech_stack.append(f"X-Powered-By: {x_powered}")

            except Exception as e:
                # Target endpoint unreachable or timeout
                continue

        return discovered

    def _parse_html_links_and_forms(self, html_content: str, base_url: str):
        soup = BeautifulSoup(html_content, "html.parser")
        
        # Parse forms
        for form in soup.find_all("form"):
            action = form.get("action") or ""
            method = (form.get("method") or "GET").upper()
            full_url = urljoin(base_url, action)
            path = urlparse(full_url).path

            params = []
            for inp in form.find_all("input"):
                name = inp.get("name")
                if name:
                    params.append(name)

            if self.governance.is_in_scope(full_url) and self.governance.is_safe_endpoint(path):
                ep = HttpEndpoint(
                    url=full_url,
                    method=method,
                    path=path,
                    parameters=params,
                    source="form_parser"
                )
                self.blackboard.add_endpoint(ep)

        # Parse links
        for a in soup.find_all("a", href=True):
            href = a["href"]
            full_url = urljoin(base_url, href)
            path = urlparse(full_url).path
            if self.governance.is_in_scope(full_url) and self.governance.is_safe_endpoint(path):
                ep = HttpEndpoint(
                    url=full_url,
                    method="GET",
                    path=path,
                    source="link_parser"
                )
                self.blackboard.add_endpoint(ep)
