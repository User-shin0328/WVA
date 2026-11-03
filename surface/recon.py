import httpx
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlsplit as urlparse, parse_qs
from datetime import datetime, timezone
from time import perf_counter
from collections import deque

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
        discovered: List[HttpEndpoint] = []
        queue = deque([self.governance.target_base_url] + [self.governance.url_for_path(path) for path in self.governance.probe_paths(self.common_paths)])
        visited = set()
        # Follow HTML links within the selected boundary; schema operations stay passive.
        while queue and len(visited) < 80:
            target_url = str(httpx.URL(queue.popleft()).copy_with(fragment=None))
            path = urlparse(target_url).path or "/"
            if target_url in visited or not self.governance.is_in_scope(target_url) or not self.governance.is_safe_endpoint(path):
                continue
            visited.add(target_url)
            try:
                request_start = perf_counter()
                resp = await client.get(target_url, timeout=5.0)
                # Check status
                if resp.status_code in [200, 201, 301, 302, 307, 308, 401, 403, 405, 422]:
                    ep = HttpEndpoint(
                        url=target_url,
                        method="GET",
                        path=path,
                        parameters=list(parse_qs(urlparse(target_url).query, keep_blank_values=True)),
                        auth_required=(resp.status_code in [401, 403]),
                        source="surface_discovery",
                        status_code=resp.status_code,
                        content_type=resp.headers.get("content-type", "").split(";")[0],
                        response_time_ms=round((perf_counter() - request_start) * 1000, 2),
                        response_bytes=len(resp.content),
                        checked_at=datetime.now(timezone.utc).isoformat(),
                        headers={k: v for k, v in resp.headers.items() if k in {
                            "server", "x-powered-by", "content-security-policy", "strict-transport-security",
                            "x-content-type-options", "x-frame-options", "access-control-allow-origin",
                            "access-control-allow-credentials", "location"}}
                    )
                    self.blackboard.add_endpoint(ep)
                    discovered.append(ep)

                    # Passive HTML parsing for additional links, forms and scripts
                    if "text/html" in resp.headers.get("content-type", ""):
                        self._parse_html_links_and_forms(resp.text, target_url)
                        for item in self.blackboard.asset.endpoints:
                            if item.method == "GET" and "link_parser" in item.sources and item.url not in visited and len(queue) < 160:
                                queue.append(item.url)
                    if path.endswith(("/openapi.json", "/swagger.json")) and resp.status_code == 200:
                        self._parse_openapi(resp, self.governance.origin_url)

                    # Check for tech stack headers
                    server = resp.headers.get("server")
                    if server and f"Server: {server}" not in self.blackboard.asset.tech_stack:
                        self.blackboard.asset.tech_stack.append(f"Server: {server}")
                    x_powered = resp.headers.get("x-powered-by")
                    if x_powered and f"X-Powered-By: {x_powered}" not in self.blackboard.asset.tech_stack:
                        self.blackboard.asset.tech_stack.append(f"X-Powered-By: {x_powered}")

            except Exception as e:
                # Target endpoint unreachable or timeout
                continue

        if queue:
            self.blackboard.log("[Surface] 경로 탐색 상한 80개에 도달했습니다. 나머지 링크는 요청하지 않았습니다.")
        return discovered

    def _parse_html_links_and_forms(self, html_content: str, base_url: str):
        soup = BeautifulSoup(html_content, "html.parser")
        
        # Parse forms
        for form in soup.find_all("form"):
            action = form.get("action") or ""
            method = (form.get("method") or "GET").upper()
            full_url = urljoin(base_url, action).split("#", 1)[0]
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
            full_url = urljoin(base_url, href).split("#", 1)[0]
            path = urlparse(full_url).path
            if self.governance.is_in_scope(full_url) and self.governance.is_safe_endpoint(path):
                ep = HttpEndpoint(
                    url=full_url,
                    method="GET",
                    path=path,
                    parameters=list(parse_qs(urlparse(full_url).query)),
                    source="link_parser"
                )
                self.blackboard.add_endpoint(ep)

        # Parse client-side scripts for bundle secret scanning
        for s in soup.find_all("script", src=True):
            src = s["src"]
            full_url = urljoin(base_url, src).split("#", 1)[0]
            path = urlparse(full_url).path
            if self.governance.is_in_scope(full_url) and self.governance.is_safe_endpoint(path):
                ep = HttpEndpoint(
                    url=full_url,
                    method="GET",
                    path=path,
                    parameters=[],
                    source="script_parser"
                )
                self.blackboard.add_endpoint(ep)

    def _parse_openapi(self, response: httpx.Response, base_url: str):
        try:
            document = response.json()
        except ValueError:
            return
        if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
            return
        for path, operations in list(document["paths"].items())[:500]:
            if not isinstance(operations, dict) or not isinstance(path, str) or not path.startswith("/"):
                continue
            full_url = urljoin(base_url, path)
            if not self.governance.is_in_scope(full_url) or not self.governance.is_safe_endpoint(path):
                continue
            for method, operation in operations.items():
                if method.lower() not in ("get", "head", "post", "put", "patch", "delete", "options") or not isinstance(operation, dict):
                    continue
                parameters = [p.get("in", "query") + ":" + p["name"] for p in operation.get("parameters", [])
                              if isinstance(p, dict) and isinstance(p.get("name"), str)]
                # Schema discovery does not execute the operation or establish its accessibility.
                self.blackboard.add_endpoint(HttpEndpoint(url=full_url, path=path, method=method.upper(), parameters=parameters, source="openapi"))
