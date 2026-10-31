import re
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class HttpEndpoint(BaseModel):
    url: str
    method: str = "GET"
    path: str
    parameters: List[str] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    auth_required: bool = False
    source: str = "crawler"  # crawler, static_js, sitemap, openapi
    sources: List[str] = Field(default_factory=list)
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    response_time_ms: Optional[float] = None
    response_bytes: Optional[int] = None
    checked_at: Optional[str] = None

class WebAsset(BaseModel):
    root_domain: str
    target_url: str
    subdomains: List[str] = Field(default_factory=list)
    endpoints: List[HttpEndpoint] = Field(default_factory=list)
    tech_stack: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def find_endpoint(self, path: str, method: str = "GET") -> Optional[HttpEndpoint]:
        for ep in self.endpoints:
            if ep.path == path and ep.method.upper() == method.upper():
                return ep
        return None
