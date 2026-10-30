from typing import Dict, List, Optional, Any
from core.models.asset import WebAsset, HttpEndpoint
from core.models.state import SecurityState, LeakedArtifact, LeakedArtifactType
from core.models.vulnerability import VulnerabilityFinding, ExploitChain

class SecurityBlackboard:
    """
    Central typed knowledge repository for the vulnerability analysis agent.
    Unlike ARTEX's unstructured text logging, this stores strongly-typed artifacts,
    enabling deterministic pre/post-condition chaining.
    """
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.asset = WebAsset(root_domain=target_url, target_url=target_url)
        self.state = SecurityState()
        self.findings: Dict[str, VulnerabilityFinding] = {}
        self.chains: List[ExploitChain] = []
        self.activity_logs: List[str] = []

    def log(self, message: str):
        self.activity_logs.append(message)

    def add_endpoint(self, endpoint: HttpEndpoint):
        if not self.asset.find_endpoint(endpoint.path, endpoint.method):
            self.asset.endpoints.append(endpoint)
            self.log(f"[Asset] Discovered endpoint: {endpoint.method} {endpoint.path}")

    def add_finding(self, finding: VulnerabilityFinding):
        if finding.id not in self.findings:
            self.findings[finding.id] = finding
            self.log(f"[Finding] [{finding.severity.value}] {finding.title} at {finding.endpoint}")
            
            # If the finding yields new leaked artifacts, record them in security state
            if "leaked_artifact" in finding.yielded_postconditions:
                art_data = finding.yielded_postconditions["leaked_artifact"]
                artifact = LeakedArtifact(
                    artifact_type=art_data.get("type", LeakedArtifactType.DEBUG_INFO),
                    key=art_data.get("key", "unknown"),
                    value=art_data.get("value", ""),
                    source_endpoint=finding.endpoint,
                    description=finding.title
                )
                self.state.add_artifact(artifact)
                self.log(f"[State] Added Leaked Artifact: {artifact.artifact_type.value} -> {artifact.key}={artifact.value}")

    def add_chain(self, chain: ExploitChain):
        self.chains.append(chain)
        self.log(f"[Chain] Identified Exploit Chain: {chain.title} (Severity: {chain.cumulative_severity.value})")

    def get_findings_list(self) -> List[VulnerabilityFinding]:
        return list(self.findings.values())

    def get_artifacts(self, artifact_type: Optional[LeakedArtifactType] = None) -> List[LeakedArtifact]:
        if artifact_type:
            return self.state.get_artifacts_by_type(artifact_type)
        return list(self.state.known_artifacts.values())
