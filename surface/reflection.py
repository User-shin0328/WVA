import httpx
import uuid
from typing import Optional, Dict, Any
from core.graph.blackboard import SecurityBlackboard
from core.models.vulnerability import VulnerabilityFinding, VulnerabilityType, Severity
from core.safety.governance import SafetyGovernance

class ReflectionCanaryAuditor:
    """
    Tests input reflection safely using harmless unique canary tokens.
    Checks whether the input is reflected verbatim in the response and identifies context.
    """
    def __init__(self, blackboard: SecurityBlackboard, governance: SafetyGovernance):
        self.blackboard = blackboard
        self.governance = governance

    async def audit_endpoint_parameters(self, client: httpx.AsyncClient, path: str, param_names: list):
        if not self.governance.is_safe_endpoint(path):
            return

        base_url = self.blackboard.target_url.rstrip("/")
        for param in param_names:
            canary_id = f"canary_{uuid.uuid4().hex[:8]}"
            test_val = f'{canary_id}"<probe>'
            test_val = self.governance.sanitize_canary(test_val)

            target_url = f"{base_url}{path}"
            try:
                resp = await client.get(target_url, params={param: test_val}, timeout=5.0)
                content_type = resp.headers.get("content-type", "")

                if canary_id in resp.text:
                    # Input reflected
                    evidence = f"Parameter '{param}' reflected in response body. Content-Type: {content_type}"
                    is_html = "text/html" in content_type

                    if is_html and "<probe>" in resp.text:
                        # Raw unencoded reflection in HTML
                        finding = VulnerabilityFinding(
                            id=f"VULN-REFLECT-{param}-{path.replace('/', '_')}",
                            vuln_type=VulnerabilityType.PARAMETER_REFLECTION,
                            title=f"Unsanitized Parameter Reflection ({param})",
                            severity=Severity.MEDIUM,
                            endpoint=path,
                            description=f"Parameter '{param}' is reflected without HTML encoding in an HTML response.",
                            evidence=evidence,
                            cwe_id="CWE-79",
                            cvss_score=6.1,
                            required_preconditions={"privilege": "unauthenticated"},
                            yielded_postconditions={"reflection_context": "html_body", "param": param},
                            remediation="Apply context-aware HTML entity encoding or template auto-escaping."
                        )
                        self.blackboard.add_finding(finding)
                    else:
                        # Reflected but sanitized or in JSON
                        finding = VulnerabilityFinding(
                            id=f"VULN-INFO-REFLECT-{param}-{path.replace('/', '_')}",
                            vuln_type=VulnerabilityType.PARAMETER_REFLECTION,
                            title=f"Benign Parameter Echo ({param})",
                            severity=Severity.INFO,
                            endpoint=path,
                            description=f"Parameter '{param}' is echoed back safely or in structured JSON.",
                            evidence=evidence,
                            cwe_id="CWE-20",
                            cvss_score=0.0,
                            required_preconditions={"privilege": "unauthenticated"},
                            yielded_postconditions={"param_candidate": param},
                            remediation="Maintain current output encoding practices."
                        )
                        self.blackboard.add_finding(finding)

            except Exception:
                continue
