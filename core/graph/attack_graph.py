from typing import List, Dict, Any, Optional
import networkx as nx
import hashlib
from core.models.state import PrivilegeLevel, LeakedArtifactType
from core.models.vulnerability import (
    VulnerabilityFinding, ExploitChain, ExploitChainStep, ChokePoint, Severity
)
from core.graph.blackboard import SecurityBlackboard

class AttackGraphEngine:
    """
    Formal state-based attack path and vulnerability chaining engine.
    Uses NetworkX directed graph to model state transitions:
    [Initial State] -> (Vulnerability Action) -> [Intermediate State] -> (Escalation) -> [Target Impact]
    """
    def __init__(self, blackboard: SecurityBlackboard):
        self.blackboard = blackboard
        self.graph = nx.DiGraph()

    def build_graph(self):
        """Construct the attack graph from current findings and security states."""
        self.graph.clear()
        
        # 1. Base Node: Initial State
        initial_node = f"STATE:{PrivilegeLevel.UNAUTHENTICATED.value}"
        self.graph.add_node(initial_node, node_type="state", privilege=PrivilegeLevel.UNAUTHENTICATED.value)

        # 2. Add finding nodes and connect based on preconditions and postconditions
        for finding in self.blackboard.get_findings_list():
            vuln_node = f"VULN:{finding.id}"
            self.graph.add_node(
                vuln_node,
                node_type="vulnerability",
                finding_id=finding.id,
                title=finding.title,
                endpoint=finding.endpoint,
                severity=finding.severity.value,
                remediation=finding.remediation
            )

            # Check required preconditions
            req_priv = finding.required_preconditions.get("privilege", PrivilegeLevel.UNAUTHENTICATED.value)
            req_artifact = finding.required_preconditions.get("artifact_ref")

            if req_artifact:
                # Connected to an artifact state
                artifact_state_node = self.artifact_node(req_artifact)
                self.graph.add_edge(artifact_state_node, vuln_node, relation="requires_artifact")
            elif finding.required_preconditions.get('artifact_type'):
                # An artifact type alone does not prove possession of this credential.
                continue
            else:
                # Connected to privilege state
                priv_state_node = f"STATE:{req_priv}"
                self.graph.add_edge(priv_state_node, vuln_node, relation="triggers_with_privilege")

            # Check yielded postconditions
            yielded_priv = finding.yielded_postconditions.get("privilege")
            if yielded_priv and finding.yielded_postconditions.get('privilege_verified') is True:
                target_state_node = f"STATE:{yielded_priv}"
                self.graph.add_edge(vuln_node, target_state_node, relation="grants_privilege")

            yielded_artifact = finding.yielded_postconditions.get("leaked_artifact")
            if yielded_artifact:
                artifact_state_node = self.artifact_node(yielded_artifact)
                self.graph.add_edge(vuln_node, artifact_state_node, relation="leaks_artifact")

    def artifact_node(self, artifact):
        identity='|'.join([self.blackboard.target_url,artifact.get('type','unknown'),artifact.get('value',''),artifact.get('session','anonymous')])
        return 'ARTIFACT:'+hashlib.sha256(identity.encode()).hexdigest()[:24]

    def bounded_paths(self, source, target):
        stack=[(source,[source])];visits=found=0
        while stack:
            node,path=stack.pop();visits+=1
            if visits>4000 or found>=100:
                self.blackboard.asset.metadata['chain_truncated']=True
                return
            if node==target:
                found+=1;yield path;continue
            if len(path)>=13:
                if any(n not in path for n in self.graph.successors(node)):
                    self.blackboard.asset.metadata['chain_truncated']=True
                continue
            for successor in sorted(self.graph.successors(node),reverse=True):
                if successor not in path:stack.append((successor,path+[successor]))

    def find_exploit_chains(self) -> List[ExploitChain]:
        """
        Analyze paths leading from unauthenticated/low privilege to high/critical impact.
        Synthesizes multi-step chains and computes defensive choke points.
        """
        self.build_graph()
        self.blackboard.chains.clear()
        self.blackboard.asset.metadata['chain_truncated']=False
        chains: List[ExploitChain] = []
        start_node = f"STATE:{PrivilegeLevel.UNAUTHENTICATED.value}"
        target_nodes = [
            f"STATE:{PrivilegeLevel.ADMIN.value}",
            f"STATE:{PrivilegeLevel.SYSTEM.value}"
        ]

        for target in target_nodes:
            if not self.graph.has_node(target) or not self.graph.has_node(start_node):
                continue

            try:
                # Find all simple paths from start to target
                paths = self.bounded_paths(start_node,target)
                for i, path in enumerate(paths):
                    # Filter only vulnerability nodes in the path
                    vuln_steps: List[ExploitChainStep] = []
                    choke_points: List[ChokePoint] = []
                    step_counter = 1

                    for node in path:
                        if node.startswith("VULN:"):
                            finding_id = self.graph.nodes[node]["finding_id"]
                            finding = self.blackboard.findings.get(finding_id)
                            if finding:
                                vuln_steps.append(
                                    ExploitChainStep(
                                        step_number=step_counter,
                                        finding_id=finding.id,
                                        action_description=f"Exploit {finding.title} at {finding.endpoint}",
                                        input_used=finding.required_preconditions,
                                        result_obtained=finding.yielded_postconditions
                                    )
                                )
                                # Each step is a candidate choke point where defense can cut the chain
                                choke_points.append(
                                    ChokePoint(
                                        step_number=step_counter,
                                        target_endpoint=finding.endpoint,
                                        recommended_patch=finding.remediation or "Implement strict validation and authorization",
                                        effort_level="LOW" if step_counter == 1 else "MEDIUM",
                                        defense_impact=f"Fixing Step {step_counter} prevents progression to critical impact"
                                    )
                                )
                                step_counter += 1

                    if len(vuln_steps) > 1:
                        # Multi-step chain discovered!
                        chain_id = 'CHAIN-'+hashlib.sha256('|'.join(path).encode()).hexdigest()[:12]
                        chain = ExploitChain(
                            chain_id=chain_id,
                            title=f"Multi-step Chained Escalation: {vuln_steps[0].action_description} -> {vuln_steps[-1].action_description}",
                            cumulative_severity=Severity.CRITICAL,
                            initial_privilege=PrivilegeLevel.UNAUTHENTICATED,
                            attained_privilege=PrivilegeLevel(target.removeprefix('STATE:')),
                            steps=vuln_steps,
                            impact_summary=f"응답 증거 {len(vuln_steps)}개가 연결되어 {target.removeprefix('STATE:')} 응답 접근 경로를 구성합니다. 시스템 장악이나 관리자 기능 실행은 입증하지 않습니다.",
                            choke_points=choke_points
                        )
                        chains.append(chain)
                        self.blackboard.add_chain(chain)

            except nx.NetworkXNoPath:
                continue

        return chains

    def to_cytoscape_elements(self) -> Dict[str, List[Dict[str, Any]]]:
        """Convert the attack graph to Cytoscape.js nodes and edges JSON format."""
        self.build_graph()
        nodes = []
        edges = []

        chain_vuln_ids = set()
        for c in self.blackboard.chains:
            for s in c.steps:
                chain_vuln_ids.add(s.finding_id)

        for node_id, attrs in self.graph.nodes(data=True):
            ntype = attrs.get("node_type", "state")
            label = node_id
            severity = attrs.get("severity", "INFO")
            is_in_chain = False

            if ntype == "vulnerability":
                fid = attrs.get("finding_id", "")
                label = attrs.get("title", fid)
                is_in_chain = fid in chain_vuln_ids
            elif ntype == "state":
                priv = attrs.get("privilege", "")
                label = f"Privilege: {priv.upper()}"
            elif "ARTIFACT:" in node_id:
                label = f"Artifact: {node_id.replace('ARTIFACT:', '')}"

            nodes.append({
                "data": {
                    "id": node_id,
                    "label": label,
                    "type": ntype,
                    "severity": severity,
                    "is_in_chain": is_in_chain,
                    "endpoint": attrs.get("endpoint", ""),
                    "remediation": attrs.get("remediation", "")
                }
            })

        for u, v, attrs in self.graph.edges(data=True):
            edges.append({
                "data": {
                    "id": f"{u}->{v}",
                    "source": u,
                    "target": v,
                    "label": attrs.get("relation", "")
                }
            })

        return {"nodes": nodes, "edges": edges}
