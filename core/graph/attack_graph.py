from typing import List, Dict, Any, Optional
import networkx as nx
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
            req_artifact = finding.required_preconditions.get("artifact_type")

            if req_artifact:
                # Connected to an artifact state
                artifact_state_node = f"ARTIFACT:{req_artifact}"
                self.graph.add_edge(artifact_state_node, vuln_node, relation="requires_artifact")
            else:
                # Connected to privilege state
                priv_state_node = f"STATE:{req_priv}"
                self.graph.add_edge(priv_state_node, vuln_node, relation="triggers_with_privilege")

            # Check yielded postconditions
            yielded_priv = finding.yielded_postconditions.get("privilege")
            if yielded_priv:
                target_state_node = f"STATE:{yielded_priv}"
                self.graph.add_edge(vuln_node, target_state_node, relation="grants_privilege")

            yielded_artifact = finding.yielded_postconditions.get("leaked_artifact")
            if yielded_artifact:
                artifact_type = yielded_artifact.get("type", "unknown")
                artifact_state_node = f"ARTIFACT:{artifact_type}"
                self.graph.add_edge(vuln_node, artifact_state_node, relation="leaks_artifact")

    def find_exploit_chains(self) -> List[ExploitChain]:
        """
        Analyze paths leading from unauthenticated/low privilege to high/critical impact.
        Synthesizes multi-step chains and computes defensive choke points.
        """
        self.build_graph()
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
                paths = list(nx.all_simple_paths(self.graph, source=start_node, target=target))
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
                        chain_id = f"CHAIN-{i+1}"
                        chain = ExploitChain(
                            chain_id=chain_id,
                            title=f"Multi-step Chained Escalation: {vuln_steps[0].action_description} -> {vuln_steps[-1].action_description}",
                            cumulative_severity=Severity.CRITICAL,
                            initial_privilege=PrivilegeLevel.UNAUTHENTICATED,
                            attained_privilege=PrivilegeLevel.ADMIN,
                            steps=vuln_steps,
                            impact_summary=f"Chaining {len(vuln_steps)} individual findings escalates from Unauthenticated to Admin privilege access.",
                            choke_points=choke_points
                        )
                        chains.append(chain)
                        self.blackboard.add_chain(chain)

            except nx.NetworkXNoPath:
                continue

        return chains
