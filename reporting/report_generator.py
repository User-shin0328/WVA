import json
from typing import Dict, Any
from core.graph.blackboard import SecurityBlackboard

class SecurityReportGenerator:
    """
    Generates structured Markdown and JSON reports from the security audit blackboard.
    Includes Mermaid attack path diagrams and choke point recommendations.
    """
    def __init__(self, blackboard: SecurityBlackboard):
        self.blackboard = blackboard

    def generate_markdown_report(self) -> str:
        bb = self.blackboard
        findings = bb.get_findings_list()
        chains = bb.chains

        report = []
        report.append("# Web Vulnerability & Attack Path Chaining Analysis Report\n")
        report.append(f"- **Target URL**: `{bb.target_url}`")
        report.append(f"- **Discovered Endpoints**: {len(bb.asset.endpoints)}")
        report.append(f"- **Total Individual Findings**: {len(findings)}")
        report.append(f"- **Identified Exploit Chains**: {len(chains)}\n")

        # 1. Executive Summary & Chained Threats
        report.append("## 1. Executive Summary (Vulnerability Chaining Analysis)")
        if chains:
            report.append("> [!CAUTION]")
            report.append("> **CRITICAL ATTACK PATH DETECTED**: Multiple low/medium vulnerabilities can be chained by an attacker to achieve full administrative compromise.\n")
            for c in chains:
                report.append(f"### {c.title}")
                report.append(f"- **Severity**: **{c.cumulative_severity.value}**")
                report.append(f"- **Privilege Escalation**: `{c.initial_privilege.value}` ➔ `{c.attained_privilege.value}`")
                report.append(f"- **Impact**: {c.impact_summary}\n")
                
                # Mermaid Diagram
                report.append("```mermaid")
                report.append("flowchart LR")
                for s in c.steps:
                    f = bb.findings.get(s.finding_id)
                    title = f.title if f else s.finding_id
                    report.append(f'    Step{s.step_number}["Step {s.step_number}: {title}"]')
                
                # Connect steps
                step_links = " --> ".join([f"Step{s.step_number}" for s in c.steps])
                report.append(f"    {step_links}")
                report.append(f'    Step{c.steps[-1].step_number} --> Impact["Admin Compromise"]')
                report.append("```\n")

                # Choke Point Defense
                report.append("#### 🛡️ Choke Point Defensive Strategy (최소 비용 최우선 방어 거점)")
                report.append("공격자는 체인 전체를 성공시켜야 하지만, 방어자는 다음 핵심 차단점 중 하나만 해결해도 공격 경로 전체를 무력화할 수 있습니다:\n")
                for cp in c.choke_points:
                    report.append(f"- **[Step {cp.step_number} 차단] {cp.target_endpoint}** (수정 난이도: {cp.effort_level})")
                    report.append(f"  - 조치: `{cp.recommended_patch}`")
                    report.append(f"  - 효과: {cp.defense_impact}\n")
        else:
            report.append("No multi-step exploit chains were detected. Isolated findings are detailed below.\n")

        # 2. Detailed Findings
        report.append("## 2. Individual Vulnerability Findings\n")
        report.append("| ID | Severity | Title | Endpoint | CWE |")
        report.append("|:---|:---:|:---|:---|:---:|")
        for f in findings:
            report.append(f"| {f.id} | {f.severity.value} | {f.title} | `{f.endpoint}` | {f.cwe_id or '-'} |")
        report.append("\n")

        for f in findings:
            report.append(f"### [{f.severity.value}] {f.title}")
            report.append(f"- **Endpoint**: `{f.method} {f.endpoint}`")
            report.append(f"- **CVSS Score**: {f.cvss_score}")
            report.append(f"- **Description**: {f.description}")
            report.append(f"- **Evidence**: `{f.evidence}`")
            report.append(f"- **Remediation**: {f.remediation}\n")

        # 3. Discovered Surface
        report.append("## 3. Discovered Attack Surface Endpoints\n")
        for ep in bb.asset.endpoints:
            auth_str = "Auth Required" if ep.auth_required else "Public"
            report.append(f"- `{ep.method} {ep.path}` ({auth_str}) [Source: {ep.source}]")
        report.append("\n")

        return "\n".join(report)

    def generate_json_report(self) -> Dict[str, Any]:
        bb = self.blackboard
        return {
            "target_url": bb.target_url,
            "endpoints": [ep.model_dump() for ep in bb.asset.endpoints],
            "findings": [f.model_dump() for f in bb.get_findings_list()],
            "exploit_chains": [c.model_dump() for c in bb.chains],
            "activity_logs": bb.activity_logs
        }
