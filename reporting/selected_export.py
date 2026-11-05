"""Selected-section exports: JSON, readable Markdown, and spreadsheet-friendly CSV."""
import csv
import io
import json
from reporting.risk_context import risk_context_lines

TITLES = {"summary": "진단 요약", "findings": "발견 항목", "chains": "연계 경로", "endpoints": "공격 표면", "logs": "진단 로그"}

def scalar(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return "" if value is None else str(value)

def safe_cell(value):
    text = scalar(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text

def ordered_action_lines(details):
    lines = []
    if details.get("steps"):
        for step in details["steps"]:
            lines += [f"{step['order']}. **{step['title']}**", f"   - 조치: {step['action']}", f"   - 완료 기준: {step['expected_result']}"]
    else:
        lines += [f"{i}. {action}" for i, action in enumerate(details.get("actions", []), 1)]
    return lines

def ordered_action_text(details, fallback=""):
    if details.get("steps"):
        return "\n\n".join(f"{s['order']}. {s['title']}\n조치: {s['action']}\n완료 기준: {s['expected_result']}" for s in details["steps"])
    return "\n".join(f"{i}. {action}" for i, action in enumerate(details.get("actions", []), 1)) or fallback


def render_sarif(payload):
    meta = payload.get("metadata", {})
    findings = payload.get("findings", [])
    if isinstance(findings, dict):
        findings = [findings]

    rules = []
    results = []
    seen_rules = set()

    for f in findings:
        rule_id = f.get("cwe_id") or f.get("vuln_type") or "WVA-RULE"
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": f.get("vuln_type", "Vulnerability"),
                "shortDescription": {"text": f.get("title", rule_id)},
                "fullDescription": {"text": f.get("description", "")},
                "help": {"text": f.get("remediation", "")},
                "properties": {
                    "cwe": f.get("cwe_id", ""),
                    "kisa": f.get("kisa_id", ""),
                    "cvss": f.get("cvss_score", 0.0)
                }
            })

        sev = (f.get("severity") or "LOW").upper()
        level = "error" if sev in ("CRITICAL", "HIGH") else "warning" if sev == "MEDIUM" else "note"
        url = f.get("request_url") or f.get("endpoint") or "/"

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"{f.get('title')}: {f.get('evidence', '')}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": url}
                }
            }]
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "WVA",
                    "version": "2.6.0",
                    "informationUri": "https://github.com/User-shin0328/WVA",
                    "rules": rules
                }
            },
            "results": results
        }]
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2), "application/sarif+json", "sarif"

def render_export(payload, format):
    if format == "sarif":
        return render_sarif(payload)
    if format == "json":
        return json.dumps(payload, ensure_ascii=False, indent=2), "application/json", "json"
    if format == "csv":
        buffer = io.StringIO(newline="")
        columns = ["구분", "진단ID", "대상", "ID", "위험도", "제목", "메서드", "경로", "HTTP", "CVSS", "CWE", "증거", "조치요약", "권고사항", "매개변수", "콘텐츠유형", "응답시간ms", "응답크기bytes", "수집출처", "시각", "로그", "가능한 공격", "성립 조건", "확인 범위", "상세JSON"]
        writer = csv.writer(buffer)
        writer.writerow(columns)
        meta = payload["metadata"]
        writer.writerow(["진단 정보",meta["scan_id"],meta["target_url"]] + [""] * (len(columns) - 4) + [safe_cell(meta)])
        for section in TITLES:
            if section not in payload:
                continue
            records = payload[section] if isinstance(payload[section], list) else [payload[section]]
            for r in records:
                details = r.get("remediation_details", {})
                risk = r.get("risk_context", {})
                row = [TITLES[section], meta["scan_id"], meta["target_url"], r.get("id",r.get("chain_id","")),r.get("severity",r.get("cumulative_severity","")),
                       r.get("title",""),r.get("method",""),r.get("request_url") or r.get("url") or r.get("endpoint",r.get("path","")),r.get("status_code",""),r.get("cvss_score",""),r.get("cwe_id",""),
                       r.get("evidence",""),details.get("summary",""),ordered_action_text(details,r.get("remediation","")),r.get("parameters",""),r.get("content_type",""),
                       r.get("response_time_ms",""),r.get("response_bytes",""),r.get("sources",r.get("source","")),r.get("timestamp",r.get("checked_at","")),r.get("data",""),
                       "\n\n".join(a["name"]+": "+a["scenario"] for a in risk.get("attacks", [])),
                       "\n\n".join(a["name"]+"\n"+"\n".join(a["conditions"]) for a in risk.get("attacks", [])), "\n".join(risk.get("limits", [])),r]
                writer.writerow([safe_cell(v) for v in row])
        return "\ufeff" + buffer.getvalue(), "text/csv", "csv"
    lines = ["# WVA 선택 정보 보고서", ""]
    for key, value in payload["metadata"].items():
        lines.append(f"- **{key}**: {scalar(value)}")
    for section,title in TITLES.items():
        if section not in payload:
            continue
        lines += ["", "## " + title, ""]
        records = payload[section] if isinstance(payload[section],list) else [payload[section]]
        if not records:
            lines.append("해당 항목 없음")
        for index, record in enumerate(records,1):
            lines += ["### " + str(index) + ". " + record.get("title", record.get("path",record.get("chain_id",title))), ""]
            for key,value in record.items():
                if key == "risk_context":
                    lines += risk_context_lines(value)
                elif key == "remediation_details":
                    lines += ["", "#### 조치사항", "", value["summary"]]
                    lines += ordered_action_lines(value)
                    lines += ["", "#### 수정 후 확인", ""] + ["- " + v for v in value["verification"]]
                else:
                    lines.append("- **" + key + "**: " + scalar(value).replace("\n","  \n  "))
    return "\n".join(lines) + "\n", "text/markdown", "md"
