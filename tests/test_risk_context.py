import csv
import io
import json
import pytest
from reporting.remediation import finding_details
from tests.test_dashboard_revision import demo


CASES = [
    ("VULN-CSP-1", "MISSING_SECURITY_HEADER"),
    ("VULN-HSTS-1", "MISSING_SECURITY_HEADER"),
    ("debug", "EXPOSED_DEBUG_ENDPOINT"),
    ("object", "BOLA_IDOR"),
    ("admin", "PRIVILEGE_ESCALATION"),
    ("cors", "CORS_MISCONFIGURATION"),
    ("cookie", "COOKIE_SECURITY_FLAG"),
]


def finding(id="admin", type="PRIVILEGE_ESCALATION"):
    return {"id": id, "vuln_type": type, "title": id, "endpoint": "/example", "evidence": "observed-original"}


@pytest.mark.parametrize("id,type", CASES)
def test_known_risk_explains_attack_conditions_and_observation_limits(id, type):
    context = finding_details(finding(id,type))["risk_context"]
    assert context["summary"] and context["observation"] and context["assessment"]
    assert context["limits"] and context["references"]
    assert context["attacks"] and all(a["name"] and a["scenario"] and a["conditions"] for a in context["attacks"])


def test_unknown_type_does_not_invent_an_attack():
    context = finding_details(finding("unknown", "PARAMETER_REFLECTION"))["risk_context"]
    assert context["attacks"] == []
    assert context["assessment"] == "추가 검토 필요"


def test_profile_lists_are_not_shared_between_findings():
    first = finding_details(finding())["risk_context"]
    first["attacks"][0]["conditions"].clear()
    assert finding_details(finding())["risk_context"]["attacks"][0]["conditions"]


@pytest.mark.parametrize("id,forbidden", [("VULN-CSP-1","네트워크 가로채기"),("VULN-HSTS-1","스크립트 삽입")])
def test_security_header_explanations_remain_specific(id, forbidden):
    context = finding_details(finding(id,"MISSING_SECURITY_HEADER"))["risk_context"]
    assert forbidden not in json.dumps(context,ensure_ascii=False)
    if "CSP" in id:
        assert "CSP 누락만으로 XSS" in context["limits"][0]
    else:
        assert "정상 HTTPS 암호화가 깨졌다는 뜻이 아닙니다" in context["limits"][0]


def test_risk_explanation_does_not_change_observed_evidence_or_severity():
    data={**finding(),"severity":"LOW","cvss_score":3.1}
    enriched=finding_details(data)
    assert all(enriched[key]==value for key,value in data.items())
    assert "risk_context" not in data


@pytest.mark.parametrize("format", ["json","md","csv"])
@pytest.mark.asyncio
async def test_risk_context_survives_selected_and_automatic_reports(client, format):
    status=await demo(client)
    response=await client.post('/api/scan/export',json={"scan_id":status["scan_id"],"sections":["findings"],"format":format})
    assert response.status_code==200
    if format=="json":
        items=response.json()["findings"]
        assert all(f["risk_context"]["attacks"] and f["risk_context"]["limits"] for f in items)
        auto=(await client.get('/api/scan/report/json')).json()["findings"]
        assert {f["id"]:f["risk_context"] for f in auto}=={f["id"]:f["risk_context"] for f in items}
    elif format=="md":
        assert '#### 가능한 공격' in response.text and '성립 조건:' in response.text and '#### 확인 범위' in response.text
        auto=(await client.get('/api/scan/report/md')).text
        assert '#### 가능한 공격' in auto and '서버 전체 장악' in auto
    else:
        rows=list(csv.reader(io.StringIO(response.text.lstrip('\ufeff'))))
        assert all(len(row)==25 for row in rows)
        assert rows[0][21:24]==['가능한 공격','성립 조건','확인 범위']
        assert all(row[21] and row[22] and row[23] for row in rows[2:])
