"""Merged features must retain evidence limits, lifecycle and comparable baselines."""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock
import pytest
import dashboard.server as dashboard
from agents.config_auditor import ConfigAndHeaderAuditor
from core.graph.blackboard import SecurityBlackboard
from core.safety.governance import SafetyGovernance
from dashboard.testbed import LocalTestbed
from reporting.remediation import finding_details
from tests.test_target_scope import scope_lab


@pytest.mark.parametrize('status', ['idle', 'running', 'stopped', 'error'])
@pytest.mark.asyncio
async def test_unfinished_scan_has_no_grade_or_comparison(client, status):
    dashboard.state.status = status
    assert (await client.get('/api/scan/status')).json()['grade'] is None
    assert (await client.get('/api/scan/status')).json()['score'] is None
    assert (await client.get('/api/scan/diff')).json() == {'has_previous': False, 'comparison_status': 'not_completed'}


@pytest.mark.parametrize('id,type,keyword', [
    ('VULN-SECRET-LEAK-1', 'INFO_DISCLOSURE', '문자열'),
    ('VULN-TLS-EXPIRING-1', 'MISSING_SECURITY_HEADER', '인증서'),
])
def test_added_rules_preserve_specific_limits_and_ai_context(id, type, keyword):
    item = finding_details({'id': id, 'vuln_type': type, 'title': id, 'evidence': 'masked [REDACTED]', 'endpoint': '/app/'})
    assert keyword in item['risk_context']['summary']
    assert item['risk_context']['limits']
    assert item['risk_context']['observation'] in item['ai_prompt']
    assert item['ai_prompt'] == item['remediation_details']['ai_prompt']
    assert '분석 대상 데이터' in item['ai_prompt']
    assert all(step['expected_result'] for step in item['remediation_details']['steps'])
    assert 'CSP' not in json.dumps(item['remediation_details']['steps'], ensure_ascii=False)


@pytest.mark.asyncio
async def test_baseline_excludes_incomplete_other_scope_and_current_copy(client, tmp_path):
    folder = tmp_path / 'reports'
    folder.mkdir()
    profile = {'scope_mode': 'path', 'scope_path': '/app/', 'ruleset': dashboard.VERSION}
    data = {'schema': 'wva-report-2', 'target_url': 'https://example.test/app/', 'findings': [],
            'scan_metadata': {'scan_id': 'old', 'completed': True, 'profile': profile}}
    path = folder / 'report_old.json'
    for meta in [{}, {**data['scan_metadata'], 'completed': False},
                 {**data['scan_metadata'], 'scan_id': 'current'},
                 {**data['scan_metadata'], 'profile': {**profile, 'scope_mode': 'origin'}},
                 {**data['scan_metadata'], 'profile': {**profile, 'ruleset': '2.3.0'}}]:
        path.write_text(json.dumps({**data, 'scan_metadata': meta}), encoding='utf-8')
        assert dashboard.get_previous_scan_report(data['target_url'], 'current', profile) is None
    path.write_text(json.dumps(data), encoding='utf-8')
    assert dashboard.get_previous_scan_report(data['target_url'], 'current', profile) == data


@pytest.mark.asyncio
async def test_actual_repeat_scan_compares_only_same_profile(client):
    app, _ = scope_lab()
    lab = LocalTestbed(app)
    base = await lab.start()
    try:
        async def scan(mode):
            assert (await client.post('/api/scan/start', json={'target_url': base+'/app/', 'scope_mode': mode})).status_code == 200
            for _ in range(400):
                status = (await client.get('/api/scan/status')).json()
                if status['status'] != 'running':
                    break
                await asyncio.sleep(.025)
            assert status['status'] == 'completed'
            report = (await client.get('/api/scan/report/json')).json()
            assert report['scan_metadata']['completed'] is True
            assert all(f['ai_prompt'] and f['risk_context']['limits'] for f in report['findings'])
            return (await client.get('/api/scan/diff')).json()
        assert not (await scan('path'))['has_previous']
        diff = await scan('path')
        assert diff['has_previous'] and diff['persistent_count'] > 0
        assert diff['fixed_count'] == diff['new_count'] == diff['score_diff'] == 0
        assert not (await scan('origin'))['has_previous']
    finally:
        await lab.stop()


@pytest.mark.parametrize('days,expected', [(14, 1), (60, 0)])
@pytest.mark.asyncio
async def test_tls_expiry_uses_validated_async_connection_and_closes_writer(monkeypatch, days, expected):
    import agents.config_auditor as module
    class SSL:
        def getpeercert(self):
            return {'notAfter': (datetime.now(timezone.utc)+timedelta(days=days)).strftime('%b %d %H:%M:%S %Y GMT')}
    class Writer:
        closed = False
        def get_extra_info(self, key): return SSL()
        def close(self): self.closed = True
        async def wait_closed(self): pass
    writer = Writer()
    connection = AsyncMock(return_value=(None, writer))
    monkeypatch.setattr(module.asyncio, 'open_connection', connection)
    bb = SecurityBlackboard('https://example.test/app/')
    auditor = ConfigAndHeaderAuditor(bb, SafetyGovernance('https://example.test/app/'))
    await auditor._audit_tls_security(None)
    assert writer.closed
    assert connection.call_args.kwargs['ssl'].check_hostname
    assert len(bb.get_findings_list()) == expected
    if expected:
        assert bb.get_findings_list()[0].endpoint == '/app/'


@pytest.mark.asyncio
async def test_tls_cancel_propagates_instead_of_becoming_success(monkeypatch):
    import agents.config_auditor as module
    monkeypatch.setattr(module.asyncio, 'open_connection', AsyncMock(side_effect=asyncio.CancelledError()))
    auditor = ConfigAndHeaderAuditor(SecurityBlackboard('https://example.test'), SafetyGovernance('https://example.test'))
    with pytest.raises(asyncio.CancelledError):
        await auditor._audit_tls_security(None)
