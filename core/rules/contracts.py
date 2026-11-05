from typing import Literal
from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator


class SessionProfile(BaseModel):
    alias: str = Field(min_length=1, max_length=40)
    headers: dict[str, SecretStr] = Field(default_factory=dict)
    cookies: dict[str, SecretStr] = Field(default_factory=dict)
    login_url: str | None = None
    login_fields: dict[str, SecretStr] = Field(default_factory=dict)

    @field_validator('headers')
    @classmethod
    def allowed_headers(cls, value):
        if any(k.lower() not in ('authorization','x-api-key') for k in value):
            raise ValueError('인증 헤더는 Authorization 또는 X-API-Key만 지정하세요.')
        return value


class AccessCase(BaseModel):
    url: str
    owner: str
    denied: list[str] = Field(default_factory=list, max_length=4)
    protected_fields: list[str] = Field(min_length=1, max_length=10)
    kind: Literal['object', 'role'] = 'object'


class StoredCase(BaseModel):
    write_url: str
    read_url: str
    cleanup_url: str
    field: str = Field(min_length=1,max_length=80)
    fields: dict[str,str] = Field(default_factory=dict)


class TimingCase(BaseModel):
    url: str
    parameter: str
    true_value: str = Field(max_length=200)
    false_value: str = Field(max_length=200)
    delay: float = Field(default=.4, ge=.2, le=.75)


class SystemCase(BaseModel):
    """Explicit contracts for owned loopback fixtures; never arbitrary remote probes."""
    kind: Literal['file', 'command', 'ssrf', 'upload']
    url: str
    parameter: str = 'value'
    control_value: str = 'wva-control'
    probe_value: str = ''
    expected_marker: str = Field(default='', max_length=200)
    shell: Literal['posix', 'windows'] = 'posix'
    callback_url: str | None = None
    receipt_url: str | None = None
    read_url: str | None = None
    cleanup_url: str | None = None
    field: str = 'file'

    @model_validator(mode='after')
    def evidence_contract(self):
        if self.kind=='file' and (len(self.expected_marker)<16 or not self.probe_value or self.expected_marker in self.probe_value):
            raise ValueError('파일 대조에는 별도 경로와 입력에 없는 16자 이상 표식이 필요합니다.')
        if self.kind=='ssrf' and any('{marker}' not in (url or '') for url in (self.callback_url,self.receipt_url)):
            raise ValueError('SSRF 대조에는 {marker} 수신 URL과 별도 수신 기록 URL이 필요합니다.')
        if self.kind=='upload' and ('{filename}' not in (self.read_url or '') or not self.cleanup_url):
            raise ValueError('업로드 대조에는 {filename} 조회 URL과 정리 URL이 필요합니다.')
        return self


class ScanOptions(BaseModel):
    mode: Literal['safe', 'deep'] = 'safe'
    sql: bool = True
    sql_common_parameters: bool = True
    sql_candidate_limit: int = Field(default=12,ge=1,le=24)
    exposure: bool = True
    xss: bool = True
    browser: bool = True
    concurrency_check: bool = True
    teardown_check: bool = True
    parameters: list[str] = Field(default_factory=list, max_length=10)
    sessions: list[SessionProfile] = Field(default_factory=list, max_length=4)
    primary_session: str | None = None
    access_cases: list[AccessCase] = Field(default_factory=list, max_length=12)
    stored_cases: list[StoredCase] = Field(default_factory=list, max_length=3)
    timing_cases: list[TimingCase] = Field(default_factory=list, max_length=3)
    system_cases: list[SystemCase] = Field(default_factory=list, max_length=8)
    max_requests: int = Field(default=450, ge=40, le=2000)
    max_response_bytes: int = Field(default=5_000_000, ge=64_000, le=10_000_000)

    @model_validator(mode='after')
    def cleanup_contract(self):
        if not self.teardown_check and (self.stored_cases or any(c.kind=='upload' for c in self.system_cases)):
            raise ValueError('저장·업로드 시나리오는 정리 확인을 끌 수 없습니다.')
        return self


class CheckResult(BaseModel):
    rule_id: str
    title: str
    status: Literal['PASS','FINDING','SIGNAL','NOT_RUN','ERROR','NOT_SUPPORTED']
    reason: str
    tested: int = 0
    findings: int = 0
    errors: int = 0
    inconclusive: int = 0
    required: bool = True
    version: str = '2.7.0'


def record(bb, rule_id, title, status, reason, tested=0, findings=0, errors=0, required=None, inconclusive=0):
    if status == 'PASS' and (not tested or errors):
        status = 'ERROR' if errors else 'NOT_RUN'
    if required is None:
        required = rule_id in bb.asset.metadata.get('required_checks', ['R11', 'R12'])
    item=CheckResult(rule_id=rule_id,title=title,status=status,reason=reason,tested=tested,findings=findings,errors=errors,required=required,inconclusive=inconclusive).model_dump()
    bb.asset.metadata.setdefault('checks',[]).append(item)
    bb.emit('check',item)
    return item
