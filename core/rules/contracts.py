from typing import Literal
from pydantic import BaseModel, Field, SecretStr, field_validator


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


class ScanOptions(BaseModel):
    sql: bool = True
    xss: bool = True
    browser: bool = True
    parameters: list[str] = Field(default_factory=list, max_length=10)
    sessions: list[SessionProfile] = Field(default_factory=list, max_length=4)
    primary_session: str | None = None
    access_cases: list[AccessCase] = Field(default_factory=list, max_length=12)
    stored_cases: list[StoredCase] = Field(default_factory=list, max_length=3)
    timing_cases: list[TimingCase] = Field(default_factory=list, max_length=3)
    max_requests: int = Field(default=450, ge=40, le=1000)
    max_response_bytes: int = Field(default=5_000_000, ge=64_000, le=10_000_000)


class CheckResult(BaseModel):
    rule_id: str
    title: str
    status: Literal['PASS','FINDING','SIGNAL','NOT_RUN','ERROR','NOT_SUPPORTED']
    reason: str
    tested: int = 0
    findings: int = 0
    errors: int = 0
    version: str = '1.0'


def record(bb, rule_id, title, status, reason, tested=0, findings=0, errors=0):
    item=CheckResult(rule_id=rule_id,title=title,status=status,reason=reason,tested=tested,findings=findings,errors=errors).model_dump()
    bb.asset.metadata.setdefault('checks',[]).append(item)
    bb.emit('check',item)
    return item
