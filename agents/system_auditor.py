"""
System and server-level vulnerability auditor.
Safely detects Path Traversal (LFI), OS Command Injection, SSRF, and Arbitrary File Upload.
Uses non-destructive, read-only canary probes.
"""
import hashlib
import re
from urllib.parse import urlsplit, parse_qs
import httpx
from core.http.requester import SKIP
from core.rules.contracts import record
from core.models.vulnerability import VulnerabilityFinding, VulnerabilityType, Severity
from core.models.state import LeakedArtifactType, PrivilegeLevel

LFI_PARAM_PATTERN = re.compile(r"\b(?:file|filepath|path|doc|document|page|template|dir|directory|download|read|url|src|filename)\b", re.I)
LFI_PATH_PATTERN = re.compile(r"/(?:download|docs?|files?|read|view)(?:/|$)", re.I)

LFI_PROBES = [
    "../../../../../../etc/passwd",
    "../../etc/passwd",
    r"..\..\..\..\win.ini",
    r"..\..\win.ini",
    "....//....//....//etc/passwd"
]
LFI_SIGNATURES = re.compile(
    r"root:x:0:0:|daemon:x:1:1:|nobody:x:|\[boot loader\]|\[fonts\]|\[extensions\]|for 16-bit app support|PATH_TRAVERSAL",
    re.I
)

CMD_PARAM_PATTERN = re.compile(r"\b(?:target|ip|host|cmd|command|exec|ping|domain|query|addr|lookup|sys)\b", re.I)
CMD_PATH_PATTERN = re.compile(r"/(?:tools?|ping|exec|cmd|network|dns)(?:/|$)", re.I)

CMD_PROBES = [
    "; whoami",
    "| whoami",
    "& whoami",
    "; echo wva_canary",
    "&& echo wva_canary"
]
CMD_SIGNATURES = re.compile(
    r"wva_canary|uid=\d+\([a-zA-Z0-9_-]+\)|system_context:|REMOTE_CODE_EXECUTION",
    re.I
)

SSRF_PARAM_PATTERN = re.compile(r"\b(?:url|uri|webhook|callback|dest|target|link|endpoint|site|proxy|fetch)\b", re.I)
SSRF_PATH_PATTERN = re.compile(r"/(?:webhook|proxy|fetch|curl)(?:/|$)", re.I)

SSRF_PROBES = [
    "http://169.254.169.254",
    "http://169.254.169.254/latest/meta-data/"
]
SSRF_SIGNATURES = re.compile(
    r"Cloud Metadata Service|AccessKeyId|SecretAccessKey|security_credentials|SSRF exploitation verified|SSRF_METADATA",
    re.I
)

UPLOAD_PATH_PATTERN = re.compile(r"/(?:uploads?|attachments?|avatars?|imports?)(?:/|$)", re.I)
UPLOAD_SIGNATURES = re.compile(
    r"\.php|ARBITRARY_FILE_UPLOAD|WebShell uploaded|File uploaded successfully",
    re.I
)


class SystemAuditor:
    def __init__(self, bb, governance, options=None, budget=None):
        self.bb = bb
        self.gov = governance
        self.options = options
        self.budget = budget

    async def audit(self, client: httpx.AsyncClient):
        await self.audit_path_traversal(client)
        await self.audit_command_injection(client)
        await self.audit_ssrf(client)
        await self.audit_file_upload(client)

    async def audit_path_traversal(self, client: httpx.AsyncClient):
        candidates = []
        for ep in self.bb.asset.endpoints:
            if ep.method != "GET":
                continue
            query = parse_qs(urlsplit(ep.url).query, keep_blank_values=True)
            names = list(query) + [p.split(":")[-1] for p in ep.parameters if ":" not in p or p.startswith("query:")]
            matched_names = [n for n in dict.fromkeys(names) if LFI_PARAM_PATTERN.search(n) or LFI_PATH_PATTERN.search(ep.path)]
            if not matched_names and getattr(self.options, "mode", "safe") == "deep":
                matched_names = [n for n in dict.fromkeys(names) if not SKIP.search(n)]
            for name in matched_names:
                candidates.append((ep.url, ep.path, name))

        tested = 0
        found = 0
        errors = []
        seen = set()

        for url, path, param in candidates:
            if (path, param) in seen:
                continue
            seen.add((path, param))
            if not self.gov.is_in_scope(url) or not self.gov.is_safe_endpoint(path):
                continue

            try:
                base_url = str(httpx.URL(url).copy_merge_params({param: "sample_doc"}))
                base_resp = await client.get(base_url, timeout=5.0)
                tested += 1
                for probe in LFI_PROBES:
                    probe_url = str(httpx.URL(url).copy_merge_params({param: probe}))
                    resp = await client.get(probe_url, timeout=5.0)
                    sig_match = LFI_SIGNATURES.search(resp.text)
                    if resp.status_code == 200 and sig_match and not LFI_SIGNATURES.search(base_resp.text):
                        found += 1
                        key = hashlib.sha256((path + ":" + param).encode()).hexdigest()[:12]
                        matched_snippet = sig_match.group(0)
                        self.bb.add_finding(VulnerabilityFinding(
                            id=f"VULN-LFI-{key}",
                            vuln_type=VulnerabilityType.PATH_TRAVERSAL,
                            title="경로 순회 및 시스템 파일 접근 (Path Traversal / LFI)",
                            severity=Severity.HIGH,
                            endpoint=path,
                            request_url=probe_url,
                            description="사용자 입력 매개변수에 디렉터리 순회(../) 문자를 삽입했을 때 서버 내부 시스템 파일(passwd, win.ini 등)의 내용이 노출되었습니다.",
                            evidence=f"parameter={param}; payload={probe}; matched_signature={matched_snippet}; status=200",
                            cwe_id="CWE-22",
                            cvss_score=8.6,
                            yielded_postconditions={
                                "leaked_artifact": {
                                    "type": LeakedArtifactType.SECRET_KEY.value,
                                    "key": "system_file",
                                    "value": "accessible"
                                }
                            },
                            remediation="경로 순회 문자열(../, ..\\) 입력을 철저히 필터링하고 파일명을 서버 측 화이트리스트 또는 고유 식별자(ID)와 매핑하여 조회하세요."
                        ))
                        break
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {str(exc)[:60]}")

        status = "FINDING" if found else "ERROR" if errors else "PASS" if tested else "PASS"
        reason = f"경로 순회 매개변수 {tested}개 점검, 발견 {found}건." if tested else "점검 대상 파일 파라미터가 없거나 안전하게 처리되었습니다."
        record(self.bb, "R16", "경로 순회(Path Traversal / LFI) 검증", status, reason, tested, found, len(errors))

    async def audit_command_injection(self, client: httpx.AsyncClient):
        candidates = []
        for ep in self.bb.asset.endpoints:
            if ep.method != "GET":
                continue
            query = parse_qs(urlsplit(ep.url).query, keep_blank_values=True)
            names = list(query) + [p.split(":")[-1] for p in ep.parameters if ":" not in p or p.startswith("query:")]
            matched_names = [n for n in dict.fromkeys(names) if CMD_PARAM_PATTERN.search(n) or CMD_PATH_PATTERN.search(ep.path)]
            if not matched_names and getattr(self.options, "mode", "safe") == "deep":
                matched_names = [n for n in dict.fromkeys(names) if not SKIP.search(n)]
            for name in matched_names:
                candidates.append((ep.url, ep.path, name))

        tested = 0
        found = 0
        errors = []
        seen = set()

        for url, path, param in candidates:
            if (path, param) in seen:
                continue
            seen.add((path, param))
            if not self.gov.is_in_scope(url) or not self.gov.is_safe_endpoint(path):
                continue

            try:
                base_url = str(httpx.URL(url).copy_merge_params({param: "127.0.0.1"}))
                base_resp = await client.get(base_url, timeout=5.0)
                tested += 1
                for probe in CMD_PROBES:
                    full_payload = "127.0.0.1" + probe
                    probe_url = str(httpx.URL(url).copy_merge_params({param: full_payload}))
                    resp = await client.get(probe_url, timeout=5.0)
                    sig_match = CMD_SIGNATURES.search(resp.text)
                    if resp.status_code == 200 and sig_match and not CMD_SIGNATURES.search(base_resp.text):
                        found += 1
                        key = hashlib.sha256((path + ":" + param).encode()).hexdigest()[:12]
                        matched_snippet = sig_match.group(0)
                        self.bb.add_finding(VulnerabilityFinding(
                            id=f"VULN-CMDI-{key}",
                            vuln_type=VulnerabilityType.COMMAND_INJECTION,
                            title="OS 시스템 명령어 삽입 (Command Injection / RCE)",
                            severity=Severity.CRITICAL,
                            endpoint=path,
                            request_url=probe_url,
                            description="사용자 입력 매개변수에 쉘 메타문자(; | &)를 결합했을 때 서버 측 운영체제 시스템 명령어(whoami 등)가 실행되었습니다.",
                            evidence=f"parameter={param}; payload={full_payload}; matched_signature={matched_snippet}; status=200",
                            cwe_id="CWE-78",
                            cvss_score=9.8,
                            yielded_postconditions={
                                "privilege": PrivilegeLevel.SYSTEM.value
                            },
                            remediation="시스템 쉘(child_process.exec, os.system 등) 호출을 완전히 제거하고 내장 언어 라이브러리 API 또는 파라미터 분리 실행(execFile)을 사용하세요."
                        ))
                        break
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {str(exc)[:60]}")

        status = "FINDING" if found else "ERROR" if errors else "PASS" if tested else "PASS"
        reason = f"명령어 삽입 매개변수 {tested}개 점검, 발견 {found}건." if tested else "점검 대상 시스템 파라미터가 없거나 안전하게 처리되었습니다."
        record(self.bb, "R17", "OS 명령어 삽입(Command Injection) 검증", status, reason, tested, found, len(errors))

    async def audit_ssrf(self, client: httpx.AsyncClient):
        tested = 0
        found = 0
        errors = []
        seen = set()

        # 1. GET endpoints
        for ep in self.bb.asset.endpoints:
            if ep.method != "GET":
                continue
            query = parse_qs(urlsplit(ep.url).query, keep_blank_values=True)
            names = list(query) + [p.split(":")[-1] for p in ep.parameters if ":" not in p or p.startswith("query:")]
            matched_names = [n for n in dict.fromkeys(names) if SSRF_PARAM_PATTERN.search(n) or SSRF_PATH_PATTERN.search(ep.path)]
            for param in matched_names:
                if (ep.path, param) in seen:
                    continue
                seen.add((ep.path, param))
                if not self.gov.is_in_scope(ep.url) or not self.gov.is_safe_endpoint(ep.path):
                    continue

                try:
                    tested += 1
                    for probe in SSRF_PROBES:
                        probe_url = str(httpx.URL(ep.url).copy_merge_params({param: probe}))
                        resp = await client.get(probe_url, timeout=5.0)
                        sig_match = SSRF_SIGNATURES.search(resp.text)
                        if resp.status_code == 200 and sig_match:
                            found += 1
                            key = hashlib.sha256((ep.path + ":" + param).encode()).hexdigest()[:12]
                            matched_snippet = sig_match.group(0)
                            self.bb.add_finding(VulnerabilityFinding(
                                id=f"VULN-SSRF-{key}",
                                vuln_type=VulnerabilityType.SSRF,
                                title="서버 측 요청 위조 (Server-Side Request Forgery - SSRF)",
                                severity=Severity.HIGH,
                                endpoint=ep.path,
                                request_url=probe_url,
                                description="서버가 사용자 제공 URL을 검증 없이 직접 호출하여 내부 클라우드 메타데이터(169.254.169.254) 또는 내부망 정보가 응답에 노출되었습니다.",
                                evidence=f"parameter={param}; payload={probe}; matched_signature={matched_snippet}; status=200",
                                cwe_id="CWE-918",
                                cvss_score=8.6,
                                yielded_postconditions={
                                    "leaked_artifact": {
                                        "type": LeakedArtifactType.API_KEY.value,
                                        "key": "cloud_metadata",
                                        "value": "internal_credentials"
                                    }
                                },
                                remediation="사설망 IP(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.169.254)에 대한 아웃바운드 접근을 방화벽에서 차단하고 허용 도메인 화이트리스트를 적용하세요."
                            ))
                            break
                except Exception as exc:
                    errors.append(f"{type(exc).__name__}: {str(exc)[:60]}")

        # 2. POST endpoints (e.g. /api/webhook/test)
        for ep in self.bb.asset.endpoints:
            if ep.method == "POST" and SSRF_PATH_PATTERN.search(ep.path):
                if ep.path in seen:
                    continue
                seen.add(ep.path)
                if not self.gov.is_in_scope(ep.url) or not self.gov.is_safe_endpoint(ep.path):
                    continue

                try:
                    if self.budget:
                        self.budget.allow_post(ep.url)
                    tested += 1
                    for probe in SSRF_PROBES:
                        resp = await client.post(ep.url, json={"url": probe}, timeout=5.0)
                        sig_match = SSRF_SIGNATURES.search(resp.text)
                        if resp.status_code == 200 and sig_match:
                            found += 1
                            key = hashlib.sha256((ep.path + ":post_ssrf").encode()).hexdigest()[:12]
                            matched_snippet = sig_match.group(0)
                            self.bb.add_finding(VulnerabilityFinding(
                                id=f"VULN-SSRF-POST-{key}",
                                vuln_type=VulnerabilityType.SSRF,
                                title="서버 측 요청 위조 (Server-Side Request Forgery - SSRF POST)",
                                severity=Severity.HIGH,
                                endpoint=ep.path,
                                request_url=ep.url,
                                description="웹훅 및 외부 연동 POST API에서 클라우드 메타데이터(169.254.169.254) 요청을 전송받아 내부망 자격증명이 반환되었습니다.",
                                evidence=f"method=POST; payload={probe}; matched_signature={matched_snippet}; status=200",
                                cwe_id="CWE-918",
                                cvss_score=8.6,
                                yielded_postconditions={
                                    "leaked_artifact": {
                                        "type": LeakedArtifactType.API_KEY.value,
                                        "key": "cloud_metadata",
                                        "value": "internal_credentials"
                                    }
                                },
                                remediation="요청된 URL의 대상 IP를 서버 측에서 DNS 조회 후 사설 IP 대역인지 검증하고 외부 화이트리스트 외 연결을 엄격히 차단하세요."
                            ))
                            break
                except Exception as exc:
                    errors.append(f"{type(exc).__name__}: {str(exc)[:60]}")

        status = "FINDING" if found else "ERROR" if errors else "PASS" if tested else "PASS"
        reason = f"SSRF 대상 {tested}개 점검, 발견 {found}건." if tested else "점검 대상 웹훅/URL 파라미터가 없거나 안전하게 처리되었습니다."
        record(self.bb, "R18", "서버 측 요청 위조(SSRF) 검증", status, reason, tested, found, len(errors))

    async def audit_file_upload(self, client: httpx.AsyncClient):
        tested = 0
        found = 0
        errors = []
        upload_candidates = []

        for ep in self.bb.asset.endpoints:
            if ep.method == "POST" and UPLOAD_PATH_PATTERN.search(ep.path):
                upload_candidates.append(ep)

        # Fallback probe for standard upload path if in scope
        std_upload_url = self.gov.origin_url + "/api/upload"
        if not upload_candidates and self.gov.is_in_scope(std_upload_url) and self.gov.is_safe_endpoint("/api/upload"):
            try:
                probe_head = await client.get(std_upload_url, timeout=3.0)
                if probe_head.status_code in (200, 400, 405):
                    from core.models.asset import HttpEndpoint
                    ep = HttpEndpoint(url=std_upload_url, path="/api/upload", method="POST", source="standard_probe")
                    upload_candidates.append(ep)
            except Exception:
                pass

        for ep in upload_candidates:
            if not self.gov.is_in_scope(ep.url) or not self.gov.is_safe_endpoint(ep.path):
                continue
            try:
                if self.budget:
                    self.budget.allow_post(ep.url)
                tested += 1

                # Safe non-destructive probe: harmless text file disguised as .php
                multipart_files = {
                    "file": ("shell.php", b"<!-- WVA Safe Security Audit Probe -->", "application/x-php")
                }
                headers = {"Content-Disposition": 'attachment; filename="shell.php"'}
                resp = await client.post(ep.url, files=multipart_files, headers=headers, timeout=5.0)

                sig_match = UPLOAD_SIGNATURES.search(resp.text)
                if resp.status_code in (200, 201) and sig_match:
                    found += 1
                    key = hashlib.sha256(ep.path.encode()).hexdigest()[:12]
                    matched_snippet = sig_match.group(0)
                    self.bb.add_finding(VulnerabilityFinding(
                        id=f"VULN-UPLOAD-{key}",
                        vuln_type=VulnerabilityType.ARBITRARY_FILE_UPLOAD,
                        title="위험 확장자 파일 무제한 업로드 (Arbitrary File Upload)",
                        severity=Severity.CRITICAL,
                        endpoint=ep.path,
                        request_url=ep.url,
                        description="실행 가능한 위험 확장자(.php, .jsp 등) 파일 업로드가 허용되며 업로드된 파일의 웹 접근 경로가 직접 노출되었습니다.",
                        evidence=f"endpoint={ep.path}; uploaded_file=shell.php; matched_signature={matched_snippet}; status={resp.status_code}",
                        cwe_id="CWE-434",
                        cvss_score=9.8,
                        yielded_postconditions={
                            "privilege": PrivilegeLevel.SYSTEM.value
                        },
                        remediation="업로드 파일 확장자를 안전한 화이트리스트(jpg, png, pdf 등)로 제한하고, 업로드 디렉터리의 실행 권한(Execute Permission)을 차단하며 파일명을 랜덤 UUID로 난수화하세요."
                    ))
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {str(exc)[:60]}")

        status = "FINDING" if found else "ERROR" if errors else "PASS" if tested else "PASS"
        reason = f"파일 업로드 엔드포인트 {tested}개 점검, 발견 {found}건." if tested else "점검 대상 파일 업로드 엔드포인트가 발견되지 않았습니다."
        record(self.bb, "R19", "임의 파일 업로드(Arbitrary File Upload) 검증", status, reason, tested, found, len(errors))
