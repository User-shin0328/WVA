# WVA 테스트 상세 설명 · 예상 결과 · 결과보고서

갱신 기준: 2026-11-03, Windows 10 x64. 이 문서는 테스트 순서와 판정 기준을 설명하며, 마지막의 자동 생성 결과보고서에 실제 수행 결과를 합칩니다.

## 1. 테스트 목표와 구성

직접 입력한 대상의 진단, 증거 조회, 연계 경로, 보고서 저장, 중단·오류 처리, Windows 단독 실행을 검증합니다. 외부 사이트를 스캔하지 않고 본 폴더의 로컬 대상만 사용합니다.

| 구성 | 위치 / 주소 | 역할 |
| --- | --- | --- |
| 사용자 실행파일 | 프로젝트 루트 `WVA.exe` | Python 설치 없이 대시보드와 데모 실행 |
| 대시보드 | 기본 `http://127.0.0.1:9030` | 직접 대상 입력 및 결과 확인; 포트 사용 중이면 9031~9039 탐색 |
| 취약 테스트 대상 | `tests/lab/target.py --mode vulnerable`, 8990 | CSP 누락·디버그 노출·CORS·객체 접근·관리자 응답을 의도적으로 제공 |
| 방어 테스트 대상 | `tests/lab/target.py --mode hardened`, 8991 | CSP 적용, 디버그 미노출, 사용자 인증 요구 및 관리자 접근 거부 |
| 내장 데모 | 운영체제가 고른 임시 로컬 포트 | 진단 동안만 실행하며 완료·중단·오류 시 종료 |
| Python 테스트 환경 | `.venv/` | 소스 테스트 및 실행파일 재빌드용 |
| 원본 검증 산출물 | `tests/artifacts/` | JUnit XML, 브라우저 스크린샷, JSON 검증 결과 |

HTTP 코드는 공격 표면 탐색 시 관찰한 응답입니다. `미측정`은 문서·링크에서만 발견한 경로이며 접근 성공을 뜻하지 않습니다. API 문서의 POST·DELETE 경로도 목록으로 수집할 수 있지만 실행하지 않습니다. 결과 0건은 전체 웹 보안의 안전을 보증하지 않습니다.

## 2. 준비 순서

### 2-1. 프로젝트 폴더에서 PowerShell 열기

이 문서의 명령은 프로젝트 루트에서 실행합니다. 폴더 이름에 한글과 공백이 있어도 동작하도록 구성했습니다. `.venv`는 이 PC에서 이미 구축되어 있습니다. 폴더를 다른 PC로 옮기면 가상환경을 재사용하지 말고 다시 생성하세요.

### 2-2. 테스트 환경 구축

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\Setup-TestEnvironment.ps1
```

예상 결과: `.venv/Scripts/python.exe`가 준비되고 `requirements-lock.txt`의 고정 버전이 설치됩니다. 초기 설치에는 인터넷이 필요합니다. Windows 실행파일과 로컬 데모 자체는 외부 CDN·인터넷 자산 다운로드가 필요하지 않습니다.

Python이 없으면 Python 3.11 이상을 설치하거나 다음처럼 실제 Python 경로를 지정합니다. 이 PC에서는 Codex에 포함된 Python 3.12.14로 구축했습니다.

```powershell
$env:WVA_PYTHON = 'C:\설치위치\python.exe'
powershell -ExecutionPolicy Bypass -File .\tests\Setup-TestEnvironment.ps1
```

판정: 설치 명령이 0으로 종료되어야 PASS입니다. 설치·네트워크 오류가 있으면 이후 결과를 PASS로 기록하지 않습니다.

## 3. 자동 기능 테스트

```powershell
.\.venv\Scripts\python.exe -m tests.run_tests
```

예상 결과: 총 123개 테스트가 통과합니다. 아래는 파라미터 조합을 포함한 분류입니다.

| 검증 | 개수 | 상세 예상 결과 |
| --- | ---: | --- |
| 동일 출처 허용 | 2 | 같은 HTTPS 출처의 기본 포트 표기 여부는 동일하게 허용 |
| 출처 이탈 차단 | 7 | 하위 도메인·다른 호스트·다른 포트·HTTP 전환·파일 주소·계정 포함 주소는 거부 |
| 위험 경로 차단 | 5 | 삭제·초기화·구매 경로와 URL 인코딩된 위험 경로를 차단 |
| 잘못된 대상 입력 | 8 | 스킴 누락·비 HTTP·URL 내 계정·잘못된 포트·화면 위치·제어 문자·공백을 거부 |
| 초기 상태·보고서 제한 | 1 | 초기 결과 0, 빈 그래프, 완료 전 보고서 409 |
| 로컬 요청 경계 | 1 | 외부 Origin 403, 폼 제출 415, 외부 Host 400 |
| 쿠키 속성 오탐 방지 | 1 | Secure·HttpOnly 쿠키를 누락으로 보고하지 않음 |
| CORS 오탐 방지 | 3 | 브라우저에서 무효인 와일드카드+인증 조합 및 인증 비허용은 제외, 임의 출처+인증 허용만 탐지 |
| 취약 데모 통합 검증 | 1 | 8개 엔드포인트·5개 발견 항목·1개 3단계 경로, 보고서 일치·데모 종료 |
| 직접 대상·방어 프로필 | 1 | 4개 엔드포인트, 발견 항목 0, 연계 경로 0 |
| 연결 실패 | 1 | 오류 상태, 원인 안내, 완료 보고서 생성·다운로드 금지 |
| 중복 시작·중단 | 1 | 두 번째 시작 409, 중단 후 작업 종료, 이전 오류와 결과 초기화 |
| 이벤트 다중 구독·재전송 | 1 | 두 구독자에게 같은 이벤트 제공, Last-Event-ID 이후 이벤트 재전송 |
| 리다이렉트 스코프 | 1 | 다른 출처로 302 응답을 보내도 외부 서버에 요청하지 않음 |
| 공격 표면 확장 정보 | 1 | 실제 HTTP·유형·시간·크기·시각과 API 매개변수·출처 병합 검증 |
| 진단 로그 저장·분리 | 1 | UTF-8 JSONL에 시작·종료 기록, 재진단 시 파일 분리, 키 로그 가림 |
| 선택 내보내기 형식 | 3 | JSON·Markdown·CSV가 선택한 발견 항목과 상세 조치만 포함 |
| 저장 선택 검증 | 4 | 빈 선택·알 수 없는 항목·중복 항목·미지원 형식을 422로 거부 |
| 현재 진단·완료 검증 | 1 | 완료 전·이전 진단 ID 저장은 409, 전체 디스크 로그 내보내기 |
| CSV 데이터 보존 | 1 | 쉼표·줄바꿈 보존, 수식으로 해석될 수 있는 셀 값 보호 |
| API 문서 읽기 전용 수집 | 1 | 문서의 새 경로를 수집하되 선언된 작업 및 스코프 밖 경로를 실행하지 않음 |
| 보안 헤더 조치 구분 | 2 | CSP 조치에 HSTS 단계가 섞이지 않고 HSTS 조치에 CSP 보고 모드가 섞이지 않음 |
| 경로·쿼리 보존 | 4 | 하위 경로·중복 및 빈 매개변수·값 끝의 슬래시를 보존 |
| 모호한 시작 경로 거부 | 3 | 입력의 상위 경로 표현 때문에 선택 범위가 서버 루트로 확대되지 않음 |
| 경로 범위 이탈 차단 | 8 | 유사 접두사·상위 경로·인코딩 우회·다른 출처의 실제 요청을 거부 |
| 범위 선택과 쿼리 전달 | 1 | 경로/서버 선택 검증, 입력 쿼리를 다른 경로에 복제하지 않음 |
| URL별 엔드포인트 식별 | 1 | 다른 쿼리는 분리하되 루트 슬래시 유무는 중복 집계하지 않음 |
| 마운트 경로·직접 쿼리·서버 범위·API 통합 | 4 | 실제 로컬 요청 경계, 상대 링크, 쿼리 보존, 경로 연계와 완료 상태 확인 |
| 유형별 위험 설명과 판정 범위 | 12 | 7개 설명 유형, 미등록 유형 보류, 공유 데이터 분리, CSP/HSTS 구분, 원래 증거·점수 보존 |
| 공격 설명 보고서 일치 | 3 | JSON·Markdown·25열 CSV에 공격 가능성·성립 조건·확인 범위 유지 |
| 상위 저장소 기능 | 4 | 참고 점수·AI 프롬프트·가림 처리된 JS 패턴 탐지·권한 확인 |
| 2.5 실행 규칙·경계·세션 | 24 | 실제 SQLite SQL·조건 음성·불안정/WAF/오류·브라우저 XSS·안전 인코딩/CSP·요청 경계/예산·CSRF·계정/역할·저장형 정리/취소·시간 SQL·등급 보류·검증 비밀 가림·세션 재진단 |
| 통합 호환성 | 11 | 미완료 등급 제한 4건, 새 설명 유형 2건, 기준 보고서 필터·실제 반복 진단 각 1건, TLS 임박/정상/취소 3건 |

실제 실패 시: `tests/artifacts/pytest-output.txt`의 실패 항목과 `pytest.xml`을 확인합니다. 명령을 다시 실행하면 이 문서 마지막의 실제 결과가 갱신됩니다.

## 4. 직접 입력한 대상 진단 테스트

### 4-1. 취약 대상을 별도 PowerShell에서 실행

```powershell
.\.venv\Scripts\python.exe -m tests.lab.target --mode vulnerable --port 8990
```

예상 결과: `http://127.0.0.1:8990`에서 로컬 테스트 대상이 응답합니다. 이 창은 테스트가 끝날 때까지 열어둡니다.

### 4-2. 대시보드 실행 후 대상 주소 입력

프로젝트 루트의 `WVA.exe`를 더블클릭합니다. 브라우저가 자동으로 열립니다. 대상 입력란에 `http://127.0.0.1:8990`을 입력하고 **진단 시작**을 누릅니다. 이전 버전의 8787 포트는 이 PC의 Windows 예약 범위에 포함되어 새 기본 포트로 사용하지 않습니다.

예상 결과:

- 시작 시 스피너·진행선, 완료 시 체크 모션이 나옵니다. 단계 표시는 실제 단계 로그에서 얻으며 진단 중에만 보입니다. 완료·실패·중단 뒤에는 다섯 단계 문구를 숨깁니다. 시작 요청이 수락되기 전에는 중단 버튼이 비활성화됩니다.
- 발견 항목 5건, 연계 경로 1건, 엔드포인트 8개입니다. 수치 옆의 추가 설명은 표시하지 않습니다.
- 위험도 분포: 심각 1 / 높음 1 / 중간 1 / 낮음 2 / 정보 0.
- 위험도와 CVSS 분포는 원형 차트로 표시합니다. 범례의 건수·비율과 실제 항목 수가 일치해야 하며, 0건인 분류는 원형 조각을 만들지 않습니다.
- 완료 후 CVSS 차트는 심각 1 / 높음 1 / 중간 2 / 낮음 1입니다. 위험도 분류와 점수 구간은 별도로 집계합니다.
- 일반 export 상태 응답을 BOLA 취약점으로 중복 보고하지 않습니다.

| 발견 항목 | 위험도 | 경로 | 예상 CVSS | 증거의 의미 |
| --- | --- | --- | ---: | --- |
| 콘텐츠 보안 정책 누락 | 낮음 | `/` | 3.1 | 응답에 CSP가 없음 |
| 디버그 정보 노출 | 낮음 | `/debug/version` | 4.3 | 테스트 사용자 식별자 노출 |
| 외부 출처 접근 허용 | 중간 | `/api/v1/user/export` | 6.5 | 테스트 Origin 및 인증 허용 헤더를 관찰 |
| 객체 접근 통제 누락 | 높음 | `/api/v1/user/profile` | 7.5 | 미인증 요청으로 일치하는 사용자 데이터·키 관찰 |
| 유출 키로 관리자 응답 접근 | 심각 | `/api/v1/admin/config` | 9.8 | 수집한 테스트 키로 ADMIN 응답 관찰 |

점수는 기존 규칙에 정해진 참고 점수이며 환경별 CVSS 재평가를 대신하지 않습니다. 연계는 디버그 식별자 → 프로필의 키 → 관리자 응답의 3단계로 구성됩니다. 관리자 설정 응답 접근을 관찰한 것이며 전체 시스템 장악을 실행한 결과가 아닙니다.

### 4-3. 증거·검색·경로·보고서 확인

1. **심각** 항목을 누릅니다. 작업 영역 너비의 75%, 화면 높이의 75%인 상세 창에 위험도·CVSS·CWE·증거·조치 순서·수정 후 확인이 표시되어야 합니다. 조치는 현황 확인 → 유출 키·접근 차단 → 관리자 권한 검사 → 새 인증 정보 발급 → 상위 노출 경로 정리 → 재검증의 6단계이며, 각 단계에 완료 기준이 있어야 합니다. `Escape` 또는 닫기로 종료합니다.
2. 검색란에 없는 단어를 입력합니다. 검색 결과 없음과 복구 안내가 표시되어야 합니다.
3. 검색을 지우고 위험도를 **높음**으로 고릅니다. 정확히 1개 행이어야 합니다.
4. **경로** 메뉴에서 대상 입력 → 3단계 경로 → 연관 발견 항목 3건 순서인지 확인합니다. 각 단계를 눌러도 경로 화면을 유지한 채 같은 상세 창이 떠야 합니다.
5. **표면** 메뉴는 엔드포인트 8개(응답 측정 7 / 문서·링크 발견 1), **로그** 메뉴는 실제 파일 위치와 수행 기록을 보여야 합니다.
6. **저장** 화면에서 정보를 선택하고 JSON·Markdown·CSV를 각각 저장합니다. 선택하지 않은 항목이 제외되고, 대상·진단 ID·시각은 모든 파일에 포함되어야 합니다.

조치 순서 확인: JSON의 `remediation_details.steps`에는 `order`, `title`, `action`, `expected_result`가 포함됩니다. Markdown과 CSV에도 동일한 번호·내용·완료 기준이 표시되어야 합니다. 자동 생성되는 전체 보고서도 같은 순서를 포함합니다. CSP 항목에는 HSTS 설정 절차가 나타나지 않아야 합니다.

7. 새로고침합니다. 실행 중인 서버의 결과가 그대로 조회되어야 합니다. 앱을 종료한 뒤 재실행하면 화면은 새 세션이며, 저장된 보고서는 디스크에 남습니다.

자동 저장 위치: `WVA.exe` 옆 `reports/날짜_시간_진단ID.md` 및 `.json`. 폴더에 쓸 수 없으면 `%LOCALAPPDATA%/WVA/reports/`를 사용합니다. 보고서에는 진단 대상의 증거가 포함될 수 있으므로 본인 작업 폴더에서 관리합니다.

진단 로그는 `logs/scans/날짜_시간_진단ID.jsonl`에 즉시 추가 기록되며 앱 종료 후에도 남습니다. 앱 실행 오류는 `logs/WVA.log`입니다. 저장 화면에서 내려받는 파일은 브라우저의 다운로드 설정 위치에 저장됩니다. JSON은 구조화 데이터, Markdown은 상세 보고서, CSV는 Excel 등의 표 도구용이며 UTF-8 BOM을 포함합니다.

표면의 프로필 경로는 필수 user_id를 보내지 않은 탐색 요청에 `422`로 응답하고, 문서에서 `query:user_id`를 수집합니다. 발견 항목의 증거는 매개변수와 수집 키를 사용한 후속 요청 결과이므로 이 탐색 HTTP 코드와 다를 수 있습니다.

## 5. 방어 설정 적용 대상과 비교

다른 PowerShell에서 실행합니다.

```powershell
.\.venv\Scripts\python.exe -m tests.lab.target --mode hardened --port 8991
```

대시보드에 `http://127.0.0.1:8991`을 입력하고 진단을 시작합니다.

예상 결과: 엔드포인트 4개, 발견 항목 0건, 연계 경로 0건. 이전 결과와 오류·증거가 새 진단에 섞이면 FAIL입니다. 이 테스트는 본 도구의 특정 규칙에 대한 음성 대조군입니다.

## 6. 오류·중단·동시 실행 테스트

1. 존재하지 않는 로컬 포트를 진단합니다. **진단 실패**와 주소·포트·TLS 확인 안내가 나와야 합니다. 보고서 버튼은 비활성화됩니다.
2. 잘못된 주소를 입력합니다. 시작 전 브라우저 검증 또는 API 422 안내가 나와야 합니다.
3. 진단 중 **진단 중단**을 누릅니다. 부분 결과 상태가 되어야 하고, 완료 보고서를 내려받을 수 없어야 합니다. 빠른 로컬 대상은 즉시 끝날 수 있으므로 자동 중단 테스트는 30초 대기 엔진을 주입하여 재현합니다.
4. 실행파일을 다시 더블클릭합니다. 이미 실행 중인 WVA 서버를 재사용해야 합니다. 별도의 중복 진단을 시작하지 않습니다.
5. 브라우저 탭을 두 개 열어 확인합니다. 두 화면은 동일 서버 상태를 조회해야 합니다. 이벤트 API는 각 구독자에게 동일 로그를 제공하며 화면 갱신은 약 0.7초 간격 상태 조회를 사용합니다.

## 7. 실행파일 독립 실행 검증

실행파일을 다시 만들 때만 다음 명령을 실행합니다.

```powershell
powershell -ExecutionPolicy Bypass -File .\packaging\build.ps1
.\.venv\Scripts\python.exe -m tests.smoke_executable
```

예상 결과: `tests/artifacts/독립 실행 한글 경로/`에 exe만 복사하여 원본 소스 없이 실행합니다. 대시보드·로컬 자산·내장 데모·보고서·상세 조치·확장 표면 정보·진단 로그·선택 JSON/CSV 내보내기·이벤트·중복 실행·종료·포트 해제 및 2.5 검사 상태·내보내기 기능의 27개 검증이 통과해야 합니다. `executable-smoke.json`에 각 검증과 exe SHA-256을 기록합니다.

첫 빌드에서 나타난 `[Errno 42] Illegal byte sequence`는 사용 중인 Python 런타임의 `ssl.py`가 읽는 인증서 정책 파일을 포함하지 않아 발생했습니다. 빌드 스크립트는 이 파일이 존재하면 함께 포함합니다. TLS 인증서 검증을 끄는 방식으로 우회하지 않습니다. 자동 테스트의 `--no-browser`에서는 오류를 로그와 실패 종료 코드로 반환하므로 오류 대화상자가 테스트를 가로막지 않습니다.

## 8. 브라우저·가독성 검증

실행 중인 대시보드와 8990 취약 대상이 필요합니다. 이 PC에는 Node와 Playwright, Edge가 준비되어 있습니다.

```powershell
node .\tests\ui_check.cjs
```

다른 환경에서는 Playwright가 설치된 `node_modules` 경로를 `WVA_NODE_MODULES`, Edge/Chrome 경로를 `WVA_BROWSER`로 지정합니다. 대시보드 주소는 `WVA_TEST_URL`, 테스트 대상은 `WVA_LAB_URL`로 바꿀 수 있습니다.

예상 결과: 기본 38개, `$env:WVA_ACTIVE_LABS='1'`로 설치된 DVWA·Juice Shop 검사까지 켜면 총 40개 검증이 통과합니다. 기존 화면·차트·저장·반응형 검증 22건과 URL 범위 검증 7건에 상세 가독성·CSP 공격 조건·모바일 상세 창 검증 3건을 추가했습니다. 추가 4건은 권한 확인 미선택 차단, 완료 참고 등급, 기존 위험 설명과 AI 프롬프트 복사의 공존, 동일 범위 재진단 비교입니다. 상세 창은 문제 요약 → 확인한 내용 → 가능한 공격 → 판정 범위 → 조치 순서 → 수정 후 확인 순서이며, 원문 증거는 접고 조치는 첫 단계만 펼칩니다. 모든 조치 펼치기와 증거 원문 열기도 확인합니다. URL 범위 검증은 임시 로컬 서버를 직접 시작하고 종료합니다. 넓은 표는 자체 가로 스크롤을 사용합니다. 스크린샷은 `tests/artifacts/browser/`에 저장됩니다.

디자인은 Impeccable과 테이스트스킬의 앱 화면 기준을 적용했습니다. 어두운 표면, 흰 글씨, 청록색 1px 선, 실제 데이터 수치, 선택한 항목의 증거를 중심으로 구성했습니다. 자동 디자인 검사 결과는 스타일 관련 보조 판단이며 실제 기능 통과 결과와 구분합니다.

## 9. 종료·정리

- 대시보드의 **앱 종료**를 누릅니다. 진단 작업과 내장 데모가 정리되고 서비스 포트가 닫힙니다.
- 수동으로 실행한 8990/8991 실습 대상 창에서는 `Ctrl+C`를 누릅니다.
- 보고서는 앱 종료 후에도 보존합니다. 테스트를 다시 실행하면 `tests/artifacts/`의 검증 자료가 갱신됩니다.
- 원본 코드, 기존 `reports/`, 설계 문서는 삭제하지 않습니다. 이전 배치 실행기 6개의 삭제 목록과 해시는 `docs/REMOVED_LAUNCHERS.md`를 확인하세요.

## 10. 실제 테스트 결과보고서

## 독립 취약 웹앱 추가 검증

DVWA low·impossible 및 OWASP Juice Shop을 별도 설치한 검증은 [벤치마크 실행 절차](benchmarks/README.md)와 [예상·실제 결과 및 한계](benchmarks/RESULTS.md)에 정리했습니다. 이미지 digest를 고정했으며 아래 명령으로 재시작·검증할 수 있습니다.

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\benchmarks\Start-Benchmark.ps1
.\.venv\Scripts\python.exe -X utf8 -m tests.benchmarks.run
.\.venv\Scripts\python.exe -m tests.run_tests --report-only
```

예상: 독립 확인 6건과 WVA 소스/실행파일 진단 12건이 PASS입니다. 알려진 양성 4개와 방어 대조 2개를 실제 규칙으로 구분해야 합니다. 상세 문서에 종료 방법과 오류 해결을 포함했습니다.

## 2.5 추가 기능과 실행파일 검증

[실행 규칙·프로필](../docs/ACTIVE_RULES.md)을 읽고 다음 순서로 확인합니다.

1. SQLi는 정상 기준 2회와 참·거짓 조건 쌍 2회가 일치해야 발견입니다. WAF·DB 오류·불안정 응답만으로 발견하지 않습니다. 실제 양성/음성은 `test_active_rules.py` 및 제3자 앱 기록을 확인합니다.
2. XSS는 브라우저 실행 표식으로 판정하며 반사·안전 인코딩·CSP 차단을 구분합니다. 브라우저가 없으면 미실행이어야 합니다.
3. 추가 진단 설정의 SQL·브라우저·매개변수·프로필을 확인하고, 검사별 수행 상태에서 미실행 사유를 확인합니다. 미완료인 검사를 A~D로 표시하지 않아야 합니다.
4. 계정/역할·저장형·시간 SQL 검증은 `.\.venv\Scripts\python.exe -X utf8 -m tests.benchmarks.extended`로 source/exe 모두 실행합니다. 예상은 10건 PASS이며 저장 표식 잔존과 인증정보 원문 노출이 없어야 합니다.
5. 소유한 로컬 실습 앱을 수동으로 실행하려면 `.\.venv\Scripts\python.exe -m tests.lab.advanced_target --port 18913`을 별도 터미널에서 시작하고 `benchmarks/profiles/advanced-loopback.json`을 불러옵니다. 서버 전체 범위를 선택합니다. 끝나면 Ctrl+C로 종료합니다.
6. 실행파일을 바꾼 경우 반드시 BUILD_INFO.json의 해시와 smoke·벤치마크·확장 결과의 해시가 모두 같아야 합니다. 버전이 같은 다른 바이너리의 결과를 재사용하지 않습니다.

브라우저 40건 실행 전에는 설치된 세 앱과 8990 취약 대상이 실제 응답해야 합니다. 아래 명령은 2.5의 실제 SQLi·DOM XSS 상세 창과 모바일/등급 보류까지 포함합니다.

```powershell
$env:WVA_ACTIVE_LABS = '1'
node .\tests\ui_check.cjs
.\.venv\Scripts\python.exe -m tests.run_tests --report-only
```

## 2.4 통합 기능 확인 순서

1. `WVA.exe`를 실행하고 진단 범위를 정한 뒤 권한 확인 체크를 해제합니다. **예상:** 진단 시작이 차단되고 권한 확인 안내가 나옵니다. 다시 체크하고 로컬 취약 대상 `http://127.0.0.1:8990`을 진단합니다.
2. 완료 후 발견 5건·경로 1개·엔드포인트 8개와 참고 점수 46/F를 확인합니다. **예상:** 참고 수치는 발견 건수에 따른 계산값이며 전체 사이트 보안 등급을 보증하지 않습니다. 연결 실패나 중단 결과에는 등급과 점수가 대시로 표시됩니다.
3. 발견 항목을 열어 문제 요약·관찰 사실·조건부 공격·판정 범위·순서별 조치를 읽고, **AI 수정 프롬프트**를 펼쳐 복사합니다. **예상:** 기존 내용이 유지되고 판정 한계를 포함한 프롬프트를 로컬에서 복사합니다. 외부 AI 호출은 발생하지 않습니다. 자동 브라우저 테스트는 운영체제 클립보드를 바꾸지 않도록 복사 함수를 대체해 전달 내용을 확인합니다.
4. 대상 URL과 범위를 바꾸지 않고 다시 진단합니다. **예상:** 같은 규칙 버전의 완료 보고서가 있으면 신규·유지·이번에 미발견 건수가 나옵니다. 기존 보고서만 있거나 URL·범위가 달라지면 비교하지 않습니다. 미발견은 조치 완료의 증명이 아닙니다.
5. JSON 보고서의 `scan_metadata`에서 `completed`, `scan_id`, `profile.scope_mode`, `profile.scope_path`, `profile.ruleset`을 확인합니다. **예상:** 완료 결과와 비교 조건이 보존됩니다. 발견 항목에는 기존 `risk_context`와 `ai_prompt`가 함께 들어 있습니다.
6. `python -m pytest tests/test_integration.py -q`는 11건을 검사합니다. **예상:** 동일 로컬 서버에서 실제 반복 진단은 같은 결과를 유지하고 범위를 바꾸면 비교 대상이 없어집니다. TLS의 14일/60일/취소 검사는 연결 객체를 모의하여 판정과 연결 정리를 확인합니다. 실제 외부 인증서 환경 검증으로 해석하지 않습니다.

실제 결과와 원본 파일 위치는 아래 자동 갱신 결과 및 [통합 보고서](../docs/INTEGRATION_REPORT.md)를 따릅니다. 실패 시 브라우저 `result.json`의 `actual`, 실행파일 `executable-smoke.json`의 `error`, `logs/WVA.log`를 확인합니다. UI 상태 변경과 비교 표시에는 요청 처리 시간이 있으므로 화면 표시가 완료된 뒤 판정합니다.

<!-- RESULTS:START -->
### 수행 환경과 검증 범위

- 보고서 갱신 시각: 2026-11-04T09:06:11+09:00
- 운영체제: Windows-10-10.0.19045-SP0
- Python: 3.12.14
- 기능 테스트: **123/123 PASS**
- 외부 운영 사이트 진단은 수행하지 않았습니다. 로컬 실습 환경에 대한 검증입니다.

### 기능 테스트 상세 결과

| 실제 테스트 | 결과 | 소요 |
| --- | --- | ---: |
| `test_sql_actual_sqlite_and_negative_conditions[sql-True-FINDING]` | PASS | 1.710초 |
| `test_sql_actual_sqlite_and_negative_conditions[safe-sql-False-PASS]` | PASS | 1.577초 |
| `test_sql_actual_sqlite_and_negative_conditions[unstable-False-SIGNAL]` | PASS | 1.351초 |
| `test_sql_actual_sqlite_and_negative_conditions[waf-False-ERROR]` | PASS | 1.137초 |
| `test_sql_actual_sqlite_and_negative_conditions[db-error-False-SIGNAL]` | PASS | 1.961초 |
| `test_browser_execution_encoding_csp_and_dom[reflected-True]` | PASS | 3.406초 |
| `test_browser_execution_encoding_csp_and_dom[safe-reflected-False]` | PASS | 4.798초 |
| `test_browser_execution_encoding_csp_and_dom[csp-reflected-False]` | PASS | 4.650초 |
| `test_browser_execution_encoding_csp_and_dom[spa/#/search?q=baseline-True]` | PASS | 3.680초 |
| `test_browser_enforces_external_path_post_and_websocket_boundaries` | PASS | 3.340초 |
| `test_response_and_request_caps_are_actual_boundaries` | PASS | 0.236초 |
| `test_csrf_get_refresh_preserves_unrelated_repeated_query` | PASS | 0.237초 |
| `test_real_login_csrf_and_private_object_role_policy` | PASS | 1.912초 |
| `test_stored_xss_separate_read_and_verified_cleanup[False]` | PASS | 2.609초 |
| `test_stored_xss_separate_read_and_verified_cleanup[True]` | PASS | 2.556초 |
| `test_timing_uses_real_sqlite_conditional_delay` | PASS | 2.366초 |
| `test_partial_check_does_not_receive_a_grade[R11-NOT_RUN]` | PASS | 0.012초 |
| `test_partial_check_does_not_receive_a_grade[R09-ERROR]` | PASS | 0.005초 |
| `test_extended_probes_reject_external_targets_without_post` | PASS | 1.078초 |
| `test_missing_browser_is_not_run_instead_of_a_pass` | PASS | 1.225초 |
| `test_cancel_stored_check_still_removes_owned_record` | PASS | 1.589초 |
| `test_primary_session_is_used_for_normal_scan` | PASS | 0.994초 |
| `test_validation_does_not_echo_profile_secrets` | PASS | 0.005초 |
| `test_session_rescan_uses_the_same_redacted_comparison_profile` | PASS | 2.283초 |
| `test_compute_score_and_grade` | PASS | 0.000초 |
| `test_build_ai_prompt` | PASS | 0.000초 |
| `test_audit_js_secrets_detection` | PASS | 0.001초 |
| `test_consent_validation_in_start_scan` | PASS | 0.004초 |
| `test_surface_measured_metadata_and_openapi` | PASS | 1.485초 |
| `test_persistent_utf8_scan_log_and_rotation` | PASS | 3.014초 |
| `test_selected_export_formats_and_detailed_remediation[json]` | PASS | 1.631초 |
| `test_selected_export_formats_and_detailed_remediation[md]` | PASS | 1.631초 |
| `test_selected_export_formats_and_detailed_remediation[csv]` | PASS | 2.025초 |
| `test_header_remediation_does_not_mix_unrelated_policies[CSP]` | PASS | 0.001초 |
| `test_header_remediation_does_not_mix_unrelated_policies[HSTS]` | PASS | 0.001초 |
| `test_export_selection_validation[sections0-json]` | PASS | 0.005초 |
| `test_export_selection_validation[sections1-json]` | PASS | 0.005초 |
| `test_export_selection_validation[sections2-md]` | PASS | 0.008초 |
| `test_export_selection_validation[sections3-xlsx]` | PASS | 0.005초 |
| `test_export_requires_completed_current_scan_and_full_disk_logs` | PASS | 1.683초 |
| `test_csv_preserves_rows_and_blocks_formulas` | PASS | 0.001초 |
| `test_openapi_discovery_never_executes_declared_operations` | PASS | 0.005초 |
| `test_unfinished_scan_has_no_grade_or_comparison[idle]` | PASS | 0.009초 |
| `test_unfinished_scan_has_no_grade_or_comparison[running]` | PASS | 0.008초 |
| `test_unfinished_scan_has_no_grade_or_comparison[stopped]` | PASS | 0.008초 |
| `test_unfinished_scan_has_no_grade_or_comparison[error]` | PASS | 0.009초 |
| `test_added_rules_preserve_specific_limits_and_ai_context[VULN-SECRET-LEAK-1-INFO_DISCLOSURE-\ubb38\uc790\uc5f4]` | PASS | 0.001초 |
| `test_added_rules_preserve_specific_limits_and_ai_context[VULN-TLS-EXPIRING-1-MISSING_SECURITY_HEADER-\uc778\uc99d\uc11c]` | PASS | 0.001초 |
| `test_baseline_excludes_incomplete_other_scope_and_current_copy` | PASS | 0.033초 |
| `test_actual_repeat_scan_compares_only_same_profile` | PASS | 10.933초 |
| `test_tls_expiry_uses_validated_async_connection_and_closes_writer[14-1]` | PASS | 0.040초 |
| `test_tls_expiry_uses_validated_async_connection_and_closes_writer[60-0]` | PASS | 0.034초 |
| `test_tls_cancel_propagates_instead_of_becoming_success` | PASS | 0.034초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[VULN-CSP-1-MISSING_SECURITY_HEADER]` | PASS | 0.001초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[VULN-HSTS-1-MISSING_SECURITY_HEADER]` | PASS | 0.004초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[debug-EXPOSED_DEBUG_ENDPOINT]` | PASS | 0.001초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[object-BOLA_IDOR]` | PASS | 0.001초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[admin-PRIVILEGE_ESCALATION]` | PASS | 0.001초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[cors-CORS_MISCONFIGURATION]` | PASS | 0.001초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[cookie-COOKIE_SECURITY_FLAG]` | PASS | 0.001초 |
| `test_unknown_type_does_not_invent_an_attack` | PASS | 0.000초 |
| `test_profile_lists_are_not_shared_between_findings` | PASS | 0.000초 |
| `test_security_header_explanations_remain_specific[VULN-CSP-1-\ub124\ud2b8\uc6cc\ud06c \uac00\ub85c\ucc44\uae30]` | PASS | 0.001초 |
| `test_security_header_explanations_remain_specific[VULN-HSTS-1-\uc2a4\ud06c\ub9bd\ud2b8 \uc0bd\uc785]` | PASS | 0.001초 |
| `test_risk_explanation_does_not_change_observed_evidence_or_severity` | PASS | 0.000초 |
| `test_risk_context_survives_selected_and_automatic_reports[json]` | PASS | 1.561초 |
| `test_risk_context_survives_selected_and_automatic_reports[md]` | PASS | 1.387초 |
| `test_risk_context_survives_selected_and_automatic_reports[csv]` | PASS | 1.290초 |
| `test_entry_path_and_query_are_preserved[https://example.com/app/]` | PASS | 0.001초 |
| `test_entry_path_and_query_are_preserved[https://example.com/app/login?next=%2Fapp%2F&lang=ko]` | PASS | 0.000초 |
| `test_entry_path_and_query_are_preserved[http://127.0.0.1:8990?empty=&tag=a&tag=b]` | PASS | 0.000초 |
| `test_entry_path_and_query_are_preserved[https://example.com/api/item?value=tail/]` | PASS | 0.000초 |
| `test_ambiguous_entry_path_cannot_expand_the_scope_to_root[/app/..]` | PASS | 0.000초 |
| `test_ambiguous_entry_path_cannot_expand_the_scope_to_root[/app/%2e%2e/]` | PASS | 0.000초 |
| `test_ambiguous_entry_path_cannot_expand_the_scope_to_root[/app/%252e%252e/]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://example.com/application]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://example.com/private]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://example.com/app/../private]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://example.com/app/%2e%2e/private]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://example.com/app/%252e%252e/private]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://example.com/app/%255c..%255cprivate]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://other.test/app/item]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[http://example.com/app/item]` | PASS | 0.000초 |
| `test_scope_choice_is_explicit_and_query_not_copied_to_other_paths` | PASS | 0.000초 |
| `test_query_variants_are_distinct_but_root_slash_is_not` | PASS | 0.000초 |
| `test_mounted_app_follows_relative_links_and_keeps_actual_boundary` | PASS | 3.470초 |
| `test_direct_query_endpoint_preserves_other_parameters_during_id_check` | PASS | 1.369초 |
| `test_origin_choice_can_probe_root_but_still_requests_the_entry` | PASS | 3.899초 |
| `test_dashboard_accepts_path_query_and_reports_selected_scope` | PASS | 3.476초 |
| `test_same_origin_allowed[https://example.com/]` | PASS | 0.001초 |
| `test_same_origin_allowed[https://example.com:443]` | PASS | 0.000초 |
| `test_outside_origin_blocked[https://sub.example.com]` | PASS | 0.000초 |
| `test_outside_origin_blocked[https://example.com.evil.test]` | PASS | 0.000초 |
| `test_outside_origin_blocked[http://example.com]` | PASS | 0.000초 |
| `test_outside_origin_blocked[https://example.com:444]` | PASS | 0.000초 |
| `test_outside_origin_blocked[https://other.test]` | PASS | 0.000초 |
| `test_outside_origin_blocked[file:///etc/hosts]` | PASS | 0.000초 |
| `test_outside_origin_blocked[https://a:b@example.com]` | PASS | 0.000초 |
| `test_destructive_paths_blocked[/delete-user]` | PASS | 0.000초 |
| `test_destructive_paths_blocked[/%64elete]` | PASS | 0.000초 |
| `test_destructive_paths_blocked[/%2564elete]` | PASS | 0.000초 |
| `test_destructive_paths_blocked[/reset-db]` | PASS | 0.000초 |
| `test_destructive_paths_blocked[/purchase]` | PASS | 0.001초 |
| `test_invalid_target_rejected[example.com]` | PASS | 0.001초 |
| `test_invalid_target_rejected[ftp://example.com]` | PASS | 0.001초 |
| `test_invalid_target_rejected[https://a:b@example.com]` | PASS | 0.000초 |
| `test_invalid_target_rejected[http://localhost:99999]` | PASS | 0.000초 |
| `test_invalid_target_rejected[http://localhost:0]` | PASS | 0.000초 |
| `test_invalid_target_rejected[http://localhost/#section]` | PASS | 0.000초 |
| `test_invalid_target_rejected[http://localhost/%0Aprivate]` | PASS | 0.000초 |
| `test_invalid_target_rejected[http://local host]` | PASS | 0.000초 |
| `test_empty_state_and_report_gate` | PASS | 0.008초 |
| `test_cross_origin_and_form_blocked` | PASS | 0.005초 |
| `test_secure_cookie_is_not_false_positive` | PASS | 0.001초 |
| `test_cors_requires_credentialed_reflection[*-true-0]` | PASS | 0.002초 |
| `test_cors_requires_credentialed_reflection[https://evil-attacker.com-false-0]` | PASS | 0.002초 |
| `test_cors_requires_credentialed_reflection[https://evil-attacker.com-true-1]` | PASS | 0.001초 |
| `test_vulnerable_demo_and_reports` | PASS | 1.809초 |
| `test_direct_target_hardened_profile` | PASS | 1.238초 |
| `test_unreachable_target_is_error` | PASS | 2.092초 |
| `test_duplicate_start_cancel_and_reset` | PASS | 0.013초 |
| `test_events_broadcast_and_replay` | PASS | 0.003초 |
| `test_redirects_do_not_escape_scope` | PASS | 1.430초 |

### 실행파일 독립 실행 결과

- 결과: **PASS**
- 수행 시각: 2026-11-04T09:00:00.299680+09:00
- 실행파일 SHA-256: `9b664f6138c34aa39350cc953ce53c4437febb526d7cae932038ed4c6a8eeb1c`
- 실행파일 크기: 65,658,315 bytes

| 검증 항목 | 결과 | 실제 결과 |
| --- | --- | --- |
| standalone_health | PASS | Copied exe starts from Korean path, no project sources |
| bundled_asset:/ | PASS | {"status": 200, "bytes": 14368} |
| bundled_asset:/static/app.css | PASS | {"status": 200, "bytes": 27732} |
| bundled_asset:/static/app.js | PASS | {"status": 200, "bytes": 30025} |
| bundled_asset:/static/fonts/NotoSansKR.ttf | PASS | {"status": 200, "bytes": 10414588} |
| bundled_asset:/static/fonts/IBMPlexMono-Regular.ttf | PASS | {"status": 200, "bytes": 135580} |
| start_demo | PASS | Embedded lab starts without Python subprocess |
| demo_result | PASS | {"status": "completed", "target_url": "http://127.0.0.1:2149", "endpoints_count": 8, "findings_count": 5, "chains_count": 1, "severity": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 2, "INFO": 0}, "score": 46, "grade": "F", "checks": [{"rule_id": "BASE", "title": "헤더·쿠키·CORS·정보 노출", "status": "FINDING", "reason": "실제로 측정한 응답에 대한 기존 규칙 결과입니다.", "tested": 8, "findings": 3, "errors": 0, "version": "1.0"}, {"rule_id": "R11", "title": "SQL Injection 조건 대조", "status": "SIGNAL", "reason": "매개변수 2개 대조, 조건 쌍 2회 반복. 읽기 응답만 비교했습니다. 판정 보류: 정상 기준 응답 없음; 정상 기준 응답 없음", "tested": 2, "findings": 0, "errors": 0, "version": "1.0"}, {"rule_id": "R06", "title": "입력값 반사와 출력 문맥", "status": "PASS", "reason": "HTML 원시 반사 0개. 반사만으로 XSS를 확정하지 않습니다.", "tested": 2, "findings": 0, "errors": 0, "version": "1.0"}, {"rule_id": "R12", "title": "브라우저 XSS 실행 확인", "status": "NOT_RUN", "reason": "범위 안에서 HTML 반사 또는 JavaScript 라우트 후보가 없습니다.", "tested": 0, "findings": 0, "errors": 0, "version": "1.0"}, {"rule_id": "R09", "title": "계정 간 객체 권한 대조", "status": "NOT_RUN", "reason": "소유권·역할 정책과 테스트 세션을 지정하지 않았습니다.", "tested": 0, "findings": 0, "errors": 0, "version": "1.0"}, {"rule_id": "R10", "title": "역할별 관리 응답 대조", "status": "NOT_RUN", "reason": "소유권·역할 정책과 테스트 세션을 지정하지 않았습니다.", "tested": 0, "findings": 0, "errors": 0, "version": "1.0"}, {"rule_id": "R11-T", "title": "시간 기반 SQL 조건 대조", "status": "NOT_RUN", "reason": "로컬 시간 대조 시나리오를 지정하지 않았습니다.", "tested": 0, "findings": 0, "errors": 0, "version": "1.0"}, {"rule_id": "R12-S", "title": "저장형 XSS 실행 대조", "status": "NOT_RUN", "reason": "저장·조회·정리 URL을 가진 로컬 시나리오를 지정하지 않았습니다.", "tested": 0, "findings": 0, "errors": 0, "version": "1.0"}], "assessment_complete": false, "assessment_note": "판정 보류: SQL Injection 조건 대조, 브라우저 XSS 실행 확인", "error": "", "scan_id": "b273e3d111e7", "started_at": "2026-11-04T00:00:05.751177+00:00", "finished_at": "2026-11-04T00:00:07.180630+00:00", "demo": true, "report_paths": ["<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\reports\\20261104_090006_b273e3d111e7.md", "<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\reports\\20261104_090006_b273e3d111e7.json"], "phase": 4, "scope_mode": "path", "log_path": "<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\logs\\scans\\20261104_090005_b273e3d111e7.jsonl", "log_error": "", "app_log_path": "<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\logs\\WVA.log"} |
| report_download | PASS | 5 findings in downloaded JSON |
| report_persistence | PASS | ["<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\reports\\20261104_090006_b273e3d111e7.md", "<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\reports\\20261104_090006_b273e3d111e7.json"] |
| detailed_remediation | PASS | 5 findings include ordered actions, completion criteria and verification |
| integrated_version | PASS | Integrated executable identifies as WVA 2.5.0 |
| risk_and_ai_context | PASS | Conditional risk limits and local AI prompt coexist in all five findings |
| reference_grade | PASS | {"score": 46, "grade": "F"} |
| comparison_metadata | PASS | Completed report records scope and rule version |
| surface_metadata | PASS | {"target_url": "http://127.0.0.1:2149", "methods": {"GET": 8}, "status_codes": {"200": 5, "unmeasured": 1, "422": 1, "403": 1}, "measured_count": 7, "schema_only_count": 1, "auth_response_count": 1, "tech_stack": ["Server: uvicorn"]} |
| persistent_scan_log | PASS | <프로젝트>\tests\artifacts\독립 실행 한글 경로\logs\scans\20261104_090005_b273e3d111e7.jsonl |
| selected_json_export | PASS | Only selected findings/logs plus provenance |
| check_coverage | PASS | Versioned check statuses and unmet prerequisites are returned |
| coverage_in_exports | PASS | Selected export preserves check scope and NOT_RUN reasons |
| selected_csv_export | PASS | UTF-8 BOM CSV includes enriched endpoint metadata |
| two_sse_clients | PASS | Independent clients receive identical first event |
| sse_resume | PASS | Last-Event-ID resumes after acknowledged event |
| second_launch_reuses_server | PASS | Second launcher exits; original service stays healthy |
| shutdown_request | PASS | Graceful shutdown accepted with an active SSE subscriber |
| graceful_exit | PASS | 0 |
| port_released | PASS | Service port closed after exit |

### 브라우저 작업 흐름 결과

- 결과: **PASS**
- 수행 시각: 2026-11-04T00:01:00.279Z

| 검증 항목 | 결과 | 실제 결과 |
| --- | --- | --- |
| minimal_copy | PASS | No screen slogan, priority panel, or explanatory count captions |
| consent_validation | PASS | Unchecked permission confirmation prevents diagnosis; checked confirmation allows it |
| running_motion | PASS | Spinner, scanning line and real stages activate; scope is locked |
| completed_reference_grade | PASS | Reference score appears for a completed scan |
| direct_target_scan | PASS | 5 findings, 1 chain, 8 endpoints |
| check_coverage_and_scope | PASS | Eight check outcomes, unmet prerequisites and limited assessment are visible |
| advanced_scan_controls | PASS | SQL, browser, parameter selection and local session/scenario profile are available in a collapsed section |
| completion_motion | PASS | Completion check appears and stage labels disappear after completion |
| charts_reconcile | PASS | Pie slices sum to 5; severity 1/1/1/2/0 and CVSS bins 1/1/2/1 |
| expanded_finding_table | PASS | Severity, finding/CWE, method/path, CVSS, evidence, remediation summary |
| finding_filters | PASS | Search empty state and HIGH-only filter |
| risk_detail_readability | PASS | Korean explanation and limits precede conditional attacks; raw evidence folds; six actions expand together |
| ai_prompt_with_risk_details | PASS | Collapsed AI prompt copies locally; observation, conditional attacks and ordered actions remain available |
| shared_detail_dialog | PASS | 75% workspace width, 75vh height, six ordered actions with completion criteria, native focus and Escape |
| attack_conditions_not_exploit_claims | PASS | CSP displays the separate XSS prerequisite and no execution claim; raw evidence remains available |
| chain_dialog_stays_on_route | PASS | Three steps, three related findings, detail opens without route change |
| surface_metadata | PASS | 7 measured, 1 unmeasured; parameters, HTTP, timing, bytes, headers and source |
| log_storage_paths | PASS | Per-scan JSONL and app error-log locations are visible |
| save_selection_gate | PASS | Five information descriptions; empty selection disables save |
| selected_json_download | PASS | Only selected findings and full disk logs plus provenance |
| selected_markdown_download | PASS | Selected summary and findings, detailed remediation included |
| selected_csv_download | PASS | UTF-8 BOM CSV with response metadata and selected endpoints |
| responsive_1440 | PASS | Charts, contained table scrolling, and dialog stay within viewport |
| responsive_768 | PASS | Charts, contained table scrolling, and dialog stay within viewport |
| mobile_risk_readability | PASS | 390px explanation, attack conditions and action controls fit the dialog at readable sizes |
| responsive_390 | PASS | Charts, contained table scrolling, and dialog stay within viewport |
| mobile_save_layout | PASS | Choices and save controls remain visible without page overflow |
| reload_restores_results | PASS | Counts and charts restore after refresh |
| reduced_motion | PASS | System motion preference disables scan/check animations |
| path_scope_network_boundary | PASS | Entry query preserved; every actual target request remains under /app/ |
| relative_links_and_query_variants | PASS | Nested relative links are measured; query variants remain separate |
| scoped_finding_request_url | PASS | Detail shows the actual request URL, without duplicated base path or query |
| scope_mobile_layout | PASS | URL and scope controls fit 390px without document overflow |
| direct_query_and_reload | PASS | Direct query is diagnosed, unrelated repeated parameters and restored input are preserved |
| origin_scope_choice | PASS | Same-server choice includes root probes while retaining entry URL |
| repeat_scan_comparison | PASS | Same target and scope show persistent findings; missing findings are not claimed as remediated |
| stage_labels_terminal_states | PASS | Stage labels disappear on stopped and failed scans as well as completed scans |
| actual_sql_finding_dialog | PASS | Installed DVWA SQLi is detected and has dedicated risks and ordered parameterization actions |
| hash_route_xss_and_partial_grade | PASS | Installed Juice Shop DOM XSS is detected; absent server query coverage prevents an A grade and the detail fits mobile |
| offline_assets | PASS | Zero external requests and zero JavaScript exceptions |

### 독립 취약 웹앱 벤치마크 (별도 수행 기록)

- 수행 시각: 2026-11-04T09:00:01+09:00
- 상태: **PASS**. 환경·재현·결과 수집 상태이며 SQLi·XSS 탐지 통과가 아닙니다.
- 독립 취약점·방어 대조 확인 6건, 소스/실행파일 진단 12건.
- SQLi·XSS 양성 4개와 방어 대조 2개를 소스·실행파일에서 비교했습니다. 전체 사이트 정확도로 일반화하지 않습니다.
- 설치·재실행: [독립 실습 절차](benchmarks/README.md). 상세 결과·한계: [벤치마크 결과](benchmarks/RESULTS.md).

### 계정·저장형·시간 기반 source/exe 검증

- 수행 시각: 2026-11-04T09:01:36+09:00
- 결과: **PASS**, 검증 10건.
- 원본: `artifacts/benchmark/extended-result.json`. 자체 SQLite 실습 앱의 결과이며 제3자 앱 측정과 구분합니다.

### 디자인 보조 검사

- 테이스트스킬 브라우저 검사: 0 FAIL, 2 WARN.
- 1440px: 페이지 가로 넘침 0px, JavaScript 예외 0개.
- 768px: 페이지 가로 넘침 0px, JavaScript 예외 0개.
- 390px: 페이지 가로 넘침 0px, JavaScript 예외 0개.
- WARN `rainbow-chart`: The charts use 5 different hues.
- WARN `tiny-text`: 67% of the text is under 13px.
- 소스 lint: 0 FAIL, 2 WARN. 숫자·URL의 고정폭 글꼴과 미측정 값의 대시 표시는 데이터 표현에 사용합니다.
- Impeccable detect: 보조 발견 2건. 진단 중 진행선 모션은 요청된 기능이며 완료 후 멈춥니다.
  - warning: Auto-scrolling marquee
  - advisory: Em-dash overuse
- 실제 데스크톱·모바일 화면과 큰 상세 창, 저장 화면의 스크린샷을 직접 확인했습니다.

### 화면 및 산출물

- [데스크톱 화면](../docs/images/dashboard.png)
- 태블릿 화면: `artifacts/browser/results-768.png` (로컬 검증 산출물)
- 모바일 화면: `artifacts/browser/results-390.png` (로컬 검증 산출물)
- 경로 화면: `artifacts/browser/chains-desktop.png` (로컬 검증 산출물)
- [순서별 조치 화면](../docs/images/actions.png)
- 공격 표면: `artifacts/browser/surface-desktop.png` (로컬 검증 산출물)
- 로그 위치: `artifacts/browser/logs-desktop.png` (로컬 검증 산출물)
- 저장 화면: `artifacts/browser/save-desktop.png` (로컬 검증 산출물)
- 기능 검증 원본: `artifacts/pytest.xml`, `artifacts/pytest-output.txt`
- 실행파일 검증 원본: `artifacts/executable-smoke.json`
- 브라우저 검증 원본: `artifacts/browser/result.json`

### 제한과 미실행 항목

- Windows 10 x64 한 대에서 확인했습니다. 별도 Windows 11 PC·백신 제품별 실행은 NOT_RUN입니다.
- 운영 사이트·운영 계정의 권한 대조, 포괄적인 전체 URL 탐색, 모든 OWASP 항목은 NOT_RUN입니다. 로컬 테스트 계정의 대조는 별도 확장 검증 기록을 따릅니다.
- 진단 데이터는 세션 메모리에 있으며 완료 보고서와 개별 JSONL 진단 로그는 파일로 보존됩니다. 앱 재실행 시 화면 히스토리를 복원하지 않습니다.
- 비밀 값은 가리지만 경로·식별자·관찰 증거는 남습니다. 공개된 실습 값과 운영 진단의 증거를 구분합니다.
<!-- RESULTS:END -->
