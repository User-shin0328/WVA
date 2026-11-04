# WVA 독립 취약 웹앱 검증 절차

기존 데모와 다른 개발자가 만든 DVWA·OWASP Juice Shop을 설치해 실제 취약점 유무를 확인한 뒤, **현재 WVA가 무엇을 탐지하고 무엇을 놓치는지** 측정한다. 2.5는 실제 SQL Injection·XSS 실행 규칙과 제3자 앱의 독립 기준을 대조한다. 이전 미지원 결과는 BASELINE_2.4.md에 보존한다. 실제 결과는 [RESULTS.md](RESULTS.md)에 있다.

## 1. 준비와 설치

프로젝트 루트에서 PowerShell을 연다. 이 PC에는 Docker Desktop, Python 테스트 환경, Node, Edge와 Playwright가 준비돼 있다. Docker가 꺼져 있으면 아래 스크립트가 기동을 시도한다. 다른 PC의 Python 환경은 `tests/Setup-TestEnvironment.ps1`로 준비한다.

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\benchmarks\Start-Benchmark.ps1
```

예상 결과: `wva-benchmark` 프로젝트의 DB·DVWA low·DVWA impossible·Juice Shop 컨테이너가 시작된다. DB는 healthy가 되어야 한다. 최초에는 이미지를 내려받는다. `compose.yaml`은 이번에 확인한 이미지 digest를 고정하므로 이후 latest 변경과 구분할 수 있다.

| 대상 | 브라우저 주소 | 용도 |
| --- | --- | --- |
| DVWA low | http://127.0.0.1:18910 | 의도적으로 취약한 SQLi·반사형 XSS |
| DVWA impossible | http://127.0.0.1:18911 | 숫자 검사·준비된 쿼리·출력 인코딩을 적용한 대조군 |
| Juice Shop | http://127.0.0.1:18912 | 다른 앱의 SQLi·JavaScript 기반 DOM XSS |

DVWA 두 서버는 **전용 테스트 DB**만 공유한다. DB 포트는 게시하지 않으며 웹앱은 127.0.0.1에만 게시한다. `low` 및 인증 비활성화 설정은 실습용이다. Docker bridge 네트워크를 사용하므로 인터넷 통신이 완전히 차단됐다고 해석하지 않는다. 다른 프로젝트의 컨테이너·DB를 변경하지 않는다.

## 2. 독립 재현과 WVA 진단 실행

```powershell
.\.venv\Scripts\python.exe -X utf8 -m tests.benchmarks.run
```

이 명령은 매번 **위 compose의 DVWA 전용 DB를 초기화**하고 다음 순서로 진행한다. 기존 실습 진행 상태를 보존하려면 결과 JSON을 검토하고 재실행 시점을 선택한다.

1. 설치된 DVWA PHP 원문과 이미지 식별자를 보존한다. **예상:** low는 입력을 SQL 문자열에 넣고, impossible은 숫자 검사·준비된 쿼리를 사용한다. 이미지를 내려받았다는 사실만으로 취약점 재현 성공으로 판정하지 않는다.
2. DVWA SQLi에 정상 ID, 참 조건, 거짓 조건을 전달한다. **예상:** low는 정상/참에 같은 1행, 거짓에 0행. impossible은 정상 ID만 1행이며 조건 문자열은 모두 0행. 참·거짓 조건 쌍을 두 번 반복한다. 응답에 표시한 입력 문자열을 제외하고 실제 DB 반환 필드를 비교한다. impossible은 각 요청 전에 정상 CSRF 토큰을 받는다.
3. Juice Shop의 공개 상품 검색에서 조건 쌍을 두 번 비교한다. **예상:** 정상/참의 상품 ID `[1, 24, 47]`이 같고 거짓은 빈 목록이다. 사용자 인증정보나 다른 테이블을 추출하지 않는다. 작은따옴표 한 번에 500이 발생할 것이라고 가정하지 않는다.
4. 격리된 Edge에서 고유 표식만 실행한다. **예상:** DVWA low와 Juice Shop의 `window.__wvaXss`에 표식이 생긴다. DVWA impossible은 정상 세션·CSRF 토큰으로 요청해도 표식이 없으며 입력이 텍스트로 표시된다. 브라우저 HTTP는 해당 출처의 GET·HEAD만 허용하고 POST·다른 출처는 차단한다. 쿠키 읽기·외부 전송·저장형 입력은 하지 않는다.
5. WVA 소스로 6개 대상에 **정상 기준 URL**을 진단한다. **예상:** 양성 4개에서는 SQLi/XSS가 탐지되고 방어 대조 2개에서는 관련 탐지가 없다. JSON 응답의 CSP 누락은 HTML 위험으로 보고하지 않는다. Juice Shop 루트는 13개, 나머지 5개 URL은 2개 엔드포인트가 수집된다. 이 수치는 고정된 이미지·현재 소스 기준이다.
6. 같은 WVA.exe를 별도 포트·별도 데이터 폴더에서 실행해 6개 진단을 반복하고 종료한다. **예상:** `docs/BUILD_INFO.json`과 exe 해시가 일치하고, 소스/실행파일의 발견 유형별 건수가 6개 대상 모두 같다. 기존 9030 대시보드는 이 검사로 종료하지 않는다.
7. 기존 `ReflectionCanaryAuditor`를 별도로 호출한다. **예상:** DVWA low는 MEDIUM 원시 반사, impossible은 INFO 안전한 반사. 기본 엔진에 연결됐다는 의미나 브라우저 XSS 실행 증명으로 사용하지 않는다.

최종 예상 출력은 `PASS`, 독립 확인 **6건**, 소스/실행파일 진단 **12건**이다. 알려진 양성 4개와 방어 대조 2개의 관련 규칙이 실제 실행돼야 한다. 이 표본 결과를 모든 사이트의 탐지율로 환산하지 않는다.

## 3. 결과 확인

- 공유 가능한 요약과 한계: [RESULTS.md](RESULTS.md), 실행할 때마다 갱신.
- 원본 전체: `tests/artifacts/benchmark/result.json`.
- 실제 진단 보고서: `source-*.json`, `exe-*.json`.
- 실제 DB 응답: `dvwa-*-sql-*.html`, `juice-sql-ground-truth.json`.
- 브라우저 실행 판정·요청: `browser-ground-truth.json` 및 XSS PNG 3장. PNG만으로 실행을 판정하지 않고 표식 값도 함께 본다.
- 독립 실행파일 보고서·로그: `tests/artifacts/benchmark/executable-data/`.
- 별도 반사 도우미: `standalone-reflection.json`.
- 설치 원문 사본: `installed-*.php`.

브라우저 원본에는 실습용 CSRF 값과 테스트 요청이 들어갈 수 있으므로 로컬 산출물로 유지한다. 일반 회귀 검사 및 실행파일 독립 실행 검증과 이 벤치마크 수치를 합쳐 탐지율로 표시하지 않는다.

## 4. 수동 확인

브라우저에서 DVWA low의 **SQL Injection** 및 **XSS (Reflected)** 메뉴를 열 수 있다. 최초 DB 초기화는 위 자동 검사에서 한다. Juice Shop은 환영창의 Dismiss를 누른 뒤 검색 화면을 확인한다.

WVA 대시보드의 대상 입력에는 다음 정상 URL을 넣고 **입력 경로와 하위 경로**를 선택한다.

```text
http://127.0.0.1:18910/vulnerabilities/sqli/?id=1&Submit=Submit
http://127.0.0.1:18910/vulnerabilities/xss_r/?name=WVA_baseline
http://127.0.0.1:18912/rest/products/search?q=apple
http://127.0.0.1:18912/
```

예상 결과: 취약 SQL·반사형 XSS와 Juice Shop SQL·DOM XSS가 실제 탐지된다. impossible 대조에서는 관련 탐지가 없어야 한다. CSP 누락은 XSS와 다른 항목이다. CSRF 토큰과 쿠키는 같은 세션에서 갱신하며 #/ 라우트 입력과 실제 렌더링된 검색 제어를 통한 탐색을 지원한다.

## 5. 종료와 재시작

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\benchmarks\Stop-Benchmark.ps1
# 다시 시작
powershell -ExecutionPolicy Bypass -File .\tests\benchmarks\Start-Benchmark.ps1
```

종료는 이 compose 프로젝트만 내리고 DB 볼륨과 이미지는 보존한다. Docker Desktop 자체나 다른 프로젝트는 종료하지 않는다. 자동 검증이 만든 임시 WVA 프로세스는 검사 종료 시 정리된다.

## 6. 오류 해결과 판정 기준

| 증상 | 확인 및 조치 |
| --- | --- |
| Docker engine 연결 실패 | Docker Desktop이 실행 중인지 확인한 뒤 시작 스크립트 재실행 |
| 18910~18912 접속 거부 | `docker compose -f tests/benchmarks/compose.yaml ps`와 `logs --tail 30` 확인. 설치 완료·DB healthy·포트 매핑을 구분 |
| 포트 충돌 | 임의 프로세스를 종료하지 말고 사용 중인 앱을 확인. 포트를 바꿀 경우 compose와 두 검사 스크립트의 고정 대상도 함께 수정 |
| DB setup 실패 | 전용 DB 로그와 `dvwa-setup.html` 확인. 다른 DB의 초기화 명령으로 대체하지 않음 |
| CSRF 경고·로그인 화면 | low/impossible 서버를 구분하고 정상 세션·토큰 획득 여부 확인. 접근 실패를 안전 판정으로 기록하지 않음 |
| 브라우저가 끝없이 대기 | Juice Shop은 지속 통신이 있어 networkidle로 기다리지 않음. DOM 준비 후 실제 표식이 생기는지 확인 |
| Playwright 모듈 없음 | Node의 npm으로 `npm install --prefix tests/artifacts/browser-runtime playwright` 후 `$env:WVA_NODE_MODULES = "$PWD/tests/artifacts/browser-runtime/node_modules"` 설정 |
| Edge 경로가 다름 | `$env:WVA_BROWSER`에 설치된 Chromium 계열 브라우저 실행파일의 실제 경로 설정 |
| 소스/exe 결과 불일치 | 임의로 기대값을 맞추지 말고 두 JSON 및 빌드 해시 확인 |

## 공식 출처

- [DVWA](https://github.com/digininja/DVWA), [공식 compose](https://github.com/digininja/DVWA/blob/master/compose.yml), [공식 환경 설정](https://github.com/digininja/DVWA/blob/master/config/config.inc.php.dist).
- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), [개별 인스턴스 실행 안내](https://pwning.owasp-juice.shop/companion-guide/latest/part1/running.html).

공식 공개 데모를 스캔한 결과가 아니다. 소유한 로컬 설치만 사용했다.

## 2.5 추가 로컬 기능 검증

```powershell
.\.venv\Scripts\python.exe -X utf8 -m tests.benchmarks.extended
```

예상: 계정 간 객체·관리 역할·실제 SQLite 시간 조건·저장형 XSS 실행 및 정리·source/exe 결과 일치·비밀 값 가림 **10건 PASS**. 임시 로컬 실습 앱을 자동 시작하고 검사 후 종료한다. 원본은 `artifacts/benchmark/extended-result.json`, `extended-source.json`, `extended-exe.json`이다. 일반 회귀 검사와 제3자 앱 결과를 합쳐 탐지율로 표시하지 않는다.

수동 확장 프로필은 [advanced-loopback.json](profiles/advanced-loopback.json), 사용 절차는 [실행 규칙 안내](../../docs/ACTIVE_RULES.md)를 따른다. 프로필에는 공개된 로컬 실습 계정만 있으며 운영 계정용 비밀 값은 저장소에 넣지 않는다.
