# WVA 독립 취약 웹앱 검증 결과

검증 시각: 2026-11-03T23:52:14+09:00 · WVA 소스: `2a06d8dc9f61c1ffeda22f453d604e4c22ac20ef`

실행 상태: **PASS_WITH_UNSUPPORTED_RULES**. 환경과 취약점 재현의 성공 여부이며 WVA의 SQL Injection·XSS 탐지 통과를 뜻하지 않는다.

## 규칙 재확인

| 항목 | 확인 결과 |
| --- | --- |
| SQL Injection | docs/RULE_DESIGN.md의 R11 설계만 존재. agents/engine.py 실행 단계와 취약점 유형에 전용 규칙 없음 |
| 브라우저 XSS | R12 설계만 존재. 기본 엔진은 브라우저를 실행하지 않음 |
| 입력값 반사 | surface/reflection.py의 ReflectionCanaryAuditor가 있으나 기본 엔진에서 호출하지 않음. 실제 실행 증명과 구분 |
| CSP 누락 | 현재 지원하는 별도 헤더 규칙. XSS 실행 확인으로 집계하지 않음 |

확인한 소스 파일의 SHA-256은 원본 result.json의 source_files에 보존한다.

## 설치 환경

| 대상 | 주소 | 설정 |
| --- | --- | --- |
| DVWA low | http://127.0.0.1:18910 | low, 실습용 인증 비활성화 |
| DVWA 방어 대조 | http://127.0.0.1:18911 | impossible, 실습용 인증 비활성화 |
| OWASP Juice Shop | http://127.0.0.1:18912 | v20.3.0 |

DB는 이 프로젝트 전용 Docker 볼륨이며 외부 포트를 게시하지 않는다. 웹앱은 127.0.0.1에만 게시한다. bridge 네트워크이므로 완전한 외부 통신 차단 환경이라고 주장하지 않는다. 이미지는 compose.yaml의 digest로 고정했다.

## 독립적인 취약점 확인

| 항목 | 예상 및 실제 | 판정 |
| --- | --- | --- |
| dvwa-low_sql_ground_truth | 기준 1행 / 참 1행 / 거짓 0행, 조건 쌍 2회 반복 | PASS |
| dvwa-safe_sql_ground_truth | 기준 1행 / 참 0행 / 거짓 0행, 조건 쌍 2회 반복 | PASS |
| juice_shop_sql_ground_truth | 기준·참 상품 ID [1, 24, 47] / 거짓 [], 조건 쌍 2회 반복 | PASS |
| dvwa-low_reflected_xss_ground_truth | 표식 실행 예상 True / 실제 True | PASS |
| dvwa-safe_reflected_xss_ground_truth | 표식 실행 예상 False / 실제 False | PASS |
| juice-shop_dom_xss_ground_truth | 표식 실행 예상 True / 실제 True | PASS |

SQL 확인은 실습 데이터 조회의 참·거짓 조건만 대조한다. 사용자 비밀번호·세션 추출·DB 쓰기·지연·외부 전송은 하지 않는다. XSS는 격리 브라우저의 window.__wvaXss에 고유 표식이 생기는지만 확인한다. DVWA impossible은 정상 CSRF 세션·토큰을 확보한 후 검사한다.

## WVA 소스 및 실행파일 측정

| 대상 | 실행 | 실제 관련 탐지 | 기타 발견 | 엔드포인트 | 판정 |
| --- | --- | ---: | --- | ---: | --- |
| dvwa-low-sql | source | 0 | {"MISSING_SECURITY_HEADER": 1} | 2 | NOT_SUPPORTED |
| dvwa-safe-sql | source | 0 | {"MISSING_SECURITY_HEADER": 1} | 2 | NOT_SUPPORTED |
| dvwa-low-xss | source | 0 | {"MISSING_SECURITY_HEADER": 1} | 2 | NOT_SUPPORTED |
| dvwa-safe-xss | source | 0 | {"MISSING_SECURITY_HEADER": 1} | 2 | NOT_SUPPORTED |
| juice-shop-search | source | 0 | {"MISSING_SECURITY_HEADER": 1} | 2 | NOT_SUPPORTED |
| juice-shop-root | source | 0 | {"MISSING_SECURITY_HEADER": 1} | 13 | NOT_SUPPORTED |
| dvwa-low-sql | exe | 0 | {"MISSING_SECURITY_HEADER": 1} | 2 | NOT_SUPPORTED |
| dvwa-safe-sql | exe | 0 | {"MISSING_SECURITY_HEADER": 1} | 2 | NOT_SUPPORTED |
| dvwa-low-xss | exe | 0 | {"MISSING_SECURITY_HEADER": 1} | 2 | NOT_SUPPORTED |
| dvwa-safe-xss | exe | 0 | {"MISSING_SECURITY_HEADER": 1} | 2 | NOT_SUPPORTED |
| juice-shop-search | exe | 0 | {"MISSING_SECURITY_HEADER": 1} | 2 | NOT_SUPPORTED |
| juice-shop-root | exe | 0 | {"MISSING_SECURITY_HEADER": 1} | 13 | NOT_SUPPORTED |

**알려진 취약 사례 4개(DVWA SQLi·반사 XSS, Juice Shop SQLi·DOM XSS)를 소스와 실행파일 모두 놓쳤다.** 방어 대조 사례 2개에서 탐지가 없다는 것도 미지원 규칙의 정상 탐지 성능으로 집계하지 않는다. 각 결과의 CSP 누락 1건은 SQLi·XSS와 다른 항목이다. 소스/실행파일의 발견 유형별 건수는 6개 대상 모두 일치한다.

실행파일의 6개 진단은 모두 참고 점수 **97점/A**였다. 실제 SQLi·XSS가 있어도 현재 규칙이 검사하지 않으면 점수에 반영되지 않는 한계가 실측됐다. 원본 measurements의 score·grade를 확인할 수 있다.

DVWA impossible SQL 진단은 WVA가 토큰을 취득해 제출하는 검사가 아니므로, DB 검사 성공이나 음성 확인으로 해석하지 않는다. Juice Shop의 #/search DOM 경로는 브라우저에서 실행 확인했고 WVA에는 서버 루트 주소를 입력했다. 현재 URL 입력은 fragment를 받지 않으며 JS 화면 탐색도 하지 않는다.

## 별도 반사 검사 코드

독립 호출에서는 DVWA low에 MEDIUM 원시 반사, impossible에 INFO 안전한 반사를 기록했다. 이는 기본 WVA 진단에 연결된 기능이 아니며 SQLi 또는 브라우저 XSS 확인 규칙으로 표시하지 않는다.

## 기록과 재실행

- 검증한 WVA.exe SHA-256: `5ceba009a5bac69ef3bc0df41e6e999b29fde46d02e9c436fed5269b6b926279`.
- 절차와 예상 결과: [README.md](README.md).
- 원본: tests/artifacts/benchmark/result.json, source-*.json, exe-*.json.
- DB 응답: dvwa-*-sql-*.html, juice-sql-ground-truth.json.
- 브라우저 표식 및 요청: browser-ground-truth.json, dvwa-low-xss.png, dvwa-safe-xss.png, juice-shop-xss.png.
- 독립 반사 검사: standalone-reflection.json. 설치 원문: installed-*.php.

## 한계점과 보완사항

1. 이번 작업은 현재 규칙을 재확인하고 별도 실습 앱에서 탐지 범위를 측정한 것이다. SQLi·XSS 전용 엔진 규칙을 새로 구현하거나 연결하지 않았다.
2. R11은 기준 응답 안정성·조건 쌍 반복·매개변수 선택·WAF/일반 오류 대조를 구현해야 한다. R12는 HTTP/하위 리소스/브라우저 요청 경계와 실행 표식 확인을 구현해야 한다.
3. 스캔이 완료됐거나 참고 등급이 높아도 미지원 항목은 안전으로 판단할 수 없다. 현재 화면에는 검사별 미지원·미실행 상태가 없으므로 이번 보고서의 NOT_SUPPORTED를 함께 확인해야 한다.
4. 기본 WVA의 쿠키/CSRF 세션 처리와 JavaScript 라우트 탐색이 부족하다. 저장형 XSS, 시간 기반/블라인드 SQLi, 로그인·다중 계정 권한 대조는 이번 검증에서 NOT_RUN이다.
5. Docker의 Linux 컨테이너를 Windows에서 실행했다. 외부 공개 서버·운영 DB·모든 OWASP 취약점 검증으로 확장하지 않는다. 직접 만든 대체 취약 앱은 필요하지 않아 추가하지 않았다.
6. DVWA의 인증 비활성화와 low 설정은 이 로컬 실습 전용이다. 환경을 다른 주소에 게시하지 않는다. 종료는 README의 전용 compose down을 사용한다.
