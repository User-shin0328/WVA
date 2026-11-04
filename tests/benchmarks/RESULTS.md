# WVA 2.5 독립 취약 웹앱 검증 결과

검증 시각: 2026-11-04T09:00:01+09:00 · 소스 기준 HEAD: `2a06d8dc9f61c1ffeda22f453d604e4c22ac20ef`

결과: **PASS**. 아래에 명시한 대상·입력·규칙의 결과이며 전체 웹 보안 인증은 아니다.

## 이전 결과와 구현 변경

[2.4 실측 기록](BASELINE_2.4.md)은 미지원으로 4개 양성을 놓치고 97/A를 표시했던 당시 결과다. 2.5는 SQL 조건 반복 대조와 브라우저 실행 표식 확인을 실제 엔진에 연결했다. 쿠키·CSRF 토큰을 갱신하며 모든 HTTP와 브라우저 자원에 출처·경로·메서드·요청 수·응답 크기 제한을 적용한다.

JavaScript 라우트는 #/ 형식 입력과 렌더링된 링크·검색 제어에서 수집한다. 검사 상태와 미실행 사유를 UI·자동 보고서·선택 내보내기에 남긴다. SQLi/XSS 검사가 미실행·오류이면 A~D 등급을 보류한다. 참고 점수는 발견 기반으로만 계산한다.

## 독립 기준 확인

| 항목 | 상태 | 실제 관찰 |
| --- | --- | --- |
| dvwa-low_sql_ground_truth | PASS | 기준 1 / 참 1 / 거짓 0, 조건 쌍 2회 |
| dvwa-safe_sql_ground_truth | PASS | 기준 1 / 참 0 / 거짓 0, 조건 쌍 2회 |
| juice_shop_sql_ground_truth | PASS | 기준/참 [1, 24, 47] / 거짓 [], 조건 쌍 2회 |
| dvwa-low_reflected_xss_ground_truth | PASS | 표식 실행 예상 True / 실제 True |
| dvwa-safe_reflected_xss_ground_truth | PASS | 표식 실행 예상 False / 실제 False |
| juice-shop_dom_xss_ground_truth | PASS | 표식 실행 예상 True / 실제 True |

## 소스 및 실행파일 진단

| 대상 | 실행 | SQLi/XSS 발견 | 판정 | 참고 점수·등급 |
| --- | --- | ---: | --- | --- |
| dvwa-low-sql | source | 1 | TRUE_POSITIVE | API 별도 |
| dvwa-safe-sql | source | 0 | TRUE_NEGATIVE | API 별도 |
| dvwa-low-xss | source | 1 | TRUE_POSITIVE | API 별도 |
| dvwa-safe-xss | source | 0 | TRUE_NEGATIVE | API 별도 |
| juice-shop-search | source | 1 | TRUE_POSITIVE | API 별도 |
| juice-shop-root | source | 1 | TRUE_POSITIVE | API 별도 |
| dvwa-low-sql | exe | 1 | TRUE_POSITIVE | 82 / 보류 |
| dvwa-safe-sql | exe | 0 | TRUE_NEGATIVE | 97 / 보류 |
| dvwa-low-xss | exe | 1 | TRUE_POSITIVE | 82 / B |
| dvwa-safe-xss | exe | 0 | TRUE_NEGATIVE | 97 / A |
| juice-shop-search | exe | 1 | TRUE_POSITIVE | 85 / 보류 |
| juice-shop-root | exe | 1 | TRUE_POSITIVE | 82 / 보류 |

알려진 양성 4개와 방어 대조 2개를 각각 소스·실행파일로 검사했다. 관련 규칙이 실제 실행된 결과를 비교하며 CSP 누락을 SQLi/XSS 탐지로 집계하지 않는다. 이 표본으로 전체 탐지 정확도를 일반화하지 않는다.

## 추가 기능의 별도 검증

tests/test_active_rules.py는 실제 SQLite의 취약/매개변수화 쿼리, 불안정·WAF·DB 오류 응답, 출력 인코딩·CSP·DOM, 브라우저의 외부/다른 경로/POST/WebSocket 차단, 요청·응답 한도, CSRF 세션, 계정·역할 정책, 저장형 XSS·정리·취소 정리, 로컬 시간 기반 조건 대조를 검사한다. 별도 로컬 실습 앱 tests/lab/advanced_target.py를 사용하며 제3자 앱 결과와 구분한다. 최신 수와 실제 PASS/FAIL은 ../TEST_RESULTS.md의 기능 검사 목록을 따른다.

## 산출물

- WVA.exe SHA-256: `9b664f6138c34aa39350cc953ce53c4437febb526d7cae932038ed4c6a8eeb1c`.
- 원본 result.json: 독립 기준 6건, 소스/실행파일 12건, 이미지 digest, 소스 파일 해시.
- source-*.json, exe-*.json: 실제 발견 항목과 검사 상태.
- browser-ground-truth.json 및 XSS PNG 3장: 브라우저 표식과 요청 기록.
- dvwa-*-sql-*.html, juice-sql-ground-truth.json: 실제 DB 조건 응답.
- 설치 원문 installed-*.php 및 별도 레거시 반사 도우미 standalone-reflection.json.
- 재실행·환경 종료 절차: [README.md](README.md).

## 남은 한계와 검사 전제

1. SQLi 기본 규칙은 안정적인 읽기 응답의 조건 차이를 확인한다. DB 오류만 있으면 SIGNAL이며 WAF·인증·통신 실패는 오류 또는 미실행으로 구분한다. 모든 DB 문법·인코딩·애플리케이션 문맥을 포괄하지 않는다.
2. 브라우저 XSS는 실제 실행 표식으로 판정하며 인코딩·CSP 차단을 구분한다. 쿠키 읽기·외부 전송·실사용 계정 작업은 하지 않는다. 브라우저 미설치·범위 제한·후보 없음은 미실행이다.
3. 저장형과 시간 기반 검사는 명시한 로컬 시나리오에서만 실행한다. 저장·조회·정리 계약 및 시간 입력이 필요하며, 전제가 없으면 NOT_RUN이다. 별도 실습 앱에서 검증했으며 이 표의 제3자 앱 6개 결과와 합치지 않는다.
4. 로그인·계정 간·역할별 대조는 제공한 세션과 명시적인 비공개 필드·권한 정책이 있어야 한다. MFA·CAPTCHA·SSO 자동 로그인과 임의 사이트의 권한 정책 추론은 지원하지 않는다.
5. Windows 10 + Docker Linux + Edge에서 검증했다. 운영 사이트·운영 DB·다른 OS/백신 조합의 검증은 별개다. bridge 네트워크의 완전한 외부 통신 차단을 주장하지 않는다.
6. R01~R13 설계 문서의 모든 세부 항목을 구현한 것은 아니다. 이번 범위는 직전 검증 보고서의 SQLi·XSS·세션·계정·브라우저 경계·판정 상태 보완이다. 현재 지원 범위와 전제는 docs/ACTIVE_RULES.md에 기록한다.
