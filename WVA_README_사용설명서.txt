================================================================================
   WVA (Web Vulnerability Auditor) - 웹 취약점 연계 분석 Agent 사용설명서
================================================================================

1. 프로젝트 개요 및 배경
--------------------------------------------------------------------------------
최근의 지능형 공격 에이전트(Attack Agents)는 단일한 대형 취약점을 노리는 대신,
사소해 보이는 여러 개의 작은 취약점(Low/Medium 등급)을 수집하고 상호 연결(Chaining)하여
최종적으로 시스템의 핵심 권한(Admin/System)을 탈취하는 방식을 사용합니다.

WVA (Web Vulnerability Auditor)는 이러한 공격 에이전트의 다단계 연계 공격 기법을
역으로 분석하여, 웹 애플리케이션의 복합 공격 경로(Exploit Chain)를 사전에 탐지하고
방어자가 가장 적은 비용으로 공격을 원천 차단할 수 있는 '최적 차단 거점(Choke Point)'을
도출하는 차세대 보안 진단 에이전트입니다.


2. ARTEX 대비 기술적 차별점 및 우위
--------------------------------------------------------------------------------
프로젝트 폴더 내 Go 기반의 오픈소스 침투 테스트 시스템인 'ARTEX'와 비교했을 때,
WVA 시스템은 다음과 같은 핵심적인 기술적 도약을 이루었습니다:

  1) 정형 상태 전이 그래프 (State-based Attack Path Graph)
     - ARTEX: 텍스트 기반의 할 일 목록(Shared Todolist)과 LLM의 자유 연상에 의존.
     - WVA: NetworkX 기반 유향 그래프(DAG)를 통해 전제조건(Preconditions)과
       후조건(Postconditions)의 상태 전이를 수학적으로 모델링하여 누락 없는 3~5단계
       체이닝 탐색을 보장합니다.

  2) 강타입 보안 지식 저장소 (Typed Security Blackboard)
     - ARTEX: Worker 간 텍스트 로그 검색(search_all_worker_traces)으로 인한 컨텍스트 오염.
     - WVA: Pydantic 기반의 구조화된 데이터(LeakedArtifact, CorrelationMatrix)로
       발견된 지식을 저장하여 에이전트 간 정확한 데이터 파이프라인을 형성합니다.

  3) 초크 포인트(Choke Point) 기반 방어 전략 자동 도출
     - 공격자는 전체 체인을 모두 성공시켜야 하지만, 방어자는 체인의 단 한 고리만
       끊어도 전체 공격을 무력화할 수 있습니다. 시스템이 최소 비용 최우선 방어 거점을
       자동으로 계산하여 제시합니다.


3. 디렉터리 구조
--------------------------------------------------------------------------------
WVA/
├── 1_WVA_웹취약점_연계분석_데모실행.bat     # 모의 취약점 타깃 자동 구동 및 연계 분석 데모
├── START_WVA_CHAIN_AUDITOR_DEMO.bat     # 위 파일의 영문 버전
├── 2_WVA_취약점분석_CLI_직접실행.bat       # 대화형 CLI 메뉴 (원하는 URL 직접 분석)
├── RUN_WVA_SCANNER_CLI.bat              # 위 파일의 영문 버전
├── 3_WVA_단위테스트_검증.bat               # 공격 그래프 엔진 및 안전 정책 유닛 테스트
├── RUN_WVA_PYTEST_VERIFICATION.bat      # 위 파일의 영문 버전
│
├── WVA_설계계획서_최종본.md               # 시스템 최종 설계 계획서 (마크다운)
├── WVA_SYSTEM_DESIGN_SPECIFICATION.md   # 위 문서의 영문 파일명 버전
├── WVA_취약점분석_결과보고서_초안.md      # 보안 감사 결과보고서 초안 (마크다운)
├── WVA_VULNERABILITY_AUDIT_REPORT_DRAFT.md # 위 문서의 영문 파일명 버전
├── WVA_사용설명서.txt                     # 시스템 상세 사용설명서
│
├── cli.py                               # CLI 및 데모 실행 진입점
├── mock_target.py                       # 취약점 연계 시나리오 검증용 FastAPI 모의 서버
│
├── core/
│   ├── models/
│   │   ├── asset.py                     # 도메인 및 엔드포인트 모델
│   │   ├── state.py                     # 보안 상태 및 권한 레벨, 유출 지식 모델
│   │   └── vulnerability.py             # 취약점, 공격 체인(Exploit Chain), Choke Point 모델
│   ├── graph/
│   │   ├── attack_graph.py              # 상태 전이 및 연쇄 공격 경로 탐색 엔진 (NetworkX)
│   │   └── blackboard.py                # 타입화된 중앙 지식 저장소 (Blackboard)
│   └── safety/
│       └── governance.py                # 스코프 검증 및 비파괴적 안전 정책
│
├── surface/
│   ├── recon.py                         # 동적 엔드포인트 및 HTTP 설정/자산 수집기
│   └── reflection.py                    # 안전한 카나리 기반 파라미터 반사 검증기
│
├── agents/
│   ├── base.py                          # 감사 에이전트 기본 클래스
│   ├── config_auditor.py                # 보안 헤더, 쿠키 플래그, CORS 설정 감사 에이전트
│   ├── idor_auditor.py                  # BOLA / IDOR 권한 격리 감사 에이전트
│   ├── chain_planner.py                 # 공격 경로 체인 기획 및 권한 상승 분석 에이전트
│   └── engine.py                        # 멀티 에이전트 오케스트레이션 파이프라인
│
├── reporting/
│   └── report_generator.py              # Markdown, Mermaid 다이어그램, JSON 리포트 생성기
│
└── tests/
    └── test_audit_engine.py             # 유닛 테스트 코드


4. 실행 방법 (더블클릭 실행 가이드)
--------------------------------------------------------------------------------
본 프로젝트는 가상환경(.venv)이 구축되어 있어 외부 종속성 설치 없이
배치 파일 더블클릭만으로 즉시 실행됩니다.

[방법 1] 원클릭 데모 실행 (가장 추천)
  - '1_WVA_웹취약점_연계분석_데모실행.bat' (또는 'START_WVA_CHAIN_AUDITOR_DEMO.bat')을 더블클릭합니다.
  - 로컬 테스트베드(mock_target.py, 8989 포트)가 자동으로 기동됩니다.
  - 에이전트가 8개 엔드포인트를 탐색하고 3단계 연계 취약점을 자동으로 연결/분석합니다.
  - 분석 완료 후 'WVA_vulnerability_report.md' 및 'WVA_vulnerability_report.json'이 생성됩니다.

[방법 2] 대화형 CLI 직접 실행
  - '2_WVA_취약점분석_CLI_직접실행.bat' (또는 'RUN_WVA_SCANNER_CLI.bat')을 더블클릭합니다.
  - 1번(데모 실행), 2번(사용자 지정 타깃 URL 분석) 중 선택하여 진단을 수행합니다.

[방법 3] 자체 유닛 테스트 검증
  - '3_WVA_단위테스트_검증.bat' (또는 'RUN_WVA_PYTEST_VERIFICATION.bat')을 더블클릭합니다.
  - pytest를 통해 공격 그래프 알고리즘 및 안전 정책의 정상 동작을 즉시 검증합니다.


5. 포함된 실전 연계 시나리오 (Demo Target)
--------------------------------------------------------------------------------
'1_WVA_웹취약점_연계분석_데모실행.bat' 실행 시 에이전트가 탐지하는 실제 연계 체인:

  [Step 1: 정보 노출 (Low)]
  - 엔드포인트: GET /debug/version
  - 현상: 인증 없이 내부 테스트 계정 ID ('usr_staging_99') 노출.
  - 에이전트 동작: 해당 ID를 수집하여 Blackboard의 Leaked Artifact로 등록.

  [Step 2: Broken Object Level Authorization (High)]
  - 엔드포인트: GET /api/v1/user/profile?user_id=usr_staging_99
  - 현상: Step 1에서 획득한 ID로 요청 시 세션 검증 없이 관리 개발자의 프로필과
          API Key ('sec_k98_admin_supersecret_token')를 평문 응답.
  - 에이전트 동작: 유출된 API Key를 수집하여 후속 권한 검증 큐로 전달.

  [Step 3: 관리자 권한 상승 (Critical)]
  - 엔드포인트: GET /api/v1/admin/config
  - 현상: Step 2에서 유출된 API Key를 헤더(X-API-Key)로 전달하여 200 OK 수신 및
          내부 마스터 DB 및 암호화 키 등 시스템 최고 권한 장악.

  [최종 산출물: Choke Point 방어 권고]
  - 전체 체인 중 [Step 1] 또는 [Step 2]만 패치해도 최종 Admin 탈취 공격이
    원천 무력화됨을 수학적으로 증명하고 코드 레벨 조치 방안을 제시합니다.


6. 결과 리포트 확인 방법
--------------------------------------------------------------------------------
스캔 완료 후 프로젝트 루트 디렉터리에 2종의 리포트가 생성됩니다:
  1) 'WVA_vulnerability_report.md':
     - GitHub Flavored Markdown 기반 리포트.
     - Mermaid 순서도(flowchart)가 포함되어 시각적으로 공격 체인을 확인 가능.
     - 단계별 조치 방안 및 최소 비용 방어 거점(Choke Point) 제시.
  2) 'WVA_vulnerability_report.json':
     - DevSecOps 파이프라인 및 SIEM/SOAR 시스템과 연동 가능한 정형 JSON 데이터.


7. 안전성 및 윤리적 가이드라인
--------------------------------------------------------------------------------
- 본 시스템은 인가된 시스템의 사전 보안 감사 및 취약점 방어를 목적으로 제작되었습니다.
- SafetyGovernance 모듈을 통해 화이트리스트 도메인 외의 비인가 요청과 파괴적 경로
  (/logout, /delete, /drop, /reset-db 등)에 대한 요청은 원천 차단됩니다.
================================================================================
