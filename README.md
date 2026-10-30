# WVA (Web Vulnerability Auditor)
> **차세대 지능형 웹 취약점 연계 분석 및 공격 경로 시뮬레이션 Agent**

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/architecture-Multi--Agent%20Graph-orange.svg)](#시스템-아키텍처)
[![Dashboard](https://img.shields.io/badge/dashboard-Live%20Cyber--Dark%20UI-cyan.svg)](#-대시보드-화면-실행)

---

## 📌 프로젝트 개요 (Overview)

현대의 공격 에이전트 및 고도화된 침투 공격은 단일한 고위험 취약점을 직접 공략하기보다, **사소해 보이는 여러 개의 저·중위험(Low/Medium) 취약점을 수집·결합(Chaining)하여 최고 권한(Admin/System)을 장악하는 다단계 공격 경로(Attack Path)**를 활용합니다.

**WVA (Web Vulnerability Auditor)**는 이러한 공격 기법을 역으로 추적·시뮬레이션하여:
1. **복합 공격 경로(Exploit Chain)**를 정형 상태 전이 그래프(DAG) 기반으로 사전 탐지하고,
2. 방어자가 최소 비용으로 전체 공격을 원천 차단할 수 있는 **최적 차단 거점(Choke Point)**을 도출하는 지능형 보안 감사 에이전트 시스템입니다.

---

## 🖥️ 실행 대시보드 화면 (Live Dashboard)

WVA는 분석 상황을 실시간으로 관제할 수 있는 **사이버 다크모드 대시보드(FastAPI + Cytoscape.js)**를 제공합니다:

* **인터랙티브 공격 경로 그래프 (Cytoscape.js)**: 다단계 권한 상승 인과관계를 시각화하고, 노드 클릭 시 세부 패킷/증적 표출.
* **최우선 방어 거점 (Choke Point Strategy)**: 공격 체인을 끊어내기 위한 최소 비용 차단점 및 언어별 패치 코드 제공.
* **실시간 SSE 이벤트 스트림**: 에이전트의 정찰, 탐색, 카나리 분석 과정 실시간 터미널 출력.
* **식별된 공격 표면 (Endpoints Table)**: 수집된 모든 URL 경로, HTTP 메소드, 인증 요구사항 목록화.

---

## 🏛️ 시스템 아키텍처 (Architecture)

```mermaid
flowchart TB
    subgraph L1["Layer 1: Scope & Safety Governance"]
        GOV["SafetyGovernance<br/>(화이트리스트 스코프, 비파괴 카나리 프로브)"]
    end

    subgraph L2["Layer 2: Surface Discovery Engine"]
        RECON["SurfaceReconEngine<br/>(동적 엔드포인트/폼 파싱, 기술 스택)"]
        CANARY["ReflectionCanaryAuditor<br/>(안전한 카나리 반사 분석)"]
    end

    subgraph L3["Layer 3: Typed Security Blackboard"]
        BB[("SecurityBlackboard<br/>- WebAsset (엔드포인트)<br/>- SecurityState (권한/유출 아티팩트)<br/>- Findings & Chains")]
    end

    subgraph L4["Layer 4: Specialized Audit Swarm"]
        AUD_CONF["ConfigAndHeaderAuditor<br/>(CSP, HSTS, Cookie, 디버그 엔드포인트)"]
        AUD_IDOR["IdorAndBolaAuditor<br/>(BOLA / IDOR 권한 격리 검증)"]
    end

    subgraph L5["Layer 5: Chain Planner & Graph Engine"]
        APG["AttackGraphEngine (NetworkX DAG)<br/>(Pre/Post-condition 상태 전이 매핑)"]
        PLANNER["ChainPlannerAgent<br/>(권한 상승 경로 탐색 & 초크 포인트 도출)"]
    end

    subgraph L6["Layer 6: Reporting & Remediation Engine"]
        REP["SecurityReportGenerator<br/>(Markdown, Mermaid 다이어그램, SARIF/JSON)"]
        DASH["FastAPI Live Dashboard<br/>(Cytoscape.js 인터랙티브 UI, SSE 스트림)"]
    end

    L1 --> L2
    L2 --> L3
    L3 <--> L4
    L3 <--> L5
    L5 --> L6
```

---

## 🚀 빠른 시작 (Quick Start)

### 1. Windows 원클릭 실행 (배치 파일)
* `4_WVA_대시보드_실행.bat` (영문: `START_WVA_DASHBOARD.bat`): **[강력 추천] 대시보드 서버 기동 및 웹 브라우저 자동 오픈 (`http://127.0.0.1:8787`)**
* `1_WVA_웹취약점_연계분석_데모실행.bat` (영문: `START_WVA_CHAIN_AUDITOR_DEMO.bat`): 모의 서버 구동 및 CLI 데모 분석
* `2_WVA_취약점분석_CLI_직접실행.bat` (영문: `RUN_WVA_SCANNER_CLI.bat`): 대화형 CLI 메뉴

### 2. CLI 명령어 실행
```bash
# 대시보드 웹 서버 실행 (포트 8787)
python -m dashboard.server

# 모의 타깃 자동 연계 데모 실행 (CLI)
python cli.py --demo

# 사용자 지정 웹 애플리케이션 진단
python cli.py --target http://localhost:8080
```

---

## 📂 프로젝트 구조 (Directory Structure)

```text
WVA/
├── 4_WVA_대시보드_실행.bat             # [추천] 대시보드 웹 서버 실행 및 브라우저 오픈
├── START_WVA_DASHBOARD.bat              # 영문 동등 실행 파일
├── 1_WVA_웹취약점_연계분석_데모실행.bat     # 모의 취약점 타깃 자동 구동 및 연계 분석 데모
├── START_WVA_CHAIN_AUDITOR_DEMO.bat     # 영문 동등 실행 파일
├── 2_WVA_취약점분석_CLI_직접실행.bat       # 대화형 CLI 메뉴
├── RUN_WVA_SCANNER_CLI.bat              # 영문 동등 실행 파일
│
├── dashboard/                           # WVA 실행 대시보드 패키지
│   ├── server.py                        # FastAPI 대시보드 백엔드 (SSE 스트림 & REST API)
│   └── static/
│       └── index.html                   # 사이버 다크모드 웹 UI (Cytoscape.js 인터랙티브 그래프)
│
├── WVA_설계계획서_최종본.md               # 시스템 최종 설계 계획서
├── WVA_취약점분석_결과보고서_초안.md      # 취약점 연계 분석 결과보고서 초안
├── WVA_사용설명서.txt                     # 사용자 매뉴얼
│
├── cli.py                               # CLI 진입점 및 데모 오케스트레이터
├── mock_target.py                       # 연계 취약점 검증용 모의 테스트베드 앱 (FastAPI)
├── requirements.txt                     # 의존성 패키지 목록
│
├── core/
│   ├── models/                          # Asset, SecurityState, Vulnerability, ExploitChain 모델
│   ├── graph/                           # AttackGraphEngine (NetworkX DAG), SecurityBlackboard
│   └── safety/                          # SafetyGovernance (화이트리스트 스코프, 비파괴 정책)
│
├── surface/                             # SurfaceReconEngine (자산/엔드포인트), ReflectionCanaryAuditor
├── agents/                              # ConfigAuditor, IdorAuditor, ChainPlanner, AnalysisEngine
└── reporting/                           # Markdown (Mermaid 포함) 및 JSON 리포트 생성기
```

---

## 🛡️ 안전성 및 보안 윤리 (Safety & Disclaimer)

* 본 도구는 **사전 인가된 환경에서의 정당한 보안 감사 및 방어 목적**으로 설계되었습니다.
* `SafetyGovernance` 모듈을 통해 파괴적 행위(`DROP`, `DELETE` 등) 및 스코프 외부 도메인에 대한 접근을 원천 차단합니다.
* 승인되지 않은 외부 시스템에 대한 무단 진단 및 악의적 사용은 법률에 의해 엄격히 금지됩니다.
