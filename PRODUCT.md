# WVA
<!-- impeccable:product-schema 1 -->

## Platform
web

## Users
직접 입력한 웹 대상의 취약점과 연계 경로를 확인하는 사용자. 사용자 답변에 따라 직접 대상 진단을 기본 작업으로 한다.

## Product Purpose
기존 Python 분석 엔진을 Windows 실행파일과 로컬 대시보드로 제공한다. 발견 항목, 증거, 연계 경로, 권고 조치를 확인하고 선택한 정보를 Markdown·JSON·CSV로 저장한다. 진단 로그는 개별 JSONL 파일에 보존한다.

## Operating Context
Windows에서 실행파일을 열어 로컬 브라우저를 사용한다. 별도 테스트 폴더와 로컬 실습 대상, 순서별 테스트 설명, 예상 결과와 실제 결과가 필요하다.

## Capabilities and Constraints
FastAPI, httpx, NetworkX, Pydantic 기반 기존 코드. 정해진 경로와 휴리스틱으로 헤더·정보 노출·객체 접근·관리자 접근을 점검한다. 전체 웹 취약점 검증 제품이나 정식 SARIF 구현으로 표현하지 않는다. 테스트 결과와 운영 환경 검증을 구분한다.

## Brand Commitments
사용자가 지정한 어두운 분위기, 흰색 글씨, 청록색 선. 깔끔하고 가독성 있게 필요한 정보만 노출한다. Impeccable 및 테이스트스킬 사용.

## Evidence on Hand
agents/, core/, surface/, reporting/, mock_target.py 및 기존 대시보드 코드. 실제 결과는 실행 중 생성하며 가상의 통계를 넣지 않는다.

## Product Principles
- 대상 입력과 진단 시작을 가장 쉽게 찾게 한다.
- 요약에서 증거와 수정 권고로 연결한다.
- 빈 결과, 중단, 오류, 분석 완료를 명확히 구분한다.
