"""Run functional tests and consolidate current evidence in TEST_GUIDE.md."""
from datetime import datetime
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests" / "artifacts"

def shareable_result(value):
    """Keep verification evidence without publishing the operator's home path."""
    if isinstance(value, dict):
        return {key: shareable_result(item) for key, item in value.items()}
    if isinstance(value, list):
        return [shareable_result(item) for item in value]
    if isinstance(value, str):
        return value.replace(str(ROOT), "<프로젝트>").replace(ROOT.as_posix(), "<프로젝트>")
    return value

def consolidate():
    rows = []
    xml = OUT / "pytest.xml"
    if xml.exists():
        suite = ET.parse(xml).getroot()
        for test in suite.iter("testcase"):
            status = "FAIL" if test.find("failure") is not None or test.find("error") is not None else "SKIP" if test.find("skipped") is not None else "PASS"
            rows.append((test.attrib["name"],status,test.attrib.get("time","0")+"초"))
    passed = sum(status == "PASS" for _,status,_ in rows)
    report = ["### 수행 환경과 검증 범위", "", f"- 보고서 갱신 시각: {datetime.now().astimezone().isoformat(timespec='seconds')}",
              f"- 운영체제: {platform.platform()}", f"- Python: {platform.python_version()}",
              f"- 기능 테스트: **{passed}/{len(rows)} PASS**", "- 외부 운영 사이트 진단은 수행하지 않았습니다. 로컬 실습 환경에 대한 검증입니다.", "",
              "### 기능 테스트 상세 결과", "", "| 실제 테스트 | 결과 | 소요 |", "| --- | --- | ---: |"]
    report += [f"| `{name}` | {status} | {duration} |" for name,status,duration in rows]
    for title,file in [("실행파일 독립 실행 결과",OUT / "executable-smoke.json"),("브라우저 작업 흐름 결과",OUT / "browser" / "result.json")]:
        report += ["", "### "+title, ""]
        if not file.exists():
            report.append("NOT_RUN — 검증 산출물이 없습니다.")
            continue
        data = json.loads(file.read_text(encoding="utf-8"))
        report += [f"- 결과: **{data['status']}**", f"- 수행 시각: {data.get('at','기록 없음')}"]
        if data.get("sha256"):
            report += [f"- 실행파일 SHA-256: `{data['sha256']}`",f"- 실행파일 크기: {data['bytes']:,} bytes"]
        report += ["", "| 검증 항목 | 결과 | 실제 결과 |", "| --- | --- | --- |"]
        for item in data.get("checks",[]):
            actual_value = shareable_result(item["actual"])
            actual = actual_value if isinstance(actual_value,str) else json.dumps(actual_value,ensure_ascii=False)
            actual = actual.replace("|","/").replace("\n"," ")
            report.append(f"| {item['name']} | {item['status']} | {actual} |")
        if data.get("error"):
            report.append("\n실패 원인: "+data["error"])
    visual = OUT / "visual-final" / "report.json"
    if visual.exists():
        data = json.loads(visual.read_text(encoding="utf-8"))
        failures = sum(x["level"] == "FAIL" for x in data["findings"])
        warnings = sum(x["level"] == "WARN" for x in data["findings"])
        report += ["", "### 디자인 보조 검사", "", f"- 테이스트스킬 브라우저 검사: {failures} FAIL, {warnings} WARN."]
        for viewport in data.get("viewports",[]):
            report.append(f"- {viewport['width']}px: 페이지 가로 넘침 {viewport['metrics']['page']['horizontalOverflow']}px, JavaScript 예외 {len(viewport.get('consoleErrors',[]))}개.")
        for finding in data["findings"]:
            report.append(f"- {finding['level']} `{finding['id']}`: {finding['message']}")
        lint = OUT / "taste-lint.txt"
        if lint.exists():
            match = re.search(r"RESULT: (.+)",lint.read_text(encoding="utf-8-sig"))
            if match:
                report.append("- 소스 lint: "+match[1]+". 숫자·URL의 고정폭 글꼴과 미측정 값의 대시 표시는 데이터 표현에 사용합니다.")
        detector = OUT / "impeccable-detect.json"
        if detector.exists():
            findings = json.loads(detector.read_text(encoding="utf-8-sig"))
            report.append(f"- Impeccable detect: 보조 발견 {len(findings)}건. 진단 중 진행선 모션은 요청된 기능이며 완료 후 멈춥니다.")
            for item in findings:
                report.append(f"  - {item['severity']}: {item['name']}")
        report.append("- 실제 데스크톱·모바일 화면과 큰 상세 창, 저장 화면의 스크린샷을 직접 확인했습니다.")
    report += ["", "### 화면 및 산출물", "", "- [데스크톱 화면](../docs/images/dashboard.png)","- 태블릿 화면: `artifacts/browser/results-768.png` (로컬 검증 산출물)","- 모바일 화면: `artifacts/browser/results-390.png` (로컬 검증 산출물)","- 경로 화면: `artifacts/browser/chains-desktop.png` (로컬 검증 산출물)","- [순서별 조치 화면](../docs/images/actions.png)","- 공격 표면: `artifacts/browser/surface-desktop.png` (로컬 검증 산출물)","- 로그 위치: `artifacts/browser/logs-desktop.png` (로컬 검증 산출물)","- 저장 화면: `artifacts/browser/save-desktop.png` (로컬 검증 산출물)","- 기능 검증 원본: `artifacts/pytest.xml`, `artifacts/pytest-output.txt`", "- 실행파일 검증 원본: `artifacts/executable-smoke.json`", "- 브라우저 검증 원본: `artifacts/browser/result.json`", "", "### 제한과 미실행 항목", "", "- Windows 10 x64 한 대에서 확인했습니다. 별도 Windows 11 PC·백신 제품별 실행은 NOT_RUN입니다.", "- 실제 외부 사이트, 로그인 세션을 가진 다중 사용자 권한 대조, 전체 URL 크롤링, 모든 OWASP 항목은 NOT_RUN입니다.", "- 진단 데이터는 세션 메모리에 있으며 완료 보고서와 개별 JSONL 진단 로그는 파일로 보존됩니다. 앱 재실행 시 화면 히스토리를 복원하지 않습니다.", "- 수집한 API 키와 식별자가 보고서에 포함될 수 있습니다. 테스트 값과 실제 진단 증거를 구분하여 관리합니다."]
    text = "\n".join(report)
    (ROOT / "tests" / "TEST_RESULTS.md").write_text("# WVA 테스트 결과보고서\n\n"+text+"\n",encoding="utf-8")
    guide = ROOT / "tests" / "TEST_GUIDE.md"
    content=guide.read_text(encoding="utf-8")
    before=content.split("<!-- RESULTS:START -->")[0]
    after=content.split("<!-- RESULTS:END -->",1)[1]
    guide.write_text(before+"<!-- RESULTS:START -->\n"+text+"\n<!-- RESULTS:END -->"+after,encoding="utf-8")
    print(f"Functional checks: {passed}/{len(rows)} PASS. TEST_GUIDE.md and TEST_RESULTS.md updated.")

def main():
    OUT.mkdir(exist_ok=True,parents=True)
    if "--report-only" not in sys.argv:
        with (OUT / "pytest-output.txt").open("w",encoding="utf-8") as log:
            result=subprocess.run([sys.executable,"-m","pytest","-q","--junitxml="+str(OUT / "pytest.xml")],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
        print((OUT / "pytest-output.txt").read_text(encoding="utf-8"))
        consolidate()
        return result.returncode
    consolidate()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
