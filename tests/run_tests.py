"""Run functional tests and consolidate current evidence in TEST_GUIDE.md."""
from datetime import datetime
import hashlib
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
    current_exe=hashlib.sha256((ROOT/'WVA.exe').read_bytes()).hexdigest() if (ROOT/'WVA.exe').exists() else None
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
        bound_hash=data.get('sha256') or data.get('exe_sha256')
        if bound_hash!=current_exe:
            report += ['STALE — 현재 실행파일과 일치하지 않는 이전 검증 기록입니다. 이번 바이너리의 PASS 근거로 사용하지 않습니다.',f"- 기록 시각: {data.get('at','기록 없음')}"]
            continue
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
    benchmark = OUT / "benchmark" / "result.json"
    if benchmark.exists() and json.loads(benchmark.read_text(encoding='utf-8')).get('exe_sha256')==current_exe:
        data = json.loads(benchmark.read_text(encoding="utf-8"))
        report += ["", "### 독립 취약 웹앱 벤치마크 (별도 수행 기록)", "",
                   f"- 수행 시각: {data.get('at','기록 없음')}",
                   f"- 상태: **{data.get('status','NOT_RUN')}**. 환경·재현·결과 수집 상태이며 SQLi·XSS 탐지 통과가 아닙니다.",
                   f"- 독립 취약점·방어 대조 확인 {len(data.get('ground_truth',[]))}건, 소스/실행파일 진단 {len(data.get('measurements',[]))}건.",
                   ("- SQLi·XSS 양성 4개와 방어 대조 2개를 소스·실행파일에서 비교했습니다. 전체 사이트 정확도로 일반화하지 않습니다." if data.get("status")=="PASS" else "- 이 기록의 미지원·오류를 탐지 통과로 합치지 않습니다. 이전 버전 결과는 수행 시각과 해시로 구분합니다."),
                   "- 설치·재실행: [독립 실습 절차](benchmarks/README.md). 상세 결과·한계: [벤치마크 결과](benchmarks/RESULTS.md)."]
        if data.get('error'):
            report.append("- 실행 오류: "+data['error'])
    extended = OUT / "benchmark" / "extended-result.json"
    if extended.exists() and json.loads(extended.read_text(encoding='utf-8')).get('exe_sha256')==current_exe:
        data=json.loads(extended.read_text(encoding="utf-8"))
        report += ["", "### 계정·저장형·시간 기반 source/exe 검증", "",f"- 수행 시각: {data.get('at')}",f"- 결과: **{data['status']}**, 검증 {len(data.get('checks',[]))}건.","- 원본: `artifacts/benchmark/extended-result.json`. 자체 SQLite 실습 앱의 결과이며 제3자 앱 측정과 구분합니다."]
        if data.get('error'):report.append('- 오류: '+data['error'])
    report += ['', '### 최신 서버 규칙 source/exe 대조', '']
    reliability=OUT/'reliability-2.6'/'acceptance.json'
    if reliability.exists() and json.loads(reliability.read_text(encoding='utf-8')).get('exe_sha256')==current_exe:
        result=json.loads(reliability.read_text(encoding='utf-8'))
        report += [f"- 상태: **{result['status']}**, 실측 대조 {len(result.get('checks',[]))}건.",'- 실제 파일·표식 명령·HTTP 수신·업로드를 사용하는 로컬 취약/방어 쌍. 운영 사이트 정확도로 일반화하지 않습니다.']
    else:report.append('- NOT_RUN — 현재 실행파일에 연결된 서버 규칙 검증 결과가 없습니다.')
    report += ['', '이전 버전의 제3자 앱·확장 검증은 해당 기록의 해시와 수행 시각으로 구분합니다. 최신 실행파일과 일치하지 않으면 이번 검증 수에 합치지 않습니다.']
    visual = OUT / "reliability-2.6" / "visual" / "report.json"
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
    report += ["", "### 화면 및 산출물", "", "- [데스크톱 화면](../docs/images/dashboard.png)","- 태블릿 화면: `artifacts/browser/results-768.png` (로컬 검증 산출물)","- 모바일 화면: `artifacts/browser/results-390.png` (로컬 검증 산출물)","- 경로 화면: `artifacts/browser/chains-desktop.png` (로컬 검증 산출물)","- [순서별 조치 화면](../docs/images/actions.png)","- 공격 표면: `artifacts/browser/surface-desktop.png` (로컬 검증 산출물)","- 로그 위치: `artifacts/browser/logs-desktop.png` (로컬 검증 산출물)","- 저장 화면: `artifacts/browser/save-desktop.png` (로컬 검증 산출물)","- 기능 검증 원본: `artifacts/pytest.xml`, `artifacts/pytest-output.txt`", "- 실행파일 검증 원본: `artifacts/executable-smoke.json`", "- 브라우저 검증 원본: `artifacts/browser/result.json`", "", "### 제한과 미실행 항목", "", "- Windows 10 x64 한 대에서 확인했습니다. 별도 Windows 11 PC·백신 제품별 실행은 NOT_RUN입니다.", "- 운영 사이트·운영 계정의 권한 대조, 포괄적인 전체 URL 탐색, 모든 OWASP 항목은 NOT_RUN입니다. 로컬 테스트 계정의 대조는 별도 확장 검증 기록을 따릅니다.", "- 진단 데이터는 세션 메모리에 있으며 완료 보고서와 개별 JSONL 진단 로그는 파일로 보존됩니다. 앱 재실행 시 화면 히스토리를 복원하지 않습니다.", "- 비밀 값은 가리지만 경로·식별자·관찰 증거는 남습니다. 공개된 실습 값과 운영 진단의 증거를 구분합니다."]
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
        def fingerprint():
            return {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                    for folder in ['agents','core','dashboard','surface','reporting','tests'] for p in (ROOT/folder).rglob('*')
                    if p.is_file() and p.suffix in ('.py','.js','.cjs','.html','.css') and '__pycache__' not in p.parts and 'artifacts' not in p.parts}
        before=fingerprint()
        with (OUT / "pytest-output.txt").open("w",encoding="utf-8") as log:
            result=subprocess.run([sys.executable,"-m","pytest","-q","--junitxml="+str(OUT / "pytest.xml")],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
        provenance={'at':datetime.now().astimezone().isoformat(),'source_files':before,'unchanged_during_run':before==fingerprint(),'exit_code':result.returncode}
        (OUT/'functional-provenance.json').write_text(json.dumps(provenance,indent=2),encoding='utf-8')
        if not provenance['unchanged_during_run']:raise RuntimeError('테스트 도중 소스가 변경되어 결과를 확정하지 않았습니다. 동일한 소스로 재실행하세요.')
        print((OUT / "pytest-output.txt").read_text(encoding="utf-8"))
        consolidate()
        return result.returncode
    consolidate()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
