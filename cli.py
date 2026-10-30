import asyncio
import sys
import argparse
import time
import subprocess
from agents.engine import VulnerabilityAnalysisEngine
from reporting.report_generator import SecurityReportGenerator

def run_demo():
    print("=" * 70)
    print("   [WVA] Web Vulnerability & Attack Path Chaining Agent (Demo)")
    print("=" * 70)
    print("[*] Launching local vulnerable testbed server (mock_target.py on port 8989)...")
    
    server_process = subprocess.Popen(
        [sys.executable, "mock_target.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    time.sleep(1.5)  # Wait for server to bind

    target_url = "http://127.0.0.1:8989"
    try:
        print(f"[*] Target is up at: {target_url}")
        print("[*] Initializing WVA Multi-Agent Analysis Pipeline...")
        
        engine = VulnerabilityAnalysisEngine(target_url)
        blackboard = asyncio.run(engine.execute_audit())

        # Generate Reports
        reporter = SecurityReportGenerator(blackboard)
        md_report = reporter.generate_markdown_report()
        json_report = reporter.generate_json_report()

        with open("WVA_vulnerability_report.md", "w", encoding="utf-8") as f:
            f.write(md_report)

        import json
        with open("WVA_vulnerability_report.json", "w", encoding="utf-8") as f:
            json.dump(json_report, f, indent=2, ensure_ascii=False)

        print("\n" + "=" * 70)
        print("               [WVA] AUDIT SUMMARY & CHAINING RESULTS")
        print("=" * 70)
        print(f"Discovered Endpoints : {len(blackboard.asset.endpoints)}")
        print(f"Individual Findings  : {len(blackboard.findings)}")
        print(f"Exploit Chains Found : {len(blackboard.chains)}")
        print("=" * 70)

        if blackboard.chains:
            print("\n>>> [CRITICAL] MULTI-STEP ATTACK CHAINS DISCOVERED <<<")
            for c in blackboard.chains:
                print(f"\n[Chain ID: {c.chain_id}] {c.title}")
                print(f"Severity: {c.cumulative_severity.value}")
                print(f"Privilege Escalation: {c.initial_privilege.value} -> {c.attained_privilege.value}")
                print("Steps:")
                for s in c.steps:
                    f = blackboard.findings.get(s.finding_id)
                    title = f.title if f else s.finding_id
                    print(f"  [{s.step_number}] {title} (Target: {f.endpoint if f else 'N/A'})")
                print("\n[Defense Choke Points]:")
                for cp in c.choke_points:
                    print(f"  * Step {cp.step_number} Choke Point: {cp.target_endpoint} -> {cp.recommended_patch}")

        print("\n[+] Full reports successfully saved to:")
        print("    - WVA_vulnerability_report.md (Markdown + Mermaid Diagram)")
        print("    - WVA_vulnerability_report.json (Structured SARIF/JSON)")
        print("=" * 70)

    finally:
        print("[*] Terminating local testbed server...")
        server_process.terminate()
        server_process.wait()
        print("[*] Done.")

def run_scan(target_url: str):
    print("=" * 70)
    print(f"   [WVA] Scanning Target URL: {target_url}")
    print("=" * 70)
    engine = VulnerabilityAnalysisEngine(target_url)
    blackboard = asyncio.run(engine.execute_audit())

    reporter = SecurityReportGenerator(blackboard)
    md_report = reporter.generate_markdown_report()

    with open("WVA_vulnerability_report.md", "w", encoding="utf-8") as f:
        f.write(md_report)

    print(f"\n[+] Scan complete. Total findings: {len(blackboard.findings)}, Chains: {len(blackboard.chains)}")
    print("[+] Report saved to WVA_vulnerability_report.md")

def main():
    parser = argparse.ArgumentParser(description="WVA - Web Vulnerability & Attack Path Chaining Agent")
    parser.add_argument("--target", type=str, help="Target URL to audit (e.g. http://localhost:8080)")
    parser.add_argument("--demo", action="store_true", help="Run self-contained demo using mock target")
    args = parser.parse_args()

    if args.demo:
        run_demo()
    elif args.target:
        run_scan(args.target)
    else:
        print("=" * 65)
        print("   [WVA] Web Vulnerability & Attack Path Chaining Agent CLI")
        print("=" * 65)
        print("1. Run Demo (Vulnerable Mock App Simulation & Chain Analysis)")
        print("2. Audit Custom Target URL")
        print("3. Exit")
        print("=" * 65)
        choice = input("Select an option [1-3]: ").strip()
        if choice == "1":
            run_demo()
        elif choice == "2":
            target = input("Enter target URL (e.g. http://127.0.0.1:8000): ").strip()
            if target:
                run_scan(target)
            else:
                print("Error: Target URL cannot be empty.")
        else:
            print("Exiting.")

if __name__ == "__main__":
    main()
