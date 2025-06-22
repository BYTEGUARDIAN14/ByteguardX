import os
import sys
import json
from secret_scanner import SecretScanner
from dependency_scanner import DependencyScanner
from ai_vuln_scanner import AIVulnScanner

class PreCommit:
    def __init__(self):
        self.log_dir = ".byteguardx"
        self.log_file = os.path.join(self.log_dir, "commit_logs.json")
        os.makedirs(self.log_dir, exist_ok=True)
        self.scanners = [
            SecretScanner(),
            DependencyScanner(),
            AIVulnScanner()
        ]

    def install_hook(self):
        hook_path = os.path.join(".git", "hooks", "pre-commit")
        script = (
            "#!/bin/sh\n"
            "python pre_commit.py run_pre_commit_check\n"
        )
        with open(hook_path, "w") as f:
            f.write(script)
        os.chmod(hook_path, 0o775)
        print("Pre-commit hook installed.")

    def run_pre_commit_check(self):
        # Get changed files
        changed = os.popen('git diff --cached --name-only').read().splitlines()
        all_findings = []
        for file in changed:
            if not os.path.isfile(file):
                continue
            for scanner in self.scanners:
                try:
                    findings = scanner.scan_file(file)
                    all_findings.extend(findings)
                except Exception:
                    pass
        # Save log
        with open(self.log_file, "a", encoding="utf-8") as f:
            for finding in all_findings:
                f.write(json.dumps(finding) + "\n")
        # Block commit if high/critical
        block = [f for f in all_findings if f.get("risk", f.get("severity", "")).lower() in ["high", "critical"]]
        if block:
            print("\n[ByteguardX] Commit blocked due to high/critical issues:")
            for b in block:
                print(f"{b.get('file')}:{b.get('line')} - {b.get('type', b.get('issue_type', ''))} [{b.get('risk', b.get('severity', ''))}]")
            sys.exit(1)
        else:
            print("[ByteguardX] No blocking issues found. Commit allowed.")

if __name__ == "__main__":
    import sys
    pc = PreCommit()
    if len(sys.argv) > 1 and sys.argv[1] == "run_pre_commit_check":
        pc.run_pre_commit_check()
    else:
        pc.install_hook() 