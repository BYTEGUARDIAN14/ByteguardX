import json
import re
import os

class DependencyScanner:
    def __init__(self, vuln_db_path="offline_db/vulnerable_packages.json"):
        with open(vuln_db_path, "r", encoding="utf-8") as f:
            self.vuln_db = json.load(f)["vulnerabilities"]

    def _parse_requirements(self, lines):
        deps = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                match = re.match(r"([a-zA-Z0-9_\-]+)==([0-9a-zA-Z\.]+)", line)
                if match:
                    deps.append((match.group(1).lower(), match.group(2)))
        return deps

    def _parse_pipfile(self, lines):
        deps = []
        for line in lines:
            match = re.match(r'\s*([a-zA-Z0-9_\-]+)\s*=\s*"([0-9a-zA-Z\.]+)"', line)
            if match:
                deps.append((match.group(1).lower(), match.group(2)))
        return deps

    def _parse_package_json(self, content):
        deps = []
        try:
            data = json.loads(content)
            for section in ["dependencies", "devDependencies"]:
                for pkg, ver in data.get(section, {}).items():
                    ver_clean = re.sub(r'[^0-9a-zA-Z\.]', '', ver)
                    deps.append((pkg.lower(), ver_clean))
        except Exception:
            pass
        return deps

    def scan_file(self, file_path):
        results = []
        ext = os.path.basename(file_path)
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                if ext == "requirements.txt":
                    deps = self._parse_requirements(f.readlines())
                elif ext == "Pipfile":
                    deps = self._parse_pipfile(f.readlines())
                elif ext == "package.json":
                    deps = self._parse_package_json(f.read())
                else:
                    return results
            for dep, ver in deps:
                for vuln in self.vuln_db:
                    if dep == vuln["package"] and ver == vuln["version"]:
                        results.append({
                            "package": dep,
                            "version": ver,
                            "cve": vuln["cve"],
                            "severity": vuln["severity"]
                        })
        except Exception:
            pass
        return results 