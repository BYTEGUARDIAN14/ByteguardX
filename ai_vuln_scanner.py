import ast
import re
import json

class AIVulnScanner:
    def __init__(self, pattern_path="offline_db/ai_insecure_patterns.json"):
        with open(pattern_path, "r", encoding="utf-8") as f:
            self.patterns = json.load(f)["patterns"]

    def scan_file(self, file_path):
        results = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            # Regex-based patterns
            for pattern in self.patterns:
                if pattern["pattern"] in ["missing_try_except", "unvalidated_input"]:
                    continue
                for match in re.finditer(pattern["pattern"], code):
                    line = code[:match.start()].count("\n") + 1
                    results.append({
                        "file": file_path,
                        "line": line,
                        "issue_type": pattern["name"],
                        "severity": pattern["severity"],
                        "unsafe_code": match.group(0)
                    })
            # AST-based patterns
            tree = ast.parse(code, filename=file_path)
            # Detect missing try-except (functions with no try)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    has_try = any(isinstance(n, ast.Try) for n in ast.walk(node))
                    if not has_try:
                        results.append({
                            "file": file_path,
                            "line": node.lineno,
                            "issue_type": "Missing try-except",
                            "severity": "medium",
                            "unsafe_code": f"def {node.name}(...): ..."
                        })
            # Detect unvalidated input (input() used without validation)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and getattr(node.func, 'id', None) == 'input':
                    parent = node
                    validated = False
                    # Check if input() is wrapped in int(), float(), etc.
                    if isinstance(getattr(parent, 'parent', None), ast.Call):
                        validated = True
                    if not validated:
                        results.append({
                            "file": file_path,
                            "line": node.lineno,
                            "issue_type": "Unvalidated input",
                            "severity": "high",
                            "unsafe_code": ast.get_source_segment(code, node) or "input()"
                        })
        except Exception:
            pass
        return results

# Patch AST nodes to have parent references
for node in ast.iter_child_nodes:
    for child in ast.iter_child_nodes(node):
        child.parent = node 