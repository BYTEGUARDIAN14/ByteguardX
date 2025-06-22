class FixGenerator:
    def __init__(self):
        pass

    def generate_fixes(self, scan_results):
        fixes = []
        for item in scan_results:
            # Mock fix and explanation
            fixed_code = f"# FIXED: {item.get('original_code', '')}"
            explanation = f"This is a mock fix for {item['issue_type']} at line {item['line']} in {item['file']}."
            fixes.append({
                "file": item["file"],
                "line": item["line"],
                "issue_type": item["issue_type"],
                "fixed_code": fixed_code,
                "explanation": explanation
            })
        return fixes 