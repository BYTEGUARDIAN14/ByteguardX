import os
import re
import json
import math

class SecretScanner:
    def __init__(self, pattern_path="offline_db/secret_patterns.json", entropy_threshold=4.5):
        with open(pattern_path, "r", encoding="utf-8") as f:
            self.patterns = json.load(f)["patterns"]
        self.entropy_threshold = entropy_threshold

    def _calculate_shannon_entropy(self, data):
        if not data:
            return 0
        entropy = 0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            entropy -= p_x * math.log2(p_x)
        return entropy

    def scan_file(self, file_path):
        results = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f, 1):
                    # Regex-based detection
                    for pattern in self.patterns:
                        match = re.search(pattern["regex"], line)
                        if match:
                            results.append({
                                "file": file_path,
                                "line": i,
                                "type": pattern["name"],
                                "risk": pattern["risk"],
                                "value": match.group(0)
                            })
                    # Entropy-based detection
                    tokens = re.findall(r"[A-Za-z0-9/+=@!#$%^&*()_\-]{16,}", line)
                    for token in tokens:
                        entropy = self._calculate_shannon_entropy(token)
                        if entropy >= self.entropy_threshold:
                            results.append({
                                "file": file_path,
                                "line": i,
                                "type": "High-entropy string",
                                "risk": "medium",
                                "value": token
                            })
        except Exception as e:
            pass  # Optionally log error
        return results

    def scan_folder(self, folder_path):
        findings = []
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                findings.extend(self.scan_file(file_path))
        return findings 