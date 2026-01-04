import yara
import os

class YaraScanner:
    """
    Scans files using YARA rules for malware pattern matching.
    Detects specific malware families and techniques.
    """
    
    def __init__(self, rules_path="data/yara_rules"):
        self.rules_path = rules_path
        self.rules = None
        self.load_rules()
    
    def load_rules(self):
        """
        Loads all .yar files from the rules directory.
        """
        try:
            rule_files = {}
            if os.path.exists(self.rules_path):
                for filename in os.listdir(self.rules_path):
                    if filename.endswith('.yar'):
                        filepath = os.path.join(self.rules_path, filename)
                        rule_files[filename] = filepath
            
            if rule_files:
                self.rules = yara.compile(filepaths=rule_files)
            else:
                self.rules = None
                
        except Exception as e:
            print(f"YARA rules loading error: {e}")
            self.rules = None
    
    def scan_file(self, file_path):
        """
        Scans a file against loaded YARA rules.
        Returns list of matched rules with metadata.
        """
        if not self.rules:
            return {
                "available": False,
                "message": "YARA rules not loaded"
            }
        
        try:
            matches = self.rules.match(file_path, timeout=30)
            
            if matches:
                detections = []
                for match in matches:
                    detection = {
                        "rule_name": match.rule,
                        "severity": match.meta.get("severity", "UNKNOWN"),
                        "description": match.meta.get("description", "No description"),
                        "matched_strings": [str(s) for s in match.strings[:5]]  # Limit to 5
                    }
                    detections.append(detection)
                
                return {
                    "available": True,
                    "matches_found": len(detections),
                    "detections": detections,
                    "verdict": "MALICIOUS" if any(d["severity"] == "CRITICAL" for d in detections) else "SUSPICIOUS"
                }
            else:
                return {
                    "available": True,
                    "matches_found": 0,
                    "detections": [],
                    "verdict": "CLEAN"
                }
                
        except Exception as e:
            return {
                "available": False,
                "message": f"Scan error: {str(e)}"
            }
