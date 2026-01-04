import base64
import re
import string

class Mayajaal:
    def __init__(self):
        pass

    def try_decode_base64(self, text):
        """
        Attempts to decode a string as Base64.
        """
        try:
            # Add padding if needed
            missing_padding = len(text) % 4
            if missing_padding:
                text += '=' * (4 - missing_padding)
            
            decoded = base64.b64decode(text).decode('utf-8', 'ignore')
            # If the result looks like garbage, ignore it
            # Stricter check: Must be 90% printable and have no weird control chars or excessive symbols
            printable_ratio = sum(c in string.printable and c not in string.whitespace for c in decoded) / len(decoded) if decoded else 0
            
            # Common garbage often has high printable count but is just symbols.
            # We enforce a higher threshold and check for common words or structure in v2
            if printable_ratio > 0.95 and len(decoded) > 10:
                return decoded
        except:
            pass
        return None

    def xor_bruteforce(self, data_bytes):
        """
        Tries single-byte XOR keys (0-255) to see if 'http' or 'program' appears.
        This is slow, so we only scan the first 1KB.
        """
        candidates = []
        sample = data_bytes[:1024] 
        
        common_keywords = [b"http", b"program", b"function", b"system32", b"powershell"]
        
        for key in range(1, 256):
            decoded = bytes([b ^ key for b in sample])
            for word in common_keywords:
                if word in decoded:
                    candidates.append({
                        "key": hex(key),
                        "snippet": decoded[:50].decode('utf-8', 'ignore')
                    })
                    break # Found a match for this key, move to next
        return candidates

    def lift_curse(self, file_path):
        """
        Analyzes file for obfuscated content.
        """
        report = {
            "xor_detected": [],
            "base64_payloads": []
        }
        
        try:
            with open(file_path, "rb") as f:
                raw_data = f.read()
                
            # 1. Bruteforce XOR
            report["xor_detected"] = self.xor_bruteforce(raw_data)
            
            # 2. Base64 Hunting
            # Find long strings that look like base64
            # Pattern: Alphanumeric + +/ = , length > 20
            b64_pattern = b'[A-Za-z0-9+/]{20,}={0,2}'
            matches = re.findall(b64_pattern, raw_data)
            
            for m in matches[:5]: # Check first 5 matches only
                decoded = self.try_decode_base64(m.decode())
                if decoded:
                    report["base64_payloads"].append(decoded[:100] + "...") # Preview
                    
        except Exception:
            pass
            
        return report
