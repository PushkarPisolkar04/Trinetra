import re

class Vani:
    def __init__(self):
        # Patterns for IoCs (Indicators of Compromise)
        self.ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        self.email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

    def extract_strings(self, file_path, min_length=4):
        """
        Extracts printable strings from a binary file using regex for speed.
        Scans only the first 20MB of large files to prevent timeouts.
        """
        try:
            file_size = os.path.getsize(file_path)
            # Limit scan to 20MB for memory/speed on free tiers
            MAX_SCAN_SIZE = 20 * 1024 * 1024 
            
            with open(file_path, "rb") as f:
                if file_size > MAX_SCAN_SIZE:
                    data = f.read(MAX_SCAN_SIZE)
                else:
                    data = f.read()
            
            # Use regex for lightning-fast extraction of printable strings
            # [ -~] matches ASCII printable range (32-126)
            pattern = rb"[ -~]{" + str(min_length).encode() + rb",}"
            found_strings = [s.decode('ascii', errors='ignore') for s in re.findall(pattern, data)]
            
            return found_strings
        except Exception as e:
            return []

    def hunt_iocs(self, file_path):
        """
        Scans strings for IPs, URLs, and Emails.
        """
        strings = self.extract_strings(file_path)
        combined_text = " ".join(strings)
        
        iocs = {
            "ips": list(set(self.ipv4_pattern.findall(combined_text))),
            "urls": list(set(self.url_pattern.findall(combined_text))),
            "emails": list(set(self.email_pattern.findall(combined_text)))
        }
        return iocs
