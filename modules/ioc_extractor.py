import re

class Vani:
    def __init__(self):
        # Patterns for IoCs (Indicators of Compromise)
        self.ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        self.email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

    def extract_strings(self, file_path, min_length=4):
        """
        Extracts printable strings from a binary file using a memory-efficient chunked approach.
        """
        found_strings = []
        try:
            pattern = b"[ -~]{" + str(min_length).encode() + b",}"
            with open(file_path, "rb") as f:
                # Read in chunks to avoid memory spikes
                chunk_size = 10 * 1024 * 1024 # 10MB chunks
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    # Find all ASCII strings in the chunk
                    for match in re.finditer(pattern, chunk):
                        found_strings.append(match.group().decode('ascii', errors='ignore'))
                    
                    # Prevent found_strings from growing too large for RAM
                    if len(found_strings) > 20000:
                        break
        except Exception as e:
            pass
            
        return found_strings

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
