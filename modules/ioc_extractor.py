import re

class Vani:
    def __init__(self):
        # Patterns for IoCs (Indicators of Compromise)
        self.ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        self.email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

    def extract_strings(self, file_path, min_length=4):
        """
        Extracts printable strings from a binary file efficiently using regex.
        """
        try:
            with open(file_path, "rb") as f:
                # Use a regex that finds printable sequences directly (much faster than a loop)
                # Matches printable ASCII characters (32 to 126)
                data = f.read()
                pattern = rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}"
                found_bytes = re.findall(pattern, data)
                return [s.decode('utf-8', 'ignore') for s in found_bytes]
        except Exception as e:
            return []  # Return empty list if file can't be read or processed

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
