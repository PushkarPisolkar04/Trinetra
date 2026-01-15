import re

class Vani:
    def __init__(self):
        # Patterns for IoCs (Indicators of Compromise)
        self.ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        self.email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

    def extract_strings(self, file_path, min_length=4):
        """
        Extracts printable strings from a binary file.
        Similar to the 'strings' command in Linux.
        """
        data = None
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            return []  # Return empty list if file can't be read
        
        # ASCII printable chars
        result = ""
        found_strings = []
        for byte in data:
            char = chr(byte)
            if 32 <= byte <= 126: # Printable range
                result += char
            else:
                if len(result) >= min_length:
                    found_strings.append(result)
                result = ""
        
        # Don't forget the last one
        if len(result) >= min_length:
            found_strings.append(result)
            
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
