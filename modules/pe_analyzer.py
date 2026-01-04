import pefile
import math

class Kundli:
    def __init__(self):
        pass

    def calculate_entropy(self, data):
        """
        Calculates the Shannon entropy of a byte array.
        Returns a float between 0 and 8.
        > 7.5 usually means packed/encrypted.
        """
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def analyze_pe(self, file_path):
        """
        Analyzes a Windows PE file (EXE/DLL).
        """
        try:
            pe = pefile.PE(file_path)
        except pefile.PEFormatError:
            return None # Not a PE file

        report = {
            "is_pe": True,
            "suspicious_sections": [],
            "imports": [],
            "dosha_score": 0 # Entropy score
        }

        try:
            # Check Sections for High Entropy (Packing)
            for section in pe.sections:
                entropy = self.calculate_entropy(section.get_data())
                if entropy > 7.4:
                    report["suspicious_sections"].append({
                        "name": section.Name.decode('utf-8', 'ignore').strip(),
                        "entropy": entropy,
                        "warning": "High Entropy (Possible Packer/Encryption)"
                    })
                    report["dosha_score"] += 20

            # Check Imports for Networking/Dangerous API
            dangerous_functions = ["CreateRemoteThread", "VirtualAlloc", "ShellExecute", "URLDownloadToFile", "WSAStartup"]
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', 'ignore')
                            if any(danger in func_name for danger in dangerous_functions):
                                report["imports"].append(func_name)
                                report["dosha_score"] += 10
        finally:
            pe.close() # CRITICAL: Release file handle
        
        return report
