import subprocess
import re

class SignatureChecker:
    """
    Verifies digital signatures on Windows executables.
    Signed files from known publishers are likely legitimate.
    """
    
    def check_signature(self, file_path):
        """
        Uses PowerShell's Get-AuthenticodeSignature to verify code signing.
        Returns publisher info if signed, None otherwise.
        """
        try:
            # Run PowerShell command to check signature
            cmd = f'powershell -Command "Get-AuthenticodeSignature \'{file_path}\' | Select-Object Status, SignerCertificate"'
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5, shell=True)
            
            output = result.stdout
            
            # Parse the output
            if "Valid" in output:
                # Extract publisher name from certificate
                cert_match = re.search(r'CN=([^,]+)', output)
                publisher = cert_match.group(1) if cert_match else "Unknown Publisher"
                
                return {
                    "is_signed": True,
                    "status": "Valid",
                    "publisher": publisher,
                    "trust_level": "HIGH" if any(trusted in publisher.lower() for trusted in 
                        ["microsoft", "valve", "epic games", "ubisoft", "ea", "riot", "blizzard", "pocketpair"]) else "MEDIUM"
                }
            elif "NotSigned" in output:
                return {
                    "is_signed": False,
                    "status": "Not Signed",
                    "publisher": None,
                    "trust_level": "LOW"
                }
            else:
                # Invalid or tampered signature
                return {
                    "is_signed": True,
                    "status": "Invalid/Tampered",
                    "publisher": None,
                    "trust_level": "CRITICAL"
                }
                
        except Exception as e:
            return {
                "is_signed": False,
                "status": f"Error: {str(e)}",
                "publisher": None,
                "trust_level": "UNKNOWN"
            }
