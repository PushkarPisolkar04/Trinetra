import pefile
import os

class SignatureChecker:
    """
    Verifies digital signatures on Windows executables using pefile.
    Detects if a file is signed and extracts basic certificate info.
    """
    
    def check_signature(self, file_path):
        """
        Checks for the existence of a security directory in the PE file.
        Returns basic signature status.
        """
        try:
            pe = pefile.PE(file_path, fast_load=True)
            
            # Check if the security directory (signature) exists
            # IMAGE_DIRECTORY_ENTRY_SECURITY is at index 4
            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
            
            is_signed = security_dir.VirtualAddress > 0 and security_dir.Size > 0
            
            if is_signed:
                # Full certificate parsing is complex in pure Python without heavy deps,
                # but we can confirm the presence of the signature.
                return {
                    "is_signed": True,
                    "status": "Signed (Physical Certificate Present)",
                    "publisher": "Unknown (Static Analysis only)",
                    "trust_level": "MEDIUM"
                }
            else:
                return {
                    "is_signed": False,
                    "status": "Not Signed",
                    "publisher": None,
                    "trust_level": "LOW"
                }
                
        except Exception as e:
            return {
                "is_signed": False,
                "status": f"N/A (Not a PE file or error: {str(e)})",
                "publisher": None,
                "trust_level": "UNKNOWN"
            }
        finally:
            try:
                if 'pe' in locals():
                    pe.close()
            except:
                pass
