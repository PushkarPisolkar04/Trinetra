import magic
import os

class Gatekeeper:
    def __init__(self):
        self.magic = magic.Magic(mime=True)

    def identify(self, file_path):
        """
        Identifies the file type based on magic bytes (not extension).
        """
        if not os.path.exists(file_path):
            return "Error: File not found"
        
            # Special check for Executables (MIME can vary between OS)
            if any(x in mime_type for x in ["dosexec", "portable-executable", "x-executable", "application/x-msdos-program"]):
                return "application/x-dosexec"
            
            # Special check for APK (often identified as ZIP)
            if ext == ".apk" or mime_type in ["application/zip", "application/java-archive", "application/octet-stream"]:
                import zipfile
                if zipfile.is_zipfile(file_path):
                    with zipfile.ZipFile(file_path, 'r') as z:
                        if 'AndroidManifest.xml' in z.namelist():
                            return "application/vnd.android.package-archive"
            
            return mime_type
        except Exception as e:
            return f"Unknown (Error: {str(e)})"
