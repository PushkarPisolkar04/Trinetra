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
        
        try:
            # We read the start of the file to guess its type
            mime_type = self.magic.from_file(file_path)
            ext = os.path.splitext(file_path)[1].lower()
            
            # Special check for APK (often identified as ZIP)
            if ext == ".apk" or mime_type in ["application/zip", "application/java-archive"]:
                import zipfile
                if zipfile.is_zipfile(file_path):
                    with zipfile.ZipFile(file_path, 'r') as z:
                        if 'AndroidManifest.xml' in z.namelist():
                            return "application/vnd.android.package-archive"
            
            return mime_type
        except Exception as e:
            return f"Unknown (Error: {str(e)})"
