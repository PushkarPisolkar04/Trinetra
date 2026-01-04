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
            file_type = self.magic.from_file(file_path)
            return file_type
        except Exception as e:
            return f"Unknown (Error: {str(e)})"
