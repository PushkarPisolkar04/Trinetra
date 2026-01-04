import os

class Drishti:
    def __init__(self):
        # Common EOF markers
        self.eof_markers = {
            "jpg": b'\xFF\xD9',
            "png": b'\x49\x45\x4E\x44\xAE\x42\x60\x82', # IEND chunk
            "gif": b'\x00\x3B'
        }

    def analyze_image(self, file_path, file_type):
        """
        Checks if an image has a secret payload hidden at the end.
        """
        report = {
            "has_hidden_data": False,
            "hidden_size": 0,
            "stego_suspicion": "Low"
        }
        
        # 1. Overlay / Appended Data Check
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            marker = None
            if "jpeg" in file_type or "jpg" in file_type:
                marker = self.eof_markers["jpg"]
            elif "png" in file_type:
                marker = self.eof_markers["png"]
            
            if marker:
                # Find the LAST occurrence of the marker
                eof_location = data.rfind(marker)
                if eof_location != -1:
                    # The file should end right after the marker
                    expected_end = eof_location + len(marker)
                    real_size = len(data)
                    
                    if real_size > expected_end:
                        extra_bytes = real_size - expected_end
                        if extra_bytes > 100: # Ignore tiny artifacts
                           report["has_hidden_data"] = True
                           report["hidden_size"] = extra_bytes
                           report["stego_suspicion"] = "High (Appended Data Detected)"

        except Exception as e:
            return report # Fail silently on read errors
            
        return report
