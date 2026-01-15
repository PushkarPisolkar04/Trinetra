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
            file_size = os.path.getsize(file_path)
            if file_size == 0: return report

            with open(file_path, "rb") as f:
                marker = None
                if "jpeg" in file_type or "jpg" in file_type:
                    marker = self.eof_markers["jpg"]
                elif "png" in file_type:
                    marker = self.eof_markers["png"]
                
                if marker:
                    # Only read the last 1MB for marker search (saves RAM)
                    chunk_size = min(file_size, 1024 * 1024) 
                    f.seek(file_size - chunk_size)
                    data_tail = f.read()
                    
                    # Find the LAST occurrence of the marker in the tail
                    eof_location_in_tail = data_tail.rfind(marker)
                    if eof_location_in_tail != -1:
                        # Convert tail location to absolute file location
                        eof_location = (file_size - chunk_size) + eof_location_in_tail
                        expected_end = eof_location + len(marker)
                        
                        if file_size > expected_end:
                            extra_bytes = file_size - expected_end
                            if extra_bytes > 100: # Ignore tiny artifacts
                               report["has_hidden_data"] = True
                               report["hidden_size"] = extra_bytes
                               report["stego_suspicion"] = "High (Appended Data Detected)"

        except Exception as e:
            return report # Fail silently on read errors
            
        return report
