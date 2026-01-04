import requests
import time
import os

class VirusTotalChecker:
    """
    Checks file hashes against VirusTotal's public API.
    Requires API key (free tier: 4 requests/minute).
    """
    
    def __init__(self, api_key=None):
        # Try to load from config file, then environment variable, then default
        if api_key:
            self.api_key = api_key
        else:
            try:
                from config import VIRUSTOTAL_API_KEY
                self.api_key = VIRUSTOTAL_API_KEY
            except ImportError:
                self.api_key = os.getenv('VIRUSTOTAL_API_KEY', 'YOUR_VT_API_KEY_HERE')
        
        self.base_url = "https://www.virustotal.com/api/v3"
        
    def check_hash(self, file_hash):
        """
        Looks up a file hash (MD5/SHA256) in VirusTotal database.
        Returns detection stats and vendor verdicts.
        """
        if self.api_key == "YOUR_VT_API_KEY_HERE":
            return {
                "available": False,
                "message": "VirusTotal API key not configured"
            }
        
        try:
            headers = {
                "x-apikey": self.api_key
            }
            
            url = f"{self.base_url}/files/{file_hash}"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                
                return {
                    "available": True,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "harmless": stats.get("harmless", 0),
                    "total_vendors": sum(stats.values()),
                    "verdict": "MALICIOUS" if stats.get("malicious", 0) > 5 else 
                              "SUSPICIOUS" if stats.get("suspicious", 0) > 3 else "CLEAN"
                }
            elif response.status_code == 404:
                return {
                    "available": True,
                    "message": "File not found in VirusTotal database (Unknown/New file)"
                }
            else:
                return {
                    "available": False,
                    "message": f"API Error: {response.status_code}"
                }
                
        except Exception as e:
            return {
                "available": False,
                "message": f"Error: {str(e)}"
            }
