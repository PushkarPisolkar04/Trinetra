import zipfile
import xml.etree.ElementTree as ET
import os

class APKAnalyzer:
    """
    Analyzes Android APK files to extract permissions and manifest details.
    """
    
    def analyze(self, file_path):
        report = {
            "available": False,
            "permissions": [],
            "package_name": "Unknown",
            "activities": [],
            "suspicious_indicators": []
        }
        
        if not zipfile.is_zipfile(file_path):
            return report
            
        try:
            with zipfile.ZipFile(file_path, 'r') as apk:
                report["available"] = True
                
                # Check for AndroidManifest.xml
                if 'AndroidManifest.xml' in apk.namelist():
                    # Note: AndroidManifest is binary XML in compiled APKs.
                    # Without complex dependencies like androguard, we'll look for strings.
                    manifest_data = apk.read('AndroidManifest.xml')
                    
                    # Basic string-based permission extraction for lightweight analysis
                    common_permissions = [
                        "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECORD_AUDIO",
                        "CAMERA", "ACCESS_FINE_LOCATION", "READ_CONTACTS",
                        "PROCESS_OUTGOING_CALLS", "INTERNET", "READ_PHONE_STATE",
                        "SYSTEM_ALERT_WINDOW", "RECEIVE_BOOT_COMPLETED"
                    ]
                    
                    for perm in common_permissions:
                        if perm.encode() in manifest_data:
                            report["permissions"].append(f"android.permission.{perm}")
                    
                    # Look for package name (usually follows 'package=')
                    try:
                        # This is a hacky way without a real AXML parser
                        manifest_str = manifest_data.decode(errors='ignore')
                        if "package" in manifest_str:
                             # Just a placeholder since parsing binary XML is complex
                             report["package_name"] = "Analyzed (See Details)"
                    except:
                        pass

                # Check for other suspicious artifacts
                if 'assets/index.android.bundle' in apk.namelist():
                    report["suspicious_indicators"].append("React Native Bundle (Potential Obfuscation)")
                
                if any('lib/' in name for name in apk.namelist()):
                    report["suspicious_indicators"].append("Contains Native Libraries (JNI)")

                # Verdict logic
                dangerous_perms = ["SEND_SMS", "RECORD_AUDIO", "SYSTEM_ALERT_WINDOW", "PROCESS_OUTGOING_CALLS"]
                found_dangerous = [p for p in report["permissions"] if any(d in p for d in dangerous_perms)]
                
                if len(found_dangerous) >= 2:
                    report["verdict"] = "SUSPICIOUS"
                elif len(report["permissions"]) > 10:
                    report["verdict"] = "SUSPICIOUS"
                else:
                    report["verdict"] = "CLEAN"

            return report
            
        except Exception as e:
            print(f"APK Analysis Error: {e}")
            return report
