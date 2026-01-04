import pefile
import re

class BehaviorPredictor:
    """
    Predicts what a Windows executable would do if executed
    by analyzing its imports, resources, and strings.
    """
    
    def predict_behavior(self, file_path, pe_report, iocs):
        """
        Analyzes static indicators to predict runtime behavior.
        """
        behaviors = {
            "network_activity": False,
            "file_operations": False,
            "registry_modifications": False,
            "process_injection": False,
            "persistence_mechanisms": False,
            "anti_analysis": False,
            "details": []
        }
        
        if not pe_report:
            return None
            
        # Analyze imports for behavioral indicators
        imports = pe_report.get("imports", [])
        
        # Network Activity
        network_apis = ["WSAStartup", "InternetOpen", "HttpSendRequest", "connect", "send", "recv"]
        if any(api in str(imports) for api in network_apis):
            behaviors["network_activity"] = True
            behaviors["details"].append("⚠ May establish network connections")
        
        # File Operations
        file_apis = ["CreateFile", "WriteFile", "DeleteFile", "MoveFile", "CopyFile"]
        if any(api in str(imports) for api in file_apis):
            behaviors["file_operations"] = True
            behaviors["details"].append("⚠ May create/modify/delete files")
        
        # Registry Modifications
        reg_apis = ["RegOpenKey", "RegSetValue", "RegCreateKey", "RegDeleteKey"]
        if any(api in str(imports) for api in reg_apis):
            behaviors["registry_modifications"] = True
            behaviors["details"].append("⚠ May modify Windows Registry")
        
        # Process Injection (Code Injection)
        injection_apis = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "NtQueueApcThread"]
        if any(api in str(imports) for api in injection_apis):
            behaviors["process_injection"] = True
            behaviors["details"].append("🔴 May inject code into other processes (MALWARE TECHNIQUE)")
        
        # Persistence Mechanisms
        persistence_indicators = ["RegSetValue", "CreateService", "SetWindowsHook"]
        if any(api in str(imports) for api in persistence_indicators):
            behaviors["persistence_mechanisms"] = True
            behaviors["details"].append("⚠ May install itself for auto-start")
        
        # Anti-Analysis Techniques
        anti_debug = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"]
        if any(api in str(imports) for api in anti_debug):
            behaviors["anti_analysis"] = True
            behaviors["details"].append("🔴 Contains anti-debugging techniques (EVASION)")
        
        # Check for suspicious URLs/IPs
        if iocs and (len(iocs.get("urls", [])) > 0 or len(iocs.get("ips", [])) > 5):
            behaviors["details"].append("⚠ Contains hardcoded network addresses")
        
        return behaviors
