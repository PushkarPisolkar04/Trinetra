from flask import Flask, render_template, request, jsonify, Response
import os
import shutil
from werkzeug.utils import secure_filename
import json
import time
from queue import Queue

# Import our Core Modules
from core.file_id import Gatekeeper
from core.hasher import Karma
from modules.ioc_extractor import Vani
from modules.pe_analyzer import Kundli
from modules.archive_scanner import Kagaz
from modules.image_forensics import Drishti
from modules.deobfuscator import Mayajaal
from modules.ai_engine import Chitragupta
from modules.signature_checker import SignatureChecker
from modules.virustotal_checker import VirusTotalChecker
from modules.behavior_predictor import BehaviorPredictor
from modules.yara_scanner import YaraScanner
from modules.apk_analyzer import APKAnalyzer

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'temp_uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024 # Limit uploads to 100MB

# Ensure temp directory exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Progress tracking
progress_queues = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Create progress queue for this scan
        scan_id = str(time.time())
        progress_queues[scan_id] = Queue()

        def emit_progress(step, percent, message):
            progress_queues[scan_id].put({
                'step': step,
                'percent': percent,
                'message': message
            })

        try:
            # --- EXECUTE THE TRINETRA ENGINE ---
            
            # 1. Gatekeeper
            emit_progress(1, 10, 'Identifying file type...')
            gk = Gatekeeper()
            file_type = gk.identify(file_path)

            # 2. Karma (Hash)
            emit_progress(2, 20, 'Calculating cryptographic hashes...')
            karma = Karma()
            hashes = {}
            try:
                hashes = karma.calculate_hashes(file_path)
            except Exception as e:
                hashes = {"error": f"Hash failed: {str(e)}"}

            # 3. Vani (Strings)
            emit_progress(3, 35, 'Extracting strings and IOCs...')
            iocs = {"ips": [], "urls": []}
            try:
                vani = Vani()
                iocs = vani.hunt_iocs(file_path)
            except:
                pass

            # 4. PE Analysis (if Windows Executable)
            pe_report = None
            signature_info = None
            if 'exe' in file_type or 'dosexec' in file_type or 'portable-executable' in file_type:
                emit_progress(4, 50, 'Analyzing executable structure...')
                try:
                    kundli = Kundli()
                    pe_report = kundli.analyze_pe(file_path)
                except:
                    pe_report = {"error": "PE analysis failed"}
                
                # Check digital signature
                try:
                    sig_checker = SignatureChecker()
                    signature_info = sig_checker.check_signature(file_path)
                except:
                    signature_info = {"is_signed": False, "status": "Check failed"}
            else:
                emit_progress(4, 50, 'Skipping executable analysis...')
            
            # 5. Kagaz (Archive)
            archive_report = None
            try:
                kagaz = Kagaz()
                archive_report = kagaz.check_zip(file_path)
            except:
                pass
            
            # 6. Drishti (Image)
            stego_report = None
            try:
                drishti = Drishti()
                stego_report = drishti.analyze_image(file_path, file_type)
            except:
                pass
            
            # 7. Mayajaal (Deobfuscation)
            maya_report = None
            try:
                maya = Mayajaal()
                maya_report = maya.lift_curse(file_path)
            except:
                pass

            # 8. VirusTotal Reputation Check
            emit_progress(5, 60, 'Checking VirusTotal reputation...')
            vt_report = {"available": False, "message": "No data"}
            try:
                vt_checker = VirusTotalChecker()
                sha256 = hashes.get("sha256")
                if sha256:
                    vt_report = vt_checker.check_hash(sha256)
            except:
                pass
            
            # 9. Behavior Prediction (for executables)
            behavior_report = None
            try:
                if pe_report and "error" not in pe_report:
                    behavior_predictor = BehaviorPredictor()
                    behavior_report = behavior_predictor.predict_behavior(file_path, pe_report, iocs)
            except:
                pass

            # 10. YARA Pattern Matching
            emit_progress(6, 75, 'Running YARA pattern matching...')
            yara_report = {"available": False, "matches_found": 0}
            try:
                yara_scanner = YaraScanner()
                yara_report = yara_scanner.scan_file(file_path)
            except:
                pass

            # 11. APK Analysis (if Android Package)
            apk_report = None
            if "android.package-archive" in file_type:
                emit_progress(6, 80, 'Analyzing APK manifest and permissions...')
                try:
                    apk_analyzer = APKAnalyzer()
                    apk_report = apk_analyzer.analyze(file_path)
                except:
                    apk_report = {"available": False, "error": "APK analysis failed"}
            
            # 12. Chitragupta (AI Scoring)
            emit_progress(7, 90, 'Computing final threat score...')
            final_score = 0
            try:
                chitra = Chitragupta()
                entropy_score = pe_report.get("dosha_score", 0) if (pe_report and "error" not in pe_report) else 0
                dangerous_count = len(pe_report.get("imports", [])) if (pe_report and "error" not in pe_report) else 0
                strings_found = len(iocs["ips"]) + len(iocs["urls"])
                
                # --- SCORING WEIGHTS ---
                # Boosts (Flags)
                vt_boost = 0
                if vt_report.get("available") and vt_report.get("malicious", 0) > 5:
                    vt_boost = 40
                
                yara_boost = 0
                if yara_report.get("available") and yara_report.get("matches_found", 0) > 0:
                    if yara_report.get("verdict") == "MALICIOUS":
                        yara_boost = 50
                    else:
                        yara_boost = 20
                
                apk_boost = 0
                if apk_report and apk_report.get("verdict") == "SUSPICIOUS":
                    apk_boost = 30

                # Discounts (Trust Signals)
                trust_discount = 0
                # 1. VirusTotal Clean Signal (0 detections is a strong sign for known files)
                if vt_report.get("available") and vt_report.get("malicious") == 0 and vt_report.get("total_vendors", 0) > 10:
                    trust_discount += 40
                
                # 2. Digital Signature Signal (Legit files are usually signed)
                if signature_info and signature_info.get("is_signed"):
                    trust_discount += 30

                # --- COMPUTE FINAL JUDGMENT ---
                ai_score = chitra.heuristic_judgment(entropy_score, dangerous_count, strings_found > 0)
                
                # Calculate raw score
                raw_score = ai_score + vt_boost + yara_boost + apk_boost
                
                # Apply trust discount if any
                final_score = max(0, raw_score - trust_discount)
                
                # --- ADVANCED DIFFERENTIATION (The "Third Eye" Verdict) ---
                is_signed = signature_info and signature_info.get("is_signed")
                vt_clean = vt_report.get("available") and vt_report.get("malicious", 0) <= 1
                is_installer = any("Installer" in d.get("rule_name", "") for d in yara_report.get("detections", []))
                
                final_verdict = "UNKNOWN"
                if final_score < 20: final_verdict = "SAFE"
                elif final_score < 60: final_verdict = "SUSPICIOUS"
                else: final_verdict = "MALICIOUS"

                # Override for Known Goodware (Official Apps)
                if is_signed and vt_clean:
                    if is_installer:
                        final_verdict = "SAFE (Legitimate Installer)"
                        final_score = min(final_score, 15)
                    else:
                        final_verdict = "SAFE (Signed Application)"
                        final_score = min(final_score, 25)
                
                # Override for Stealthy Malware (Clean on VT but hits YARA critical)
                if not vt_clean and yara_report.get("verdict") == "MALICIOUS":
                    final_verdict = "MALICIOUS (Targeted Pattern Detected)"
                    final_score = max(final_score, 85)

                final_score = min(100, final_score)

            except Exception as e:
                final_score = 50 
                final_verdict = "ANALYSIS_ERROR"

            # --- CONSTRUCT REPORT ---
            response = {
                'scan_id': scan_id,
                'filename': filename,
                'file_type': file_type,
                'hashes': hashes if 'hashes' in locals() else {},
                'iocs': iocs if 'iocs' in locals() else {"ips":[], "urls":[]},
                'pe_analysis': pe_report if 'pe_report' in locals() else None,
                'signature_info': signature_info if 'signature_info' in locals() else None,
                'virustotal': vt_report if 'vt_report' in locals() else {"available": False},
                'yara_scan': yara_report if 'yara_report' in locals() else {"available": False},
                'apk_analysis': apk_report if 'apk_report' in locals() else None,
                'behavior_prediction': behavior_report if 'behavior_report' in locals() else None,
                'archive_analysis': archive_report if 'archive_report' in locals() else None,
                'stego_analysis': stego_report if 'stego_report' in locals() else None,
                'deobfuscation': maya_report if 'maya_report' in locals() else None,
                'threat_score': final_score,
                'verdict_label': final_verdict
            }
            
            emit_progress(8, 100, 'Analysis complete!')
            return jsonify(response)

        except Exception as e:
            # Clean up progress queue on error
            if scan_id in progress_queues:
                del progress_queues[scan_id]
            return jsonify({"error": f"An error occurred during analysis: {str(e)}", "status": "failed"}), 500

        finally:
            # Clean up the file safely (ignore errors if file is locked on Windows)
            try:
                if 'file_path' in locals() and os.path.exists(file_path):
                    os.remove(file_path)
            except:
                pass

    return jsonify({"error": "No file successfully uploaded"}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)
