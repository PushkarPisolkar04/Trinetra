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

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'temp_uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024 # 500MB Limit

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
            hashes = karma.calculate_hashes(file_path)

            # 3. Vani (Strings)
            emit_progress(3, 35, 'Extracting strings and IOCs...')
            vani = Vani()
            iocs = vani.hunt_iocs(file_path)

            # 4. PE Analysis (if Windows Executable)
            pe_report = None
            signature_info = None
            if 'exe' in file_type or 'dosexec' in file_type:
                emit_progress(4, 50, 'Analyzing executable structure...')
                kundli = Kundli()
                pe_report = kundli.analyze_pe(file_path)
                
                # Check digital signature
                sig_checker = SignatureChecker()
                signature_info = sig_checker.check_signature(file_path)
            else:
                emit_progress(4, 50, 'Skipping executable analysis...')
            
            # 5. Kagaz (Archive)
            kagaz = Kagaz()
            archive_report = kagaz.check_zip(file_path)
            
            # 6. Drishti (Image)
            drishti = Drishti()
            stego_report = drishti.analyze_image(file_path, file_type)
            
            # 7. Mayajaal (Deobfuscation)
            maya = Mayajaal()
            maya_report = maya.lift_curse(file_path)

            # 8. VirusTotal Reputation Check
            emit_progress(5, 60, 'Checking VirusTotal reputation...')
            vt_checker = VirusTotalChecker()
            vt_report = vt_checker.check_hash(hashes["sha256"])
            
            # 9. Behavior Prediction (for executables)
            behavior_predictor = BehaviorPredictor()
            behavior_report = behavior_predictor.predict_behavior(file_path, pe_report, iocs) if pe_report else None

            # 10. YARA Pattern Matching
            emit_progress(6, 75, 'Running YARA pattern matching...')
            yara_scanner = YaraScanner()
            yara_report = yara_scanner.scan_file(file_path)

            # 11. Chitragupta (AI Scoring)
            emit_progress(7, 90, 'Computing final threat score...')
            chitra = Chitragupta()
            entropy_score = pe_report["dosha_score"] if pe_report else 0
            dangerous_count = len(pe_report["imports"]) if pe_report else 0
            strings_found = len(iocs["ips"]) + len(iocs["urls"])
            
            # Boost score if VirusTotal flags it
            vt_boost = 0
            if vt_report.get("available") and vt_report.get("malicious", 0) > 5:
                vt_boost = 40  # Major red flag
            
            # Boost score if YARA detects malware patterns
            yara_boost = 0
            if yara_report.get("available") and yara_report.get("matches_found", 0) > 0:
                if yara_report.get("verdict") == "MALICIOUS":
                    yara_boost = 50  # Critical patterns detected
                else:
                    yara_boost = 20  # Suspicious patterns
            
            ai_score = chitra.heuristic_judgment(entropy_score, dangerous_count, strings_found > 0)
            final_score = min(100, ai_score + vt_boost + yara_boost)

            emit_progress(8, 100, 'Analysis complete!')

            # --- CONSTRUCT REPORT ---
            response = {
                'scan_id': scan_id,
                'filename': filename,
                'file_type': file_type,
                'hashes': hashes,
                'iocs': iocs,
                'pe_analysis': pe_report,
                'signature_info': signature_info,
                'virustotal': vt_report,
                'yara_scan': yara_report,
                'behavior_prediction': behavior_report,
                'archive_analysis': archive_report,
                'stego_analysis': stego_report,
                'deobfuscation': maya_report,
                'threat_score': final_score
            }
            
            # Clean up progress queue
            if scan_id in progress_queues:
                del progress_queues[scan_id]
            
            return jsonify(response)

        finally:
            # Clean up the file
            if os.path.exists(file_path):
                os.remove(file_path)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
