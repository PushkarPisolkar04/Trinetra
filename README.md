# Trinetra - Universal Static File Analyzer

**🔍 A powerful, offline malware detection tool that analyzes any file without execution.**

Trinetra (Sanskrit: "The Third Eye") is a comprehensive static analysis tool designed to detect viruses, malware, and hidden threats in files of any type - executables, documents, images, archives, and more.

---

## ✨ Features

- **🛡️ Multi-Layer Detection**
  - Digital signature verification
  - VirusTotal integration (70+ antivirus engines)
  - YARA pattern matching for malware families
  - Behavioral prediction (what the file would do)
  - Entropy analysis for packed/encrypted code
  
- **📁 Universal File Support**
  - Detects real file type (ignores fake extensions)
  - Executables (EXE, DLL)
  - Documents (PDF, Office files)
  - Archives (ZIP, RAR)
  - Images (JPG, PNG) with steganography detection
  
- **🎯 Advanced Analysis**
  - Code injection detection
  - Ransomware pattern matching
  - Cryptominer detection
  - Keylogger identification
  - Hidden payload extraction (Base64, XOR)
  
- **🌐 Modern Web Interface**
  - Drag-and-drop file upload
  - Real-time threat scoring (0-100)
  - Detailed analysis reports
  - Clean, professional UI

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Windows OS (for digital signature verification)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/trinetra.git
   cd trinetra
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   venv\Scripts\activate  # Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure VirusTotal (Optional)**
   - Get a free API key from [virustotal.com](https://www.virustotal.com/)
   - Edit `modules/virustotal_checker.py`
   - Replace `YOUR_VT_API_KEY_HERE` with your key

5. **Run the application**
   ```bash
   python web_app.py
   ```

6. **Open your browser**
   - Navigate to `http://127.0.0.1:5000`
   - Drag and drop any file to analyze

---

## 📊 Understanding Results

### Threat Score
- **0-20 (Safe)**: Standard files, no suspicious indicators
- **20-60 (Suspicious)**: Unknown binaries, unsigned executables
- **60-100 (Malicious)**: Known malware patterns, dangerous behaviors

> **Note:** Legitimate software (games, anti-cheat systems) may score high due to code packing. Check the **Digital Signature** section to verify the publisher.

### Analysis Sections

**Identity**
- File hashes (MD5, SHA256) for VirusTotal lookup

**Indicators**
- Embedded IPs, URLs, and suspicious strings

**Digital Signature**
- ✅ Signed by trusted publisher = Likely safe
- ⚠️ Not signed = Proceed with caution
- ❌ Invalid signature = Tampered file

**VirusTotal Reputation**
- Shows how many antivirus engines flagged the file

**YARA Detections**
- Specific malware family patterns (Ransomware, Trojans, etc.)

**Predicted Behavior**
- What the file would do if executed (network calls, file modifications, etc.)

---

## 🔒 Security & Privacy

- **100% Offline Analysis**: All scanning happens locally (except optional VirusTotal lookup)
- **No File Execution**: Files are never run on your system
- **Safe for Malware**: Designed to analyze dangerous files safely
- **No Data Collection**: Your files stay on your machine

---

## ⚠️ Limitations

- **Static Analysis Only**: Cannot detect runtime-only behaviors
- **False Positives**: Legitimate packed software may be flagged
- **New Malware**: Zero-day threats may not match YARA rules
- **Requires Judgment**: Use digital signatures and VirusTotal to verify results

---

## 🛠️ Troubleshooting

**"PermissionError" when scanning**
- Close any programs that might have the file open
- Try restarting the server

**"YARA rules not loaded"**
- Ensure `data/yara_rules/` directory exists
- Check that `.yar` files are present

**VirusTotal not working**
- Verify your API key is correctly configured
- Free tier allows 4 requests/minute

---

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🙏 Acknowledgments

Built with:
- [python-magic](https://github.com/ahupp/python-magic) - File type detection
- [pefile](https://github.com/ericZimmerman/pefile) - PE file analysis
- [YARA](https://virustotal.github.io/yara/) - Pattern matching
- [VirusTotal API](https://www.virustotal.com/) - Threat intelligence

---

## ⚡ Quick Tips

1. **Always check digital signatures** on high-scoring executables
2. **Cross-reference hashes** on VirusTotal for second opinions
3. **Trust the YARA detections** - they're based on known malware patterns
4. **Use behavior predictions** to understand file capabilities
5. **When in doubt**, don't execute the file

---

**Made with 🛡️ by [Your Name]**
