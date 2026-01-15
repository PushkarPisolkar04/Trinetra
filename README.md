# 👁️ TRINETRA | Universal Static Forensic Analyzer

![Trinetra Banner](https://img.shields.io/badge/Security-Advanced-red?style=for-the-badge&logo=kalilinux)
![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

> **"Unveil the Unseen."**  
> Trinetra (Third Eye) is a powerful, open-source static analysis engine designed to dissect suspicious files without executing them.

---

## 🚀 Why Trinetra?

In a world of evolving cyber threats, dynamic analysis (sandboxing) isn't always feasible or safe. Trinetra provides **deep static inspection** to identify malicious intent, hidden payloads, and IOCs in seconds.

Whether you are a **Red Teamer**, **Blue Teamer**, or **Security Researcher**, Trinetra gives you the X-ray vision you need.

## ✨ Key Features

- **� Universal File Support**: Analyzes Executables (EXE/DLL), Documents (PDF/Docx), Archives (ZIP), Images (Steganography), and even Videos.
- **🧠 Chitragupta AI Engine**: Heuristic scoring system that calculates a "Threat Score" based on entropy, imports, and anomalies.
- **🛡️ Deep PE Analysis**: Inspects headers, sections, imports, and digital signatures for manipulation.
- **🧬 YARA Integration**: Built-in support for YARA rules to detect known malware families and patterns.
- **🌐 Network Intelligence**: Extracts IPs, URLs, and Domains to hunt for C2 (Command & Control) infrastructure.
- **⚡ Blazing Fast**: Purely static analysis means results in seconds, not minutes.
- **� Modern UI**: A sleek, professional web interface with real-time progress tracking.

---

## 📸 Screenshots

![Trinetra Dashboard](./dashboard.png)

---

## �️ Installation

### Prerequisites
- Python 3.9+
- Windows (Recommended) or Linux

### Quick Start

1. **Clone the Repository**
   ```bash
   git clone https://github.com/PushkarPisolkar04/Trinetra.git
   cd Trinetra
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Application**
   ```bash
   python web_app.py
   ```

4. **Access the Dashboard**
   Open your browser and navigate to: `http://127.0.0.1:5000`

---

## ☁️ Free Deployment

Trinetra is optimized for free hosting on **[Render](https://render.com/)** or **[Koyeb](https://www.koyeb.com/)** using Docker.

1. **GitHub**: Push your code to a GitHub repository.
2. **Render**: 
   - Create a new **Web Service**.
   - Connect your Trinetra repository.
   - Select **Runtime: Docker**.
   - Render will automatically use the `Dockerfile` to build and deploy.
3. **Wait & Launch**: Once the build finish, you'll get a public `.onrender.com` URL!

> [!NOTE]
> Free tier services on Render spin down after 15 minutes of inactivity. The first scan after a break might take a minute to "wake up" the server.

---

## ⚙️ Configuration

Trinetra works out of the box, but you can superpowers it with API keys.

1. Rename `config.example.py` to `config.py`.
2. Add your **VirusTotal API Key** (optional but recommended for reputation checks).

```python
# config.py
VIRUSTOTAL_API_KEY = "your_api_key_here"
```

---

## 🤝 Contributing

We love open source! Help us make Trinetra better:
1. Fork the repo.
2. Create a feature branch (`git checkout -b feature/amazing-feature`).
3. Commit your changes.
4. Push to the branch.
5. Open a **Pull Request**.

## ⭐ Support Us

If you find this tool useful, please **give us a STAR ⭐** on GitHub! It helps more people discover Trinetra.

**[PushkarPisolkar04/Trinetra](https://github.com/PushkarPisolkar04/Trinetra)**

---

**Disclaimer**: This tool is for educational and defensive purposes only. The authors are not responsible for misuse.