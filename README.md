# 🛡️ Phishing Detector - URL Threat & Risk Analyzer

Python par aadharit ek powerful security tool jo kisi bhi link/URL ko scan karke **phishing, scam aur malicious threats** ko detect karta hai aur **multi-engine consensus logic (72 vendors)** me risk score batata hai.

---

## 🚀 Key Features

1. **VirusTotal-Style Detection Ratio**:
   - `69 / 72 Security vendors flagged this URL as malicious` jaise real format me result deta hai.
   - Har vendor ka status: `Malicious`, `Suspicious`, `Clean`, `Undetected`.
2. **0 - 100% Risk Score & Verdict**:
   - `CLEAN & SAFE` (0% - 14%)
   - `LOW RISK` (15% - 34%)
   - `SUSPICIOUS` (35% - 64%)
   - `MALICIOUS / PHISHING` (65% - 100%)
3. **VirusTotal Heuristics & Threat Logic**:
   - **Target Brand Spoofing / Impersonation**: PayPal, Google, Microsoft, Apple, Amazon, State Bank of India, Paytm, Binance, etc.
   - **Punycode / Homoglyph Attack**: Cyrillic ya lookalike characters jo user ko dhokha dete hain (e.g. `раypal.com`).
   - **Direct IP Hostname**: Agar domain ki jagah IP address use ho raha ho (e.g. `http://192.168.1.1/login`).
   - **High-Risk Phishing Keywords**: `login`, `verify`, `banking`, `secure`, `wallet`, `kyc`, `airdrop`, `suspended`.
   - **Abused TLDs**: `.xyz`, `.top`, `.tk`, `.buzz`, `.click`, `.loan`, `.cam`, etc.
   - **Shannon Entropy**: Domain randomness check (DGA algorithmically generated domains).
   - **URL Shorteners**: `bit.ly`, `tinyurl.com`, `t.co`, etc.
   - **Trick Symbols**: `@` symbol credential bypass, `//` double-slash redirects.
4. **Official VirusTotal API v3 Support**:
   - Agar aapke paas VirusTotal ki free API Key ho, to aap real-time live VirusTotal cloud intelligence database se bhi scan kar sakte hain!
   - Bina API key ke offline heuristic consensus engine 72 vendors ko simulate karke scan karta hai.
5. **Dono Interfaces Available**:
   - **CLI Tool (`cli.py`)**: Terminal me Rich colors, progress bar aur tables ke saath.
   - **Web Dashboard (`web_app.py`)**: VirusTotal jaisa dark mode web dashboard jisme donut gauge chart aur vendor matrix hai!

---

## 📂 Project Structure

```text
phishing_detector/
├── detector/
│   ├── __init__.py
│   ├── analyzer.py        # Core orchestrator & score aggregation
│   ├── heuristics.py      # Lexical analysis, homoglyphs, brands, entropy
│   ├── threat_vendors.py  # 72 security vendors detection matrix
│   └── vt_api.py          # Official VirusTotal API v3 integration
├── templates/
│   └── index.html         # VirusTotal dark-mode web dashboard
├── cli.py                 # Interactive terminal scanner
├── web_app.py             # Local web application server
├── requirements.txt
└── README.md
```

---

## 💻 How to Use (Kaise Chalaye)

### 1. Terminal (CLI) Mode

Single URL scan karne ke liye:
```bash
python cli.py "http://paypal-security-update.xyz/login/verify.php"
```

Interactive mode (bar bar alag alag URLs scan karne ke liye):
```bash
python cli.py
```

Sabhi 72 vendors ki list dekhne ke liye `--all` flag lagaye:
```bash
python cli.py "https://example.com" --all
```

VirusTotal API v3 key ke saath chalana ho to:
```bash
python cli.py "https://example.com" --api-key "YOUR_VIRUSTOTAL_API_KEY"
```

---

### 2. Web Dashboard Mode (VirusTotal Clone UI)

Web server start kare:
```bash
python web_app.py
```
Phir apne browser me open kare:
👉 **`http://127.0.0.1:5000`**

Aapko exact VirusTotal jaisa interface milega jisme aap link paste karke scan kar sakte hain, instant demo buttons try kar sakte hain, aur 72 engines ko filter kar sakte hain.

---

### 3. Python Code Me Import Karke Use Karna

```python
from detector.analyzer import PhishingAnalyzer

analyzer = PhishingAnalyzer()
result = analyzer.scan("http://paypal-security-update.xyz/login")

print("Detection Ratio:", result.detection_ratio)
print("Risk Score:", result.risk_score, "%")
print("Verdict:", result.risk_level)
print("Indicators:", result.indicators)
```
