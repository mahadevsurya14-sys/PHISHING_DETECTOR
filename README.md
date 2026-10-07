🛡️ Phishing Detector - URL Threat & Risk Analyzer

A powerful Python-based security tool that scans any link/URL to detect phishing, scams, and malicious threats, and provides a risk score using multi-engine consensus logic (72 vendors).

🚀 Key Features

VirusTotal-Style Detection Ratio:

Shows results in a real format like 69 / 72 Security vendors flagged this URL as malicious.
Each vendor's status: Malicious, Suspicious, Clean, Undetected.

0 – 100% Risk Score & Verdict:

CLEAN & SAFE (0% – 14%)
LOW RISK (15% – 34%)
SUSPICIOUS (35% – 64%)
MALICIOUS / PHISHING (65% – 100%)

VirusTotal Heuristics & Threat Logic:

Target Brand Spoofing / Impersonation: PayPal, Google, Microsoft, Apple, Amazon, State Bank of India, Paytm, Binance, etc.
Punycode / Homoglyph Attack: Cyrillic or lookalike characters that deceive the user (e.g. раypal.com).
Direct IP Hostname: When an IP address is used instead of a domain name (e.g. http://192.168.1.1/login).
High-Risk Phishing Keywords: login, verify, banking, secure, wallet, kyc, airdrop, suspended.
Abused TLDs: .xyz, .top, .tk, .buzz, .click, .loan, .cam, etc.
Shannon Entropy: Domain randomness check (algorithmically generated domains / DGA).
URL Shorteners: bit.ly, tinyurl.com, t.co, etc.
Trick Symbols: @ symbol credential bypass, // double-slash redirects.

Official VirusTotal API v3 Support:

If you have a free VirusTotal API Key, you can also scan using the real-time live VirusTotal cloud intelligence database!
Without an API key, the offline heuristic consensus engine simulates 72 vendors to perform the scan.

Both Interfaces Available:

CLI Tool (cli.py): In the terminal with Rich colors, progress bars, and tables.
Web Dashboard (web_app.py): A VirusTotal-like dark mode web dashboard featuring a donut gauge chart and vendor matrix!
📂 Project Structure
text
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
💻 How to Use
1. Terminal (CLI) Mode

To scan a single URL:

bash
python cli.py "http://paypal-security-update.xyz/login/verify.php"

Interactive mode (to scan different URLs repeatedly):

bash
python cli.py

To view the list of all 72 vendors, use the --all flag:

bash
python cli.py "https://example.com" --all

To run with a VirusTotal API v3 key:

bash
python cli.py "https://example.com" --api-key "YOUR_VIRUSTOTAL_API_KEY"
2. Web Dashboard Mode (VirusTotal Clone UI)

Start the web server:

bash
python web_app.py

Then open in your browser: 👉 http://127.0.0.1:5000

You will get an interface exactly like VirusTotal where you can paste a link and scan it, try instant demo buttons, and filter across all 72 engines.

3. Using It by Importing in Python Code
python
from detector.analyzer import PhishingAnalyzer
analyzer = PhishingAnalyzer()
result = analyzer.scan("http://paypal-security-update.xyz/login")
print("Detection Ratio:", result.detection_ratio)
print("Risk Score:", result.risk_score, "%")
print("Verdict:", result.risk_level)
print("Indicators:", result.indicators)
