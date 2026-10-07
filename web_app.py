#!/usr/bin/env python3
"""
VirusTotal Clone Web Server.
Provides local web dashboard replicating VirusTotal's UI, REST API,
and automatically opens the default web browser on Windows.
"""
import os
import sys
import webbrowser
import threading
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from detector.analyzer import PhishingAnalyzer

app = Flask(__name__, template_folder="templates")
CORS(app)

vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
analyzer = PhishingAnalyzer(vt_api_key=vt_api_key)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["GET", "POST"])
def scan_endpoint():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        target_url = data.get("url") or request.form.get("url", "")
    else:
        target_url = request.args.get("url", "")

    if not target_url:
        return jsonify({"error": "Missing 'url' parameter"}), 400

    result = analyzer.scan(target_url)

    return jsonify({
        "url": result.url,
        "normalized_url": result.normalized_url,
        "hostname": result.hostname,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "detection_ratio": result.detection_ratio,
        "stats": result.stats,
        "vendor_results": result.vendor_results,
        "indicators": result.indicators,
        "features": result.features,
        "source": result.source,
        "is_trusted": result.is_trusted,
        "brand_spoofed": result.brand_spoofed
    })


def open_browser(port):
    """Opens browser automatically on Windows."""
    try:
        webbrowser.open(f"http://127.0.0.1:{port}")
    except Exception:
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n========================================================")
    print(f"  PHISHING DETECTOR - Threat Intelligence Server")
    print(f"  Windows Mode: Browser will launch automatically!")
    print(f"  Access URL: http://127.0.0.1:{port}")
    print(f"========================================================\n")

    # Launch browser after 1 second
    if "--no-browser" not in sys.argv:
        threading.Timer(1.2, open_browser, args=[port]).start()

    app.run(host="127.0.0.1", port=port, debug=False)
