"""
Core Phishing Analyzer Orchestrator.
Combines Heuristics Engine, VirusTotal Vendor Matrix, and Live API v3 if configured.
"""
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from .heuristics import analyze_url_heuristics
from .threat_vendors import evaluate_vendors
from .vt_api import VirusTotalClient


@dataclass
class ScanResult:
    url: str
    normalized_url: str
    hostname: str
    risk_score: int                 # 0 to 100%
    risk_level: str                 # CLEAN, LOW RISK, SUSPICIOUS, MALICIOUS
    detection_ratio: str            # e.g., "52 / 72"
    stats: Dict[str, int]           # malicious, suspicious, harmless, undetected
    vendor_results: Dict[str, Dict[str, str]]
    indicators: List[str]
    features: Dict[str, Any]
    source: str                     # Heuristic Engine or VirusTotal API v3
    is_trusted: bool
    brand_spoofed: Optional[str] = None


class PhishingAnalyzer:
    """Main analyzer coordinating detection mechanisms."""

    def __init__(self, vt_api_key: Optional[str] = None):
        self.vt_client = VirusTotalClient(vt_api_key) if vt_api_key else None

    def scan(self, url: str) -> ScanResult:
        """
        Executes complete scan for a given URL.
        1. Runs local heuristic & structural analysis.
        2. Tries live VirusTotal API v3 if API key is present.
        3. If no API key or VT fails, evaluates against the simulated 72-vendor engine.
        4. Compiles unified VirusTotal-style report.
        """
        # Step 1: Heuristic Analysis
        heuristic_data = analyze_url_heuristics(url)

        # Step 2: Attempt real VirusTotal API if key is present
        vt_data = None
        if self.vt_client:
            vt_data = self.vt_client.get_url_report(url)

        if vt_data and "stats" in vt_data:
            source = vt_data.get("source", "VirusTotal API v3")
            stats = vt_data["stats"]
            vendor_results = vt_data["results"]
            total_vendors = vt_data.get("total", len(vendor_results))

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            # Calculate composite risk score based on VT vendor detections + heuristics
            if total_vendors > 0:
                vt_score = int(((malicious * 1.0 + suspicious * 0.5) / total_vendors) * 100)
            else:
                vt_score = 0
            
            # Combine VT vendor consensus with deep lexical heuristic score
            combined_score = max(vt_score, heuristic_data["risk_score"])
            combined_score = min(max(combined_score, 0), 100)
            
            if combined_score >= 60 or malicious >= 3:
                risk_level = "MALICIOUS"
            elif combined_score >= 30 or (malicious + suspicious) >= 2:
                risk_level = "SUSPICIOUS"
            elif combined_score >= 10:
                risk_level = "LOW RISK"
            else:
                risk_level = "CLEAN"

        else:
            # Step 3: Heuristic Multi-Vendor Evaluation
            source = "Phishing Detector Consensus Engine (72 Vendors)"
            vendor_eval = evaluate_vendors(heuristic_data)
            stats = vendor_eval["stats"]
            vendor_results = vendor_eval["results"]
            total_vendors = vendor_eval["total"]

            malicious = stats["malicious"]
            suspicious = stats["suspicious"]
            harmless = stats["harmless"]
            undetected = stats["undetected"]

            combined_score = heuristic_data["risk_score"]
            risk_level = heuristic_data["risk_level"]

        flagged_count = malicious + suspicious
        detection_ratio = f"{flagged_count} / {total_vendors}"

        return ScanResult(
            url=heuristic_data["url"],
            normalized_url=heuristic_data["normalized_url"],
            hostname=heuristic_data["hostname"],
            risk_score=combined_score,
            risk_level=risk_level,
            detection_ratio=detection_ratio,
            stats=stats,
            vendor_results=vendor_results,
            indicators=heuristic_data["indicators"],
            features=heuristic_data["features"],
            source=source,
            is_trusted=heuristic_data["is_trusted"],
            brand_spoofed=heuristic_data.get("brand_spoofed")
        )
