"""
VirusTotal-Style Security Vendor Ecosystem Simulation.
Simulates over 70 real-world cybersecurity vendors with customized detection heuristics,
matching VirusTotal's exact result structure and categories.
"""
from typing import Dict, List, Any

# 72 Industry Security Vendors matching VirusTotal's engine roster
SECURITY_VENDORS = [
    {"name": "Google Safe Browsing", "specialty": ["brand_impersonation", "homoglyph_spoofing", "phishing_keywords"], "bias": 0.85},
    {"name": "Kaspersky", "specialty": ["brand_impersonation", "ip_host", "homoglyph_spoofing", "high_entropy"], "bias": 0.90},
    {"name": "BitDefender", "specialty": ["brand_impersonation", "phishing_keywords", "at_symbol", "suspicious_tld"], "bias": 0.88},
    {"name": "PhishTank", "specialty": ["brand_impersonation", "phishing_keywords", "deep_subdomains"], "bias": 0.92},
    {"name": "ESET", "specialty": ["brand_impersonation", "ip_host", "suspicious_tld", "double_slash"], "bias": 0.87},
    {"name": "Sophos", "specialty": ["ip_host", "high_entropy", "suspicious_tld", "phishing_keywords"], "bias": 0.86},
    {"name": "Fortinet", "specialty": ["brand_impersonation", "suspicious_tld", "phishing_keywords"], "bias": 0.85},
    {"name": "TrendMicro", "specialty": ["brand_impersonation", "excessive_length", "suspicious_tld"], "bias": 0.84},
    {"name": "Microsoft SmartScreen", "specialty": ["brand_impersonation", "homoglyph_spoofing", "phishing_keywords"], "bias": 0.89},
    {"name": "Spamhaus", "specialty": ["suspicious_tld", "ip_host", "high_entropy"], "bias": 0.82},
    {"name": "URLhaus", "specialty": ["ip_host", "double_slash", "excessive_length"], "bias": 0.80},
    {"name": "OpenPhish", "specialty": ["brand_impersonation", "phishing_keywords", "url_shortener"], "bias": 0.91},
    {"name": "Netcraft", "specialty": ["brand_impersonation", "ip_host", "homoglyph_spoofing"], "bias": 0.90},
    {"name": "Avast", "specialty": ["phishing_keywords", "suspicious_tld", "deep_subdomains"], "bias": 0.83},
    {"name": "AVG", "specialty": ["phishing_keywords", "suspicious_tld", "deep_subdomains"], "bias": 0.83},
    {"name": "McAfee", "specialty": ["brand_impersonation", "excessive_length", "suspicious_tld"], "bias": 0.81},
    {"name": "Symantec / Broadcom", "specialty": ["brand_impersonation", "ip_host", "suspicious_tld"], "bias": 0.86},
    {"name": "CleanBrowsing", "specialty": ["suspicious_tld", "phishing_keywords"], "bias": 0.78},
    {"name": "CRDF Labs", "specialty": ["ip_host", "high_entropy", "suspicious_tld"], "bias": 0.79},
    {"name": "Quttera", "specialty": ["high_entropy", "deep_subdomains", "double_slash"], "bias": 0.75},
    {"name": "Forcepoint ThreatSeeker", "specialty": ["brand_impersonation", "phishing_keywords"], "bias": 0.80},
    {"name": "Webroot", "specialty": ["brand_impersonation", "suspicious_tld", "at_symbol"], "bias": 0.82},
    {"name": "Cyren", "specialty": ["suspicious_tld", "phishing_keywords"], "bias": 0.77},
    {"name": "Quick Heal", "specialty": ["brand_impersonation", "phishing_keywords"], "bias": 0.79},
    {"name": "Dr.Web", "specialty": ["ip_host", "high_entropy", "phishing_keywords"], "bias": 0.76},
    {"name": "G-Data", "specialty": ["brand_impersonation", "suspicious_tld"], "bias": 0.80},
    {"name": "Comodo / Valkyrie", "specialty": ["homoglyph_spoofing", "deep_subdomains"], "bias": 0.78},
    {"name": "Malwarepatrol", "specialty": ["ip_host", "suspicious_tld"], "bias": 0.74},
    {"name": "Yandex Safe Browsing", "specialty": ["brand_impersonation", "homoglyph_spoofing"], "bias": 0.81},
    {"name": "VIPRE", "specialty": ["phishing_keywords", "suspicious_tld"], "bias": 0.75},
    {"name": "Trustwave", "specialty": ["brand_impersonation", "at_symbol"], "bias": 0.76},
    {"name": "Sangfor", "specialty": ["ip_host", "phishing_keywords"], "bias": 0.74},
    {"name": "AlienVault OTX", "specialty": ["ip_host", "suspicious_tld", "high_entropy"], "bias": 0.79},
    {"name": "Tencent", "specialty": ["brand_impersonation", "url_shortener"], "bias": 0.73},
    {"name": "Baidu", "specialty": ["brand_impersonation", "suspicious_tld"], "bias": 0.72},
    {"name": "K7AntiVirus", "specialty": ["phishing_keywords", "suspicious_tld"], "bias": 0.75},
    {"name": "AhnLab-V3", "specialty": ["brand_impersonation", "ip_host"], "bias": 0.77},
    {"name": "Arcabit", "specialty": ["phishing_keywords", "suspicious_tld"], "bias": 0.73},
    {"name": "ZoneAlarm", "specialty": ["brand_impersonation", "phishing_keywords"], "bias": 0.78},
    {"name": "Zvelo", "specialty": ["suspicious_tld", "deep_subdomains"], "bias": 0.72},
    {"name": "Antiy-AVL", "specialty": ["ip_host", "high_entropy"], "bias": 0.71},
    {"name": "F-Secure", "specialty": ["brand_impersonation", "phishing_keywords"], "bias": 0.82},
    {"name": "Palo Alto Networks", "specialty": ["brand_impersonation", "ip_host", "high_entropy"], "bias": 0.85},
    {"name": "Check Point", "specialty": ["brand_impersonation", "phishing_keywords", "homoglyph_spoofing"], "bias": 0.84},
    {"name": "CrowdStrike Falcon", "specialty": ["high_entropy", "ip_host", "brand_impersonation"], "bias": 0.86},
    {"name": "Cisco Talos", "specialty": ["brand_impersonation", "suspicious_tld", "ip_host"], "bias": 0.87},
    {"name": "SentinelOne", "specialty": ["brand_impersonation", "high_entropy"], "bias": 0.83},
    {"name": "Juniper Networks", "specialty": ["ip_host", "suspicious_tld"], "bias": 0.75},
    {"name": "Barracuda", "specialty": ["phishing_keywords", "suspicious_tld", "url_shortener"], "bias": 0.79},
    {"name": "Akamai Threat Engine", "specialty": ["high_entropy", "deep_subdomains", "ip_host"], "bias": 0.82},
    {"name": "Cloudflare Radar", "specialty": ["homoglyph_spoofing", "brand_impersonation"], "bias": 0.84},
    {"name": "Fidelis", "specialty": ["brand_impersonation", "phishing_keywords"], "bias": 0.72},
    {"name": "FireEye / Trellix", "specialty": ["brand_impersonation", "ip_host"], "bias": 0.83},
    {"name": "Zscaler", "specialty": ["phishing_keywords", "suspicious_tld", "brand_impersonation"], "bias": 0.84},
    {"name": "Scantitan", "specialty": ["deep_subdomains", "excessive_length"], "bias": 0.70},
    {"name": "Lionic", "specialty": ["phishing_keywords", "suspicious_tld"], "bias": 0.71},
    {"name": "Gridinsoft", "specialty": ["suspicious_tld", "phishing_keywords"], "bias": 0.74},
    {"name": "Cluster25", "specialty": ["high_entropy", "brand_impersonation"], "bias": 0.73},
    {"name": "AlphaSOC", "specialty": ["high_entropy", "ip_host"], "bias": 0.75},
    {"name": "Abusix", "specialty": ["suspicious_tld", "ip_host"], "bias": 0.76},
    {"name": "Certego", "specialty": ["brand_impersonation", "phishing_keywords"], "bias": 0.72},
    {"name": "DNS8", "specialty": ["suspicious_tld", "deep_subdomains"], "bias": 0.71},
    {"name": "Feodo Tracker", "specialty": ["ip_host", "high_entropy"], "bias": 0.70},
    {"name": "GreenSnow", "specialty": ["ip_host", "suspicious_tld"], "bias": 0.70},
    {"name": "Hoplite Industries", "specialty": ["phishing_keywords", "brand_impersonation"], "bias": 0.73},
    {"name": "IPsum", "specialty": ["ip_host"], "bias": 0.77},
    {"name": "Malwared", "specialty": ["phishing_keywords", "high_entropy"], "bias": 0.72},
    {"name": "PhishLabs", "specialty": ["brand_impersonation", "phishing_keywords", "homoglyph_spoofing"], "bias": 0.88},
    {"name": "PrecisionSec", "specialty": ["brand_impersonation", "suspicious_tld"], "bias": 0.74},
    {"name": "Sansec eComscan", "specialty": ["phishing_keywords", "insecure_http"], "bias": 0.72},
    {"name": "Securd", "specialty": ["deep_subdomains", "suspicious_tld"], "bias": 0.71},
    {"name": "ThreatHive", "specialty": ["ip_host", "brand_impersonation"], "bias": 0.75}
]


def evaluate_vendors(heuristic_result: dict) -> Dict[str, Any]:
    """
    Evaluates the target URL across 72 security vendors based on heuristic features.
    Returns VirusTotal-compliant scan structure:
      - stats: malicious, suspicious, harmless, undetected
      - results: map of vendor_name -> {category, result, method}
    """
    risk_score = heuristic_result.get("risk_score", 0)
    risk_factors = set(heuristic_result.get("risk_factors", []))
    is_trusted = heuristic_result.get("is_trusted", False)

    results = {}
    stats = {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0
    }

    if is_trusted:
        for vendor in SECURITY_VENDORS:
            name = vendor["name"]
            results[name] = {
                "category": "harmless",
                "result": "clean",
                "method": "reputation"
            }
            stats["harmless"] += 1
        return {"stats": stats, "results": results, "total": len(SECURITY_VENDORS)}

    for vendor in SECURITY_VENDORS:
        name = vendor["name"]
        specialties = vendor["specialty"]
        bias = vendor["bias"]

        # Check how many risk factors trigger this vendor's specialty
        matched_specialties = [rf for rf in risk_factors if rf in specialties]
        
        # Vendor decision logic
        if risk_score >= 65:
            # High threat
            if matched_specialties or bias >= 0.80:
                verdict = "malicious"
                detail = "phishing" if "brand_impersonation" in risk_factors or "phishing_keywords" in risk_factors else "malicious"
            elif bias >= 0.73:
                verdict = "suspicious"
                detail = "suspicious"
            else:
                verdict = "undetected"
                detail = "unrated"
        elif risk_score >= 35:
            # Medium / Suspicious threat
            if len(matched_specialties) >= 1 and bias >= 0.82:
                verdict = "malicious"
                detail = "phishing"
            elif matched_specialties or bias >= 0.78:
                verdict = "suspicious"
                detail = "suspicious"
            else:
                verdict = "undetected"
                detail = "unrated"
        elif risk_score >= 15:
            # Low Risk
            if matched_specialties and bias >= 0.85:
                verdict = "suspicious"
                detail = "suspicious"
            else:
                verdict = "harmless"
                detail = "clean"
        else:
            # Clean
            verdict = "harmless"
            detail = "clean"

        results[name] = {
            "category": verdict,
            "result": detail,
            "method": "heuristic" if verdict in ("malicious", "suspicious") else "blacklist"
        }
        stats[verdict] += 1

    return {
        "stats": stats,
        "results": results,
        "total": len(SECURITY_VENDORS)
    }
