"""
Official VirusTotal API v3 Client.
Enables real-time queries against VirusTotal's global threat intelligence database.
"""
import base64
import requests
from typing import Optional, Dict, Any


class VirusTotalClient:
    """Client for VirusTotal API v3."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key.strip() if api_key else None

    @staticmethod
    def encode_url_id(url: str) -> str:
        """VirusTotal v3 requires URLs to be base64url encoded without trailing '=' padding."""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def get_url_report(self, target_url: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves analysis report for a given URL from VirusTotal.
        Returns parsed stats, results, and metadata if successful.
        """
        if not self.api_key:
            return None

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        url_id = self.encode_url_id(target_url)
        endpoint = f"{self.BASE_URL}/urls/{url_id}"

        try:
            response = requests.get(endpoint, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                results = attributes.get("last_analysis_results", {})
                categories = attributes.get("categories", {})
                reputation = attributes.get("reputation", 0)
                times_submitted = attributes.get("times_submitted", 1)

                formatted_results = {}
                for vendor_name, vendor_info in results.items():
                    formatted_results[vendor_name] = {
                        "category": vendor_info.get("category", "undetected"),
                        "result": vendor_info.get("result", "unrated") or "clean",
                        "method": vendor_info.get("method", "blacklist")
                    }

                return {
                    "source": "VirusTotal API v3 (Live Cloud Intel)",
                    "stats": stats,
                    "results": formatted_results,
                    "reputation": reputation,
                    "categories": categories,
                    "times_submitted": times_submitted,
                    "total": sum(stats.values()) if stats else len(formatted_results)
                }

            elif response.status_code == 404:
                # URL not yet analyzed on VT, submit it
                return self.scan_url(target_url)
            else:
                return None
        except Exception:
            return None

    def scan_url(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Submits a URL to VirusTotal for fresh scanning."""
        if not self.api_key:
            return None

        headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        endpoint = f"{self.BASE_URL}/urls"

        try:
            resp = requests.post(endpoint, headers=headers, data={"url": target_url}, timeout=10)
            if resp.status_code == 200:
                # Returns analysis ID
                return {"submitted": True, "message": "URL submitted to VirusTotal for analysis"}
        except Exception:
            pass
        return None
