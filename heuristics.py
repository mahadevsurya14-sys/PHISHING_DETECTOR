"""
Heuristic Feature Extraction & Phishing Detection Rules.
Analyzes URL structure, lexical patterns, entropy, brand spoofing, and deceptive tactics.
"""
import re
import math
import unicodedata
from urllib.parse import urlparse, unquote

# Legitimate brands commonly targeted by phishing
TARGETED_BRANDS = {
    "paypal": ["paypal.com"],
    "google": ["google.com", "accounts.google.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "roblox": ["roblox.com"],
    "telegram": ["telegram.org", "t.me"],
    "twitter": ["twitter.com", "x.com"],
    "sbi": ["onlinesbi.sbi", "sbi.co.in"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "paytm": ["paytm.com"],
}

# High-risk keywords indicating credential harvesting or urgent deception
PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "secure", "security", "update", "account", "password", "credential",
    "banking", "wallet", "recover", "recovery", "billing", "confirm",
    "confirmation", "authenticate", "auth", "validation", "unlock",
    "suspended", "limited", "appeal", "kyc", "bonus", "gift", "airdrop",
    "claim", "reward", "re-activate", "reactivate", "support", "helpdesk"
]

# TLDs frequently abused by cybercriminals due to low cost or lax verification
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "work", "click",
    "loan", "fit", "surf", "monster", "quest", "live", "shop", "icu",
    "wang", "link", "date", "trade", "racing", "download", "accountant",
    "faith", "review", "stream", "party", "science", "cam", "rest",
    "country", "kim", "cricket", "men", "win", "bid", "pw", "cc"
}

# Well-known URL shortening services
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy",
    "ow.ly", "shorturl.at", "goo.gl", "buff.ly", "adf.ly", "bit.do"
}

# Trusted root domains to prevent false positives
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "yahoo.com",
    "amazon.com", "twitter.com", "instagram.com", "linkedin.com", "microsoft.com",
    "apple.com", "netflix.com", "github.com", "gitlab.com", "stackoverflow.com",
    "reddit.com", "paypal.com", "whatsapp.com", "dropbox.com", "spotify.com",
    "adobe.com", "wordpress.org", "medium.com", "cloudflare.com", "virustotal.com"
}


def calculate_entropy(text: str) -> float:
    """Calculates Shannon Entropy to detect random or algorithmic domain names."""
    if not text:
        return 0.0
    prob_dist = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob_dist if p > 0)


def extract_base_domain(hostname: str) -> str:
    """Extracts second-level + top-level domain e.g., 'login.paypal.com' -> 'paypal.com'."""
    hostname = hostname.lower().strip()
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def detect_homoglyph_or_punycode(text: str) -> dict:
    """Checks for IDN Punycode ('xn--') or non-ASCII lookalike characters."""
    is_punycode = "xn--" in text.lower()
    has_non_ascii = any(ord(char) > 127 for char in text)
    
    # Common Cyrillic / Greek homoglyphs mimicking Latin letters
    confusable_chars = []
    for char in text:
        name = unicodedata.name(char, "")
        if "CYRILLIC" in name or "GREEK" in name:
            confusable_chars.append(f"{char} ({name})")
            
    is_homoglyph = bool(confusable_chars) or (is_punycode and has_non_ascii)
    return {
        "is_punycode": is_punycode,
        "is_homoglyph": is_homoglyph,
        "confusables": confusable_chars
    }


def analyze_url_heuristics(raw_url: str) -> dict:
    """
    Performs comprehensive lexical and heuristic analysis on a target URL.
    Returns extracted features, detection indicators, and a baseline risk score (0-100).
    """
    url = raw_url.strip()
    if not re.match(r"^[a-zA-Z]+://", url):
        # Default to http if no scheme provided
        url = "http://" + url

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    # Split hostname and port
    if ":" in netloc:
        hostname, port = netloc.split(":", 1)
    else:
        hostname, port = netloc, None

    base_domain = extract_base_domain(hostname)
    full_url_lower = url.lower()

    indicators = []
    risk_factors = []
    score = 0

    # 1. Check if it's a completely trusted domain
    is_trusted = any(hostname == td or hostname.endswith("." + td) for td in TRUSTED_DOMAINS)
    if is_trusted:
        return {
            "url": raw_url,
            "normalized_url": url,
            "scheme": scheme,
            "hostname": hostname,
            "base_domain": base_domain,
            "is_ip": False,
            "is_trusted": True,
            "is_shortened": False,
            "risk_score": 0,
            "risk_level": "CLEAN",
            "indicators": ["Verified Official & Trusted Domain"],
            "features": {
                "length": len(url),
                "entropy": round(calculate_entropy(hostname), 2),
                "subdomains": hostname.count(".") - 1,
                "has_ip": False
            }
        }

    # 2. IP Address in Hostname
    is_ipv4 = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))
    is_hex_or_octal_ip = bool(re.match(r"^0x[0-9a-fA-F]+$", hostname)) or hostname.isdigit()
    is_ip = is_ipv4 or is_hex_or_octal_ip
    if is_ip:
        score += 35
        indicators.append("Host is direct IP address instead of registered domain")
        risk_factors.append("ip_host")

    # 3. Homoglyph / Punycode Deception
    homoglyph_data = detect_homoglyph_or_punycode(url)
    if homoglyph_data["is_punycode"] or homoglyph_data["is_homoglyph"]:
        score += 35
        indicators.append("Punycode / Homoglyph lookalike characters detected (spoofing attempt)")
        risk_factors.append("homoglyph_spoofing")

    # 4. Brand Impersonation / Typosquatting
    brand_spoofed = None
    for brand, legit_domains in TARGETED_BRANDS.items():
        if brand in full_url_lower:
            # Check if this URL actually belongs to the legitimate brand
            is_legit_brand = any(hostname == ld or hostname.endswith("." + ld) for ld in legit_domains)
            if not is_legit_brand:
                score += 40
                brand_spoofed = brand
                indicators.append(f"Target brand impersonation: '{brand.capitalize()}' found on unauthorized domain")
                risk_factors.append("brand_impersonation")
                break

    # 5. Phishing Keywords
    matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in full_url_lower]
    if matched_keywords:
        kw_penalty = min(len(matched_keywords) * 10, 30)
        score += kw_penalty
        indicators.append(f"Suspicious phishing keywords found: {', '.join(matched_keywords[:4])}")
        risk_factors.append("phishing_keywords")

    # 6. Suspicious TLD
    tld = hostname.split(".")[-1] if "." in hostname else ""
    if tld in SUSPICIOUS_TLDS:
        score += 20
        indicators.append(f"High-abuse top-level domain detected: .{tld}")
        risk_factors.append("suspicious_tld")

    # 7. URL Shortener Detection
    is_shortened = base_domain in URL_SHORTENERS or hostname in URL_SHORTENERS
    if is_shortened:
        score += 15
        indicators.append("URL shortener used to conceal real destination")
        risk_factors.append("url_shortener")

    # 8. Excessive URL Length
    url_len = len(url)
    if url_len > 100:
        score += 15
        indicators.append(f"Unusually long URL length ({url_len} characters)")
        risk_factors.append("excessive_length")
    elif url_len > 75:
        score += 8
        indicators.append(f"Long URL structure ({url_len} characters)")
        risk_factors.append("long_length")

    # 9. Subdomain Depth & Excessive Hyphens
    subdomain_count = max(0, hostname.count(".") - 1)
    if subdomain_count >= 3:
        score += 15
        indicators.append(f"Excessive subdomains ({subdomain_count} levels) to mimic legitimacy")
        risk_factors.append("deep_subdomains")

    hyphen_count = hostname.count("-")
    if hyphen_count >= 2:
        score += 12
        indicators.append(f"Multiple hyphens in domain ({hyphen_count} hyphens)")
        risk_factors.append("domain_hyphens")

    # 10. "@" Symbol in URL (userinfo deception trick)
    if "@" in raw_url:
        score += 25
        indicators.append("Contains '@' symbol: browser bypass / credential confusion technique")
        risk_factors.append("at_symbol")

    # 11. Double Slash Redirect Trick
    if "//" in path:
        score += 15
        indicators.append("Double slash '//' in path used for open redirection tricks")
        risk_factors.append("double_slash")

    # 12. Non-Standard Port
    if port and port not in ("80", "443"):
        score += 15
        indicators.append(f"Non-standard HTTP port used: :{port}")
        risk_factors.append("non_standard_port")

    # 13. High Entropy (DGA or obfuscation)
    domain_entropy = calculate_entropy(hostname)
    if domain_entropy > 3.9 and not is_ip:
        score += 12
        indicators.append(f"High domain randomness/entropy ({domain_entropy:.2f} bits)")
        risk_factors.append("high_entropy")

    # 14. Unencrypted HTTP with sensitive actions
    if scheme == "http" and matched_keywords:
        score += 10
        indicators.append("Insecure HTTP protocol used on sensitive keyword endpoint")
        risk_factors.append("insecure_http")

    # Cap score between 0 and 100
    risk_score = min(max(score, 0), 100)

    # Classify Risk Level
    if risk_score >= 65:
        risk_level = "MALICIOUS"
    elif risk_score >= 35:
        risk_level = "SUSPICIOUS"
    elif risk_score >= 15:
        risk_level = "LOW RISK"
    else:
        risk_level = "CLEAN"

    return {
        "url": raw_url,
        "normalized_url": url,
        "scheme": scheme,
        "hostname": hostname,
        "base_domain": base_domain,
        "is_ip": is_ip,
        "is_trusted": False,
        "is_shortened": is_shortened,
        "brand_spoofed": brand_spoofed,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators if indicators else ["No obvious malicious indicators detected"],
        "risk_factors": risk_factors,
        "features": {
            "length": url_len,
            "entropy": round(domain_entropy, 2),
            "subdomains": subdomain_count,
            "hyphens": hyphen_count,
            "has_ip": is_ip,
            "tld": tld,
            "matched_keywords": matched_keywords
        }
    }
