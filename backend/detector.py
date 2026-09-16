# ============================================================
# AEGIS URL THREAT DETECTION ENGINE
# AI-Powered Smart Campus Cybersecurity System
# ============================================================

from urllib.parse import urlparse
import ipaddress
import re


# ============================================================
# URL SCANNER
# ============================================================

def scan_url(url: str):

    # --------------------------------------------------------
    # Basic cleanup
    # --------------------------------------------------------

    url = url.strip()

    if not url:
        return {
            "valid": False,
            "risk_level": "Unknown",
            "risk_score": 0,
            "message": "URL cannot be empty.",
            "indicators": []
        }


    # --------------------------------------------------------
    # Add scheme if user forgot it
    # --------------------------------------------------------

    test_url = url

    if not test_url.startswith(
        ("http://", "https://")
    ):
        test_url = "http://" + test_url


    # --------------------------------------------------------
    # Parse URL
    # --------------------------------------------------------

    try:

        parsed = urlparse(test_url)

    except Exception:

        return {
            "valid": False,
            "risk_level": "Unknown",
            "risk_score": 0,
            "message": "Invalid URL format.",
            "indicators": []
        }


    # --------------------------------------------------------
    # Validate domain
    # --------------------------------------------------------

    hostname = parsed.hostname

    if not hostname:

        return {
            "valid": False,
            "risk_level": "Unknown",
            "risk_score": 0,
            "message": "Could not identify the website domain.",
            "indicators": []
        }


    hostname = hostname.lower()


    # --------------------------------------------------------
    # Risk variables
    # --------------------------------------------------------

    score = 0
    indicators = []


    # ========================================================
    # CHECK 1 — HTTP instead of HTTPS
    # ========================================================

    if parsed.scheme == "http":

        score += 15

        indicators.append(
            "Website does not use HTTPS encryption"
        )


    # ========================================================
    # CHECK 2 — IP ADDRESS INSTEAD OF DOMAIN
    # ========================================================

    try:

        ipaddress.ip_address(hostname)

        score += 25

        indicators.append(
            "URL uses an IP address instead of a domain name"
        )

    except ValueError:

        pass


    # ========================================================
    # CHECK 3 — @ SYMBOL
    # ========================================================

    if "@" in url:

        score += 30

        indicators.append(
            "URL contains '@' which can hide the real destination"
        )


    # ========================================================
    # CHECK 4 — VERY LONG URL
    # ========================================================

    if len(url) > 150:

        score += 10

        indicators.append(
            "URL is unusually long"
        )

    elif len(url) > 250:

        score += 20

        indicators.append(
            "URL is extremely long"
        )


    # ========================================================
    # CHECK 5 — TOO MANY SUBDOMAINS
    # ========================================================

    parts = hostname.split(".")

    if len(parts) >= 5:

        score += 15

        indicators.append(
            "Domain contains an unusually large number of subdomains"
        )


    # ========================================================
    # CHECK 6 — SUSPICIOUS KEYWORDS
    # ========================================================

    suspicious_keywords = [

        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "password",
        "credential",
        "secure",
        "security",
        "update",
        "confirm",
        "bank",
        "payment",
        "wallet",
        "recover",
        "unlock",
        "bonus",
        "free",
        "claim",
        "gift",
        "prize",
        "urgent"

    ]


    found_keywords = []

    full_url_lower = url.lower()


    for keyword in suspicious_keywords:

        if keyword in full_url_lower:

            found_keywords.append(keyword)


    if len(found_keywords) >= 3:

        score += 25

        indicators.append(
            "Multiple suspicious keywords detected: "
            + ", ".join(found_keywords)
        )

    elif len(found_keywords) >= 1:

        score += 10

        indicators.append(
            "Suspicious keyword detected: "
            + ", ".join(found_keywords)
        )


    # ========================================================
    # CHECK 7 — URL SHORTENER
    # ========================================================

    shortener_domains = [

        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "cutt.ly",
        "shorturl.at"

    ]


    if hostname in shortener_domains:

        score += 20

        indicators.append(
            "URL uses a link shortening service"
        )


    # ========================================================
    # CHECK 8 — SUSPICIOUS PORT
    # ========================================================

    try:

        port = parsed.port

        if port is not None:

            suspicious_ports = [
                21,
                22,
                23,
                445,
                3389,
                8080,
                8443
            ]

            if port in suspicious_ports:

                score += 15

                indicators.append(
                    f"URL uses a potentially suspicious port: {port}"
                )

    except ValueError:

        score += 15

        indicators.append(
            "URL contains an invalid port number"
        )


    # ========================================================
    # CHECK 9 — SUSPICIOUS CHARACTERS
    # ========================================================

    suspicious_character_count = len(
        re.findall(
            r"[%]{2,}|-{3,}|_{3,}",
            url
        )
    )


    if suspicious_character_count > 0:

        score += 10

        indicators.append(
            "URL contains unusual character patterns"
        )


    # ========================================================
    # CHECK 10 — DOMAIN WITH MANY HYPHENS
    # ========================================================

    hyphen_count = hostname.count("-")


    if hyphen_count >= 3:

        score += 15

        indicators.append(
            "Domain contains an unusually high number of hyphens"
        )


    # ========================================================
    # CHECK 11 — DOMAIN LOOKALIKE PATTERN
    # ========================================================

    lookalike_patterns = [

        "paypa1",
        "paypai",
        "faceb00k",
        "g00gle",
        "micr0soft",
        "amaz0n",
        "instagr4m",
        "whatsapp1"

    ]


    for pattern in lookalike_patterns:

        if pattern in hostname:

            score += 35

            indicators.append(
                "Possible lookalike or impersonation domain detected"
            )

            break


    # ========================================================
    # LIMIT SCORE
    # ========================================================

    if score > 100:

        score = 100


    # ========================================================
    # RISK CLASSIFICATION
    # ========================================================

    if score >= 70:

        risk_level = "Critical"

    elif score >= 45:

        risk_level = "High"

    elif score >= 20:

        risk_level = "Medium"

    else:

        risk_level = "Low"


    # ========================================================
    # SECURITY RECOMMENDATION
    # ========================================================

    if risk_level == "Critical":

        recommendation = (
            "Avoid opening this URL or entering personal information. "
            "The URL contains multiple high-risk indicators."
        )

    elif risk_level == "High":

        recommendation = (
            "Exercise extreme caution. Verify the website through "
            "an official source before entering credentials or payment information."
        )

    elif risk_level == "Medium":

        recommendation = (
            "Proceed with caution. Some suspicious characteristics "
            "were detected. Verify the website before providing sensitive information."
        )

    else:

        recommendation = (
            "No major suspicious URL patterns were detected. "
            "However, a low-risk result does not guarantee that the website is safe."
        )


    # ========================================================
    # RETURN RESULT
    # ========================================================

    return {

        "valid": True,

        "url": url,

        "domain": hostname,

        "protocol": parsed.scheme,

        "risk_level": risk_level,

        "risk_score": score,

        "indicators": indicators,

        "recommendation": recommendation

    }


# ============================================================
# EXISTING THREAT REPORT DETECTOR
# ============================================================
# We keep this because your existing Report Threat feature
# already uses it.


def detect_threat(threat_type, description):

    text = (
        threat_type + " " + description
    ).lower()


    phishing_keywords = [
        "password",
        "login",
        "credential",
        "verify account",
        "click link",
        "urgent",
        "otp",
        "bank",
        "suspicious email",
        "email"
    ]


    malware_keywords = [
        "virus",
        "malware",
        "trojan",
        "ransomware",
        "infected",
        "download",
        "exe",
        "unknown software"
    ]


    fake_website_keywords = [
        "fake website",
        "fake site",
        "login page",
        "lookalike website",
        "website asking for password"
    ]


    unauthorized_keywords = [
        "unauthorized",
        "unknown login",
        "someone accessed",
        "account accessed",
        "unknown device",
        "hacked"
    ]


    data_breach_keywords = [
        "data leaked",
        "data breach",
        "personal information",
        "information leaked",
        "database leaked",
        "student data"
    ]


    matches = []


    for keyword in phishing_keywords:

        if keyword in text:
            matches.append(keyword)


    for keyword in malware_keywords:

        if keyword in text:
            matches.append(keyword)


    for keyword in fake_website_keywords:

        if keyword in text:
            matches.append(keyword)


    for keyword in unauthorized_keywords:

        if keyword in text:
            matches.append(keyword)


    for keyword in data_breach_keywords:

        if keyword in text:
            matches.append(keyword)


    if len(matches) >= 4:

        risk = "Critical"

    elif len(matches) >= 2:

        risk = "High"

    elif len(matches) == 1:

        risk = "Medium"

    else:

        risk = "Low"


    if any(
        keyword in text
        for keyword in phishing_keywords
    ):

        detected_type = "Phishing"

    elif any(
        keyword in text
        for keyword in malware_keywords
    ):

        detected_type = "Malware"

    elif any(
        keyword in text
        for keyword in fake_website_keywords
    ):

        detected_type = "Fake Website"

    elif any(
        keyword in text
        for keyword in unauthorized_keywords
    ):

        detected_type = "Unauthorized Access"

    elif any(
        keyword in text
        for keyword in data_breach_keywords
    ):

        detected_type = "Data Breach"

    else:

        detected_type = threat_type


    return {

        "detected_type": detected_type,

        "risk_level": risk,

        "matched_keywords": matches

    }