import ipaddress
import math
import re
from collections import Counter
from urllib.parse import parse_qs, unquote, urlparse


# ============================================================
# AEGIS ADVANCED URL THREAT DETECTOR
# ============================================================
#
# Defensive static URL analysis engine.
#
# IMPORTANT:
# This scanner does NOT open or visit the submitted URL.
# It analyzes the URL structure only.
#
# ============================================================


# ------------------------------------------------------------
# Suspicious keyword groups
# ------------------------------------------------------------

PHISHING_KEYWORDS = {
    "login",
    "log-in",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "validate",
    "validation",
    "confirm",
    "confirmation",
    "authenticate",
    "authentication",
    "account",
    "password",
    "passwd",
    "credential",
    "credentials",
    "secure",
    "security",
    "update",
    "unlock",
    "recover",
    "recovery",
    "reset",
    "activate",
    "activation",
    "suspended",
    "suspension",
    "restricted",
    "warning",
    "alert",
    "urgent",
    "important",
    "notice",
}

FINANCIAL_KEYWORDS = {
    "bank",
    "banking",
    "payment",
    "payments",
    "pay",
    "wallet",
    "card",
    "credit",
    "debit",
    "invoice",
    "billing",
    "transaction",
    "transfer",
    "refund",
    "deposit",
    "withdraw",
    "upi",
    "netbanking",
    "paypal",
    "stripe",
}

SOCIAL_KEYWORDS = {
    "facebook",
    "instagram",
    "whatsapp",
    "telegram",
    "twitter",
    "x.com",
    "snapchat",
    "linkedin",
    "discord",
    "tiktok",
}

REWARD_KEYWORDS = {
    "bonus",
    "free",
    "gift",
    "prize",
    "winner",
    "winning",
    "reward",
    "rewards",
    "claim",
    "offer",
    "cashback",
    "coupon",
    "giveaway",
}

DOWNLOAD_KEYWORDS = {
    "download",
    "install",
    "setup",
    "update",
    "apk",
    "exe",
    "zip",
    "rar",
    "dmg",
    "msi",
}

REDIRECT_KEYWORDS = {
    "redirect",
    "redirect_url",
    "redirect_uri",
    "return",
    "return_url",
    "returnurl",
    "next",
    "continue",
    "url",
    "target",
    "dest",
    "destination",
    "goto",
    "link",
}

# ------------------------------------------------------------
# URL shortening services
# ------------------------------------------------------------

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly",
    "rb.gy",
    "tiny.cc",
    "lnkd.in",
    "s.id",
    "short.io",
}

# ------------------------------------------------------------
# Suspicious TLDs
#
# These are contextual signals, NOT proof of maliciousness.
# ------------------------------------------------------------

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "click",
    "top",
    "xyz",
    "work",
    "support",
    "live",
    "online",
    "site",
    "club",
    "shop",
    "buzz",
    "cam",
    "icu",
    "rest",
    "fit",
    "monster",
    "download",
    "stream",
    "gq",
    "tk",
    "ml",
    "cf",
    "ga",
}

# ------------------------------------------------------------
# Brands used for impersonation detection
# ------------------------------------------------------------

BRANDS = {
    "paypal",
    "google",
    "gmail",
    "microsoft",
    "office",
    "outlook",
    "apple",
    "icloud",
    "amazon",
    "facebook",
    "instagram",
    "whatsapp",
    "telegram",
    "linkedin",
    "discord",
    "netflix",
    "steam",
    "epicgames",
    "github",
    "gitlab",
    "dropbox",
    "adobe",
    "spotify",
    "binance",
    "coinbase",
    "metamask",
    "sbi",
    "hdfc",
    "icici",
    "axisbank",
    "pnb",
    "paytm",
    "phonepe",
    "flipkart",
    "myntra",
}

# ------------------------------------------------------------
# Known lookalike strings
# ------------------------------------------------------------

LOOKALIKE_PATTERNS = {
    "paypa1": "paypal",
    "paypai": "paypal",
    "g00gle": "google",
    "goog1e": "google",
    "go0gle": "google",
    "micr0soft": "microsoft",
    "m1crosoft": "microsoft",
    "amaz0n": "amazon",
    "faceb00k": "facebook",
    "facebo0k": "facebook",
    "instagr4m": "instagram",
    "whatsapp1": "whatsapp",
    "whatsap": "whatsapp",
    "netf1ix": "netflix",
    "netfiix": "netflix",
    "app1e": "apple",
    "githu8": "github",
    "paytm1": "paytm",
}

# ------------------------------------------------------------
# Dangerous executable extensions
# ------------------------------------------------------------

DANGEROUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".pif",
    ".msi",
    ".jar",
    ".apk",
    ".dmg",
    ".pkg",
    ".vbs",
    ".js",
    ".hta",
    ".ps1",
}

# ------------------------------------------------------------
# Sensitive parameter names
# ------------------------------------------------------------

SENSITIVE_PARAMETER_NAMES = {
    "password",
    "passwd",
    "pass",
    "pwd",
    "token",
    "auth",
    "authorization",
    "session",
    "sessionid",
    "apikey",
    "api_key",
    "secret",
    "credential",
    "username",
    "user",
    "email",
    "login",
}

# ------------------------------------------------------------
# Redirect parameter names
# ------------------------------------------------------------

REDIRECT_PARAMETER_NAMES = {
    "redirect",
    "redirect_url",
    "redirect_uri",
    "return",
    "return_url",
    "returnurl",
    "next",
    "continue",
    "target",
    "dest",
    "destination",
    "goto",
    "url",
    "link",
}


# ============================================================
# Helper functions
# ============================================================

def _normalize_url(url: str):
    """
    Normalize URL input for parsing.
    The URL is not requested or visited.
    """

    if not isinstance(url, str):
        return ""

    url = url.strip()

    if not url:
        return ""

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        url,
    ):
        url = "https://" + url

    return url


def _safe_parse(url: str):
    try:
        return urlparse(url)
    except Exception:
        return None


def _is_ip_address(hostname: str):
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _is_private_ip(hostname: str):
    if not hostname:
        return False

    try:
        ip = ipaddress.ip_address(hostname)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
        )
    except ValueError:
        return False


def _calculate_entropy(value: str):
    """
    Shannon entropy.
    Used only as a contextual static signal.
    """

    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def _extract_hostname_parts(hostname: str):
    if not hostname:
        return []

    return [
        part
        for part in hostname.lower().split(".")
        if part
    ]


def _get_tld(hostname: str):
    if not hostname:
        return ""

    parts = hostname.lower().split(".")

    if len(parts) < 2:
        return ""

    return parts[-1]


def _count_keywords(text: str, keywords):
    text = text.lower()

    found = []

    for keyword in keywords:
        if keyword.lower() in text:
            found.append(keyword)

    return sorted(set(found))


def _has_dangerous_extension(path: str):
    path = path.lower()

    for extension in DANGEROUS_EXTENSIONS:
        if path.endswith(extension):
            return extension

    return None


def _detect_encoded_content(raw_url: str):
    findings = []

    encoded_matches = re.findall(
        r"%[0-9a-fA-F]{2}",
        raw_url,
    )

    if len(encoded_matches) >= 3:
        findings.append(
            "Multiple percent-encoded characters detected."
        )

    decoded = unquote(raw_url).lower()

    if decoded != raw_url.lower():

        if "javascript:" in decoded:
            findings.append(
                "Encoded content contains a javascript scheme."
            )

        if "data:" in decoded:
            findings.append(
                "Encoded content contains a data scheme."
            )

    return findings


def _detect_ip_obfuscation(hostname: str):
    findings = []

    if not hostname:
        return findings

    # Decimal IPv4 representation
    if hostname.isdigit():
        try:
            number = int(hostname)

            if 0 <= number <= 4294967295:
                findings.append(
                    "Hostname is a decimal-encoded IPv4 address."
                )
        except ValueError:
            pass

    # Hexadecimal notation
    if hostname.lower().startswith("0x"):
        findings.append(
            "Hostname uses hexadecimal IP-style notation."
        )

    # Dotted numeric / hexadecimal representation
    if re.fullmatch(
        r"(0x[0-9a-fA-F]+|\d+)"
        r"(\.(0x[0-9a-fA-F]+|\d+)){1,3}",
        hostname,
    ):
        findings.append(
            "Hostname may use an obfuscated numeric IP representation."
        )

    return findings


def _detect_homograph(hostname: str):
    findings = []

    if not hostname:
        return findings

    # Punycode
    if "xn--" in hostname.lower():
        findings.append(
            "Internationalized domain uses punycode (xn--)."
        )

    # Non-ASCII hostname
    try:
        hostname.encode("ascii")
    except UnicodeEncodeError:
        findings.append(
            "Hostname contains non-ASCII characters and may use Unicode lookalikes."
        )

    return findings


def _detect_suspicious_characters(raw_url: str):
    findings = []

    if "\\" in raw_url:
        findings.append(
            "Backslash characters appear in the URL."
        )

    if "<" in raw_url or ">" in raw_url:
        findings.append(
            "HTML-style angle brackets appear in the URL."
        )

    if '"' in raw_url or "'" in raw_url:
        findings.append(
            "Quote characters appear in the URL."
        )

    if "\x00" in raw_url:
        findings.append(
            "Null-byte character detected."
        )

    if re.search(r"-{3,}", raw_url):
        findings.append(
            "Multiple consecutive hyphens detected."
        )

    if re.search(r"_{3,}", raw_url):
        findings.append(
            "Multiple consecutive underscores detected."
        )

    if re.search(r"\.{4,}", raw_url):
        findings.append(
            "Unusually many consecutive dots detected."
        )

    return findings


# ============================================================
# Main detection function
# ============================================================

def detect_threat(url: str):
    """
    Analyze a URL using multiple static threat indicators.

    The submitted URL is NOT opened, downloaded, or visited.
    """

    original_url = url

    normalized_url = _normalize_url(url)

    result = {
        "valid": False,
        "url": original_url,
        "domain": "",
        "protocol": "",
        "risk_level": "Unknown",
        "risk_score": 0,
        "confidence": "Low",
        "indicators": [],
        "recommendation": "",
    }

    # --------------------------------------------------------
    # Basic validation
    # --------------------------------------------------------

    if not normalized_url:
        result["risk_level"] = "Invalid"
        result["recommendation"] = (
            "Enter a valid URL."
        )
        return result

    parsed = _safe_parse(normalized_url)

    if not parsed:
        result["risk_level"] = "Invalid"
        result["recommendation"] = (
            "The URL could not be parsed safely."
        )
        return result

    hostname = parsed.hostname or ""
    hostname = hostname.lower().rstrip(".")

    protocol = parsed.scheme.lower()

    result["domain"] = hostname
    result["protocol"] = protocol

    if not hostname:
        result["risk_level"] = "Invalid"
        result["recommendation"] = (
            "The URL does not contain a valid hostname."
        )
        return result

    result["valid"] = True

    # IMPORTANT:
    # Define this before any lookalike or brand analysis.
    hostname_without_dots = hostname.replace(".", "")

    indicators = []
    score = 0

    # --------------------------------------------------------
    # 1. Protocol analysis
    # --------------------------------------------------------

    if protocol == "http":

        score += 12

        indicators.append(
            "HTTP is used instead of HTTPS."
        )

    elif protocol not in {"http", "https"}:

        score += 35

        indicators.append(
            f"Unusual URL scheme detected: {protocol}."
        )

    # --------------------------------------------------------
    # 2. Raw IP address
    # --------------------------------------------------------

    if _is_ip_address(hostname):

        score += 28

        indicators.append(
            "The hostname is a raw IP address instead of a normal domain."
        )

        if _is_private_ip(hostname):

            indicators.append(
                "The IP address belongs to a private, loopback, or link-local range."
            )

    # --------------------------------------------------------
    # 3. Obfuscated IP
    # --------------------------------------------------------

    ip_obfuscation = _detect_ip_obfuscation(
        hostname
    )

    if ip_obfuscation:

        score += min(
            len(ip_obfuscation) * 15,
            30,
        )

        indicators.extend(
            ip_obfuscation
        )

    # --------------------------------------------------------
    # 4. @ manipulation
    # --------------------------------------------------------

    if "@" in normalized_url:

        score += 35

        indicators.append(
            "The URL contains '@', which can hide the actual destination hostname."
        )

    # --------------------------------------------------------
    # 5. Punycode / Unicode
    # --------------------------------------------------------

    homograph_findings = _detect_homograph(
        hostname
    )

    if homograph_findings:

        score += min(
            len(homograph_findings) * 20,
            35,
        )

        indicators.extend(
            homograph_findings
        )

    # --------------------------------------------------------
    # 6. URL length
    # --------------------------------------------------------

    url_length = len(normalized_url)

    if url_length > 300:

        score += 22

        indicators.append(
            f"Extremely long URL detected ({url_length} characters)."
        )

    elif url_length > 200:

        score += 15

        indicators.append(
            f"Very long URL detected ({url_length} characters)."
        )

    elif url_length > 150:

        score += 8

        indicators.append(
            f"Long URL detected ({url_length} characters)."
        )

    # --------------------------------------------------------
    # 7. Hostname complexity
    # --------------------------------------------------------

    hostname_parts = _extract_hostname_parts(
        hostname
    )

    subdomain_count = max(
        len(hostname_parts) - 2,
        0,
    )

    if subdomain_count >= 5:

        score += 25

        indicators.append(
            f"Excessive subdomain depth detected ({subdomain_count} subdomains)."
        )

    elif subdomain_count >= 3:

        score += 12

        indicators.append(
            f"Multiple subdomains detected ({subdomain_count})."
        )

    # --------------------------------------------------------
    # 8. Hyphen analysis
    # --------------------------------------------------------

    hyphen_count = hostname.count("-")

    if hyphen_count >= 5:

        score += 25

        indicators.append(
            "Hostname contains a very high number of hyphens."
        )

    elif hyphen_count >= 3:

        score += 15

        indicators.append(
            "Hostname contains multiple hyphens."
        )

    # --------------------------------------------------------
    # 9. Suspicious TLD
    # --------------------------------------------------------

    tld = _get_tld(hostname)

    if tld in SUSPICIOUS_TLDS:

        score += 8

        indicators.append(
            f"Domain uses the .{tld} top-level domain, treated as a contextual risk signal."
        )

    # --------------------------------------------------------
    # 10. URL shortener
    # --------------------------------------------------------

    is_shortener = (
        hostname in SHORTENERS
        or any(
            hostname.endswith(
                "." + shortener
            )
            for shortener in SHORTENERS
        )
    )

    if is_shortener:

        score += 22

        indicators.append(
            "Known URL-shortening service detected; the final destination is hidden."
        )

    # --------------------------------------------------------
    # 11. Keyword analysis
    # --------------------------------------------------------

    full_text = unquote(
        normalized_url
    ).lower()

    phishing_found = _count_keywords(
        full_text,
        PHISHING_KEYWORDS,
    )

    financial_found = _count_keywords(
        full_text,
        FINANCIAL_KEYWORDS,
    )

    social_found = _count_keywords(
        full_text,
        SOCIAL_KEYWORDS,
    )

    reward_found = _count_keywords(
        full_text,
        REWARD_KEYWORDS,
    )

    download_found = _count_keywords(
        full_text,
        DOWNLOAD_KEYWORDS,
    )

    if len(phishing_found) >= 4:

        score += 28

        indicators.append(
            "Multiple phishing-related keywords detected: "
            + ", ".join(phishing_found)
        )

    elif len(phishing_found) >= 2:

        score += 18

        indicators.append(
            "Multiple phishing-related keywords detected: "
            + ", ".join(phishing_found)
        )

    elif len(phishing_found) == 1:

        score += 8

        indicators.append(
            "Phishing-related keyword detected: "
            + ", ".join(phishing_found)
        )

    if len(financial_found) >= 3:

        score += 25

        indicators.append(
            "Multiple financial/payment keywords detected: "
            + ", ".join(financial_found)
        )

    elif len(financial_found) >= 1:

        score += 10

        indicators.append(
            "Financial or payment-related keyword detected: "
            + ", ".join(financial_found)
        )

    if len(social_found) >= 1:

        score += 6

        indicators.append(
            "Social-media brand keyword detected: "
            + ", ".join(social_found)
        )

    if len(reward_found) >= 2:

        score += 15

        indicators.append(
            "Multiple reward/promotional keywords detected: "
            + ", ".join(reward_found)
        )

    elif len(reward_found) == 1:

        score += 6

        indicators.append(
            "Reward or promotional keyword detected: "
            + ", ".join(reward_found)
        )

    if len(download_found) >= 1:

        score += 12

        indicators.append(
            "Download/install-related keyword detected: "
            + ", ".join(download_found)
        )

    # --------------------------------------------------------
    # 12. Brand impersonation
    # --------------------------------------------------------

    brand_matches = []

    for brand in BRANDS:

        if brand in hostname:

            brand_matches.append(
                brand
            )

    if brand_matches:

        registrable_section = ""

        if len(hostname_parts) >= 2:

            registrable_section = ".".join(
                hostname_parts[-2:]
            )

        for brand in brand_matches:

            suspicious_brand_context = False

            if brand not in registrable_section:

                suspicious_brand_context = True

            if any(
                token in hostname
                for token in [
                    "secure",
                    "login",
                    "verify",
                    "account",
                    "support",
                    "auth",
                    "update",
                    "wallet",
                    "payment",
                ]
            ):

                suspicious_brand_context = True

            if suspicious_brand_context:

                score += 32

                indicators.append(
                    f"Possible impersonation of the {brand} brand detected in the hostname."
                )

    # --------------------------------------------------------
    # 13. Lookalike domains
    # --------------------------------------------------------

    for fake, real in LOOKALIKE_PATTERNS.items():

        if fake in hostname_without_dots:

            score += 40

            indicators.append(
                f"Lookalike domain pattern detected: resembles {real}."
            )

    # --------------------------------------------------------
    # 14. Suspicious characters
    # --------------------------------------------------------

    character_findings = _detect_suspicious_characters(
        normalized_url
    )

    if character_findings:

        score += min(
            len(character_findings) * 8,
            24,
        )

        indicators.extend(
            character_findings
        )

    # --------------------------------------------------------
    # 15. Encoded content
    # --------------------------------------------------------

    encoded_findings = _detect_encoded_content(
        normalized_url
    )

    if encoded_findings:

        score += min(
            len(encoded_findings) * 10,
            25,
        )

        indicators.extend(
            encoded_findings
        )

    # --------------------------------------------------------
    # 16. Port analysis
    # --------------------------------------------------------

    try:

        port = parsed.port

        if port is not None:

            if port in {
                21,
                22,
                23,
                25,
                110,
                143,
                445,
                3389,
                5900,
                8080,
                8443,
            }:

                score += 15

                indicators.append(
                    f"Unusual or security-sensitive port detected: {port}."
                )

            elif port not in {
                80,
                443,
            }:

                score += 8

                indicators.append(
                    f"Non-standard web port detected: {port}."
                )

    except ValueError:

        score += 20

        indicators.append(
            "Invalid or malformed port specification detected."
        )

    # --------------------------------------------------------
    # 17. Query parameter analysis
    # --------------------------------------------------------

    query = parsed.query

    if query:

        query_parameters = parse_qs(
            query,
            keep_blank_values=True,
        )

        parameter_count = len(
            query_parameters
        )

        if parameter_count >= 10:

            score += 18

            indicators.append(
                f"Large number of query parameters detected ({parameter_count})."
            )

        elif parameter_count >= 6:

            score += 8

            indicators.append(
                f"Multiple query parameters detected ({parameter_count})."
            )

        sensitive_parameters = []

        redirect_parameters = []

        for parameter in query_parameters:

            parameter_lower = parameter.lower()

            if parameter_lower in SENSITIVE_PARAMETER_NAMES:

                sensitive_parameters.append(
                    parameter
                )

            if parameter_lower in REDIRECT_PARAMETER_NAMES:

                redirect_parameters.append(
                    parameter
                )

        if sensitive_parameters:

            score += 12

            indicators.append(
                "Sensitive-looking parameter names detected: "
                + ", ".join(
                    sorted(
                        set(
                            sensitive_parameters
                        )
                    )
                )
            )

        if redirect_parameters:

            score += 18

            indicators.append(
                "Possible redirect parameter detected: "
                + ", ".join(
                    sorted(
                        set(
                            redirect_parameters
                        )
                    )
                )
            )

    # --------------------------------------------------------
    # 18. Embedded URL detection
    # --------------------------------------------------------

    decoded_url = unquote(
        normalized_url
    )

    nested_url_matches = re.findall(
        r"https?://",
        decoded_url.lower(),
    )

    if len(nested_url_matches) >= 2:

        score += 25

        indicators.append(
            "URL contains another embedded URL, which may indicate redirect or phishing infrastructure."
        )

    # --------------------------------------------------------
    # 19. Dangerous file extension
    # --------------------------------------------------------

    dangerous_extension = _has_dangerous_extension(
        parsed.path
    )

    if dangerous_extension:

        score += 28

        indicators.append(
            "Potentially dangerous executable file extension detected: "
            + dangerous_extension
            + "."
        )

    # --------------------------------------------------------
    # 20. Double extension
    # --------------------------------------------------------

    filename = parsed.path.lower().split("/")[-1]

    if re.search(
        r"\.(pdf|doc|docx|jpg|jpeg|png|txt)"
        r"\.(exe|scr|bat|cmd|js|vbs|apk|msi)$",
        filename,
    ):

        score += 35

        indicators.append(
            "Double-extension pattern detected that can disguise an executable file."
        )

    # --------------------------------------------------------
    # 21. Entropy analysis
    # --------------------------------------------------------

    path_entropy = _calculate_entropy(
        parsed.path
    )

    query_entropy = _calculate_entropy(
        parsed.query
    )

    if (
        len(parsed.path) > 35
        and path_entropy >= 4.2
    ):

        score += 8

        indicators.append(
            "URL path contains a high-entropy string that may indicate generated or obfuscated content."
        )

    if (
        len(parsed.query) > 40
        and query_entropy >= 4.3
    ):

        score += 8

        indicators.append(
            "Query string contains high-entropy content that may indicate obfuscation or tracking."
        )

    # --------------------------------------------------------
    # 22. Excessive digits
    # --------------------------------------------------------

    digits_in_hostname = sum(
        character.isdigit()
        for character in hostname
    )

    if digits_in_hostname >= 6:

        score += 10

        indicators.append(
            "Hostname contains an unusually high number of digits."
        )

    # --------------------------------------------------------
    # 23. Repeated suspicious tokens
    # --------------------------------------------------------

    suspicious_token_count = 0

    for token in [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "confirm",
        "password",
        "payment",
        "bank",
        "wallet",
    ]:

        occurrences = full_text.count(
            token
        )

        if occurrences >= 2:

            suspicious_token_count += 1

    if suspicious_token_count >= 2:

        score += 18

        indicators.append(
            "Multiple security-sensitive terms are repeated within the URL."
        )

    # --------------------------------------------------------
    # 24. Credential-style path
    # --------------------------------------------------------

    credential_path_pattern = re.search(
        r"/(login|signin|verify|account|password|credential|auth|secure|payment)"
        r"(/|$|-|_)",
        parsed.path.lower(),
    )

    if credential_path_pattern:

        score += 14

        indicators.append(
            "Credential or authentication-related path detected."
        )

    # --------------------------------------------------------
    # 25. Long hostname
    # --------------------------------------------------------

    if len(hostname) > 70:

        score += 15

        indicators.append(
            "Hostname is unusually long."
        )

    # --------------------------------------------------------
    # 26. Letter-digit mixing
    # --------------------------------------------------------

    if re.search(
        r"[a-zA-Z]\d[a-zA-Z]\d[a-zA-Z]",
        hostname,
    ):

        score += 8

        indicators.append(
            "Hostname contains alternating letters and digits that may indicate generated or lookalike naming."
        )

    # --------------------------------------------------------
    # 27. Brand mismatch
    # --------------------------------------------------------

    important_brand_found = None

    for brand in BRANDS:

        if brand in full_text:

            important_brand_found = brand
            break

    if important_brand_found:

        registrable_section = ""

        if len(hostname_parts) >= 2:

            registrable_section = ".".join(
                hostname_parts[-2:]
            )

        if important_brand_found not in registrable_section:

            score += 28

            indicators.append(
                f"The URL mentions {important_brand_found}, but the apparent domain does not match that brand."
            )

    # --------------------------------------------------------
    # 28. Urgency + phishing combination
    # --------------------------------------------------------

    urgency_terms = {
        "urgent",
        "immediately",
        "now",
        "warning",
        "suspended",
        "blocked",
        "expired",
        "verify",
        "confirm",
    }

    urgency_found = _count_keywords(
        full_text,
        urgency_terms,
    )

    if urgency_found and phishing_found:

        score += 18

        indicators.append(
            "Urgency language is combined with account or verification language."
        )

    # --------------------------------------------------------
    # 29. Financial + authentication combination
    # --------------------------------------------------------

    if financial_found and phishing_found:

        score += 25

        indicators.append(
            "Financial/payment language is combined with authentication or verification language."
        )

    # --------------------------------------------------------
    # 30. Reward + account combination
    # --------------------------------------------------------

    if reward_found and phishing_found:

        score += 18

        indicators.append(
            "Reward/promotional language is combined with account or verification language."
        )

    # --------------------------------------------------------
    # 31. Shortener + suspicious language
    # --------------------------------------------------------

    if (
        is_shortener
        and (
            phishing_found
            or financial_found
            or reward_found
        )
    ):

        score += 30

        indicators.append(
            "URL shortener is combined with phishing, financial, or reward-related language."
        )

    # --------------------------------------------------------
    # 32. IP + phishing combination
    # --------------------------------------------------------

    if (
        _is_ip_address(hostname)
        and phishing_found
    ):

        score += 25

        indicators.append(
            "Raw IP address is combined with phishing or authentication language."
        )

    # --------------------------------------------------------
    # 33. HTTP + phishing combination
    # --------------------------------------------------------

    if (
        protocol == "http"
        and phishing_found
    ):

        score += 18

        indicators.append(
            "Insecure HTTP is combined with credential or verification language."
        )

    # --------------------------------------------------------
    # 34. @ + authentication combination
    # --------------------------------------------------------

    if (
        "@" in normalized_url
        and phishing_found
    ):

        score += 25

        indicators.append(
            "URL obfuscation using '@' is combined with phishing-related language."
        )

    # --------------------------------------------------------
    # 35. Punycode + brand combination
    # --------------------------------------------------------

    if (
        "xn--" in hostname
        and important_brand_found
    ):

        score += 30

        indicators.append(
            "Punycode/IDN structure is combined with a known brand reference."
        )

    # --------------------------------------------------------
    # Remove duplicate indicators
    # --------------------------------------------------------

    unique_indicators = []

    seen = set()

    for indicator in indicators:

        if indicator not in seen:

            seen.add(indicator)
            unique_indicators.append(
                indicator
            )

    indicators = unique_indicators

    # --------------------------------------------------------
    # Score cap
    # --------------------------------------------------------

    score = min(
        max(score, 0),
        100,
    )

    # --------------------------------------------------------
    # Risk classification
    # --------------------------------------------------------

    if score >= 85:

        risk_level = "Critical"

    elif score >= 65:

        risk_level = "High"

    elif score >= 40:

        risk_level = "Medium"

    elif score >= 15:

        risk_level = "Low"

    else:

        risk_level = "Minimal"

    # --------------------------------------------------------
    # Confidence
    #
    # This is confidence in the static classification,
    # NOT proof that the website is safe or malicious.
    # --------------------------------------------------------

    indicator_count = len(indicators)

    if (
        score >= 75
        and indicator_count >= 4
    ):

        confidence = "Very High"

    elif (
        score >= 55
        and indicator_count >= 3
    ):

        confidence = "High"

    elif (
        score >= 30
        and indicator_count >= 2
    ):

        confidence = "Medium"

    else:

        confidence = "Low"

    # --------------------------------------------------------
    # Recommendations
    # --------------------------------------------------------

    if risk_level == "Critical":

        recommendation = (
            "Do not open this URL. Do not enter credentials, "
            "payment information, OTPs, or personal data. "
            "Treat the destination as potentially malicious."
        )

    elif risk_level == "High":

        recommendation = (
            "Avoid opening this URL. Do not provide credentials, "
            "financial information, OTPs, or download files from it."
        )

    elif risk_level == "Medium":

        recommendation = (
            "Use caution. Verify the domain independently before "
            "logging in, downloading files, or providing sensitive information."
        )

    elif risk_level == "Low":

        recommendation = (
            "No strong malicious pattern was detected by static analysis, "
            "but this does not guarantee that the destination is safe."
        )

    else:

        recommendation = (
            "No significant suspicious URL pattern was detected. "
            "Static analysis alone cannot guarantee that a destination is safe."
        )

    # --------------------------------------------------------
    # No-indicator message
    # --------------------------------------------------------

    if not indicators:

        indicators.append(
            "No significant suspicious structural indicators detected."
        )

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    result.update(
        {
            "risk_level": risk_level,
            "risk_score": score,
            "confidence": confidence,
            "indicators": indicators,
            "recommendation": recommendation,
        }
    )

    return result
def scan_url(url: str):
    """
    Compatibility wrapper for the FastAPI /scan-url endpoint.
    Uses the advanced detect_threat() engine.
    """
    return detect_threat(url)