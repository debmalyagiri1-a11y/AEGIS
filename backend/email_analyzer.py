import re
import html
from email import policy
from email.parser import BytesParser
from email.message import Message
from urllib.parse import urlparse

from backend.detector import scan_url


# ============================================================
# URL EXTRACTION
# ============================================================

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE
)


def _clean_url(url: str) -> str:
    """
    Remove punctuation that commonly appears immediately after
    URLs inside normal email text.
    """

    if not url:
        return ""

    url = html.unescape(url.strip())

    while url and url[-1] in ".,;:!?)]}>\"'":
        url = url[:-1]

    while url.startswith("<") and url.endswith(">"):
        url = url[1:-1].strip()

    return url.strip()


def _extract_urls_from_text(text: str):
    """
    Extract HTTP/HTTPS URLs from plain-text email content.
    """

    if not text:
        return []

    matches = URL_PATTERN.findall(text)

    urls = []

    for match in matches:

        cleaned = _clean_url(match)

        if not cleaned:
            continue

        parsed = urlparse(cleaned)

        if parsed.scheme.lower() not in {"http", "https"}:
            continue

        if not parsed.hostname:
            continue

        urls.append(cleaned)

    return urls


def _extract_urls_from_html(html_content: str):
    """
    Extract URLs from HTML href attributes and visible HTML text.
    """

    if not html_content:
        return []

    content = html.unescape(html_content)

    urls = []

    # --------------------------------------------------------
    # href="..."
    # --------------------------------------------------------

    href_matches = re.findall(
        r"""href\s*=\s*["']([^"']+)["']""",
        content,
        re.IGNORECASE
    )

    for href in href_matches:

        cleaned = _clean_url(href)

        if not cleaned:
            continue

        parsed = urlparse(cleaned)

        if parsed.scheme.lower() not in {"http", "https"}:
            continue

        if not parsed.hostname:
            continue

        urls.append(cleaned)

    # --------------------------------------------------------
    # URLs appearing directly in HTML text
    # --------------------------------------------------------

    urls.extend(
        _extract_urls_from_text(content)
    )

    return urls


# ============================================================
# EMAIL BODY EXTRACTION
# ============================================================

def _extract_email_content(message: Message):
    """
    Extract plain-text and HTML parts from an EML message.

    Attachments are not opened or executed.
    """

    plain_parts = []
    html_parts = []

    if message.is_multipart():

        for part in message.walk():

            content_type = (
                part.get_content_type()
                or ""
            ).lower()

            disposition = (
                part.get_content_disposition()
                or ""
            ).lower()

            # Do not inspect file attachments as message body.
            if disposition == "attachment":
                continue

            try:

                payload = part.get_payload(
                    decode=True
                )

                if payload is None:
                    continue

                charset = (
                    part.get_content_charset()
                    or "utf-8"
                )

                decoded = payload.decode(
                    charset,
                    errors="replace"
                )

            except Exception:

                try:
                    decoded = part.get_content()
                except Exception:
                    continue

            if content_type == "text/plain":
                plain_parts.append(
                    str(decoded)
                )

            elif content_type == "text/html":
                html_parts.append(
                    str(decoded)
                )

    else:

        content_type = (
            message.get_content_type()
            or ""
        ).lower()

        try:

            payload = message.get_payload(
                decode=True
            )

            if payload is None:
                payload = b""

            charset = (
                message.get_content_charset()
                or "utf-8"
            )

            decoded = payload.decode(
                charset,
                errors="replace"
            )

        except Exception:

            try:
                decoded = message.get_content()
            except Exception:
                decoded = ""

        if content_type == "text/html":
            html_parts.append(
                str(decoded)
            )

        else:
            plain_parts.append(
                str(decoded)
            )

    return (
        "\n".join(plain_parts),
        "\n".join(html_parts)
    )


# ============================================================
# RISK HELPERS
# ============================================================

RISK_ORDER = {
    "Unknown": 0,
    "Minimal": 1,
    "Low": 2,
    "Medium": 3,
    "High": 4,
    "Critical": 5
}


def _risk_value(risk_level):
    return RISK_ORDER.get(
        str(risk_level or "Unknown"),
        0
    )


def _choose_highest_result(results):
    """
    Select the most severe URL analysis result.
    """

    if not results:
        return None

    highest = results[0]

    for current in results[1:]:

        current_risk = _risk_value(
            current.get("risk_level")
        )

        highest_risk = _risk_value(
            highest.get("risk_level")
        )

        if current_risk > highest_risk:
            highest = current
            continue

        if (
            current_risk == highest_risk
        ):

            try:

                current_score = float(
                    current.get(
                        "risk_score",
                        0
                    )
                )

            except Exception:

                current_score = 0

            try:

                highest_score = float(
                    highest.get(
                        "risk_score",
                        0
                    )
                )

            except Exception:

                highest_score = 0

            if current_score > highest_score:
                highest = current

    return highest


# ============================================================
# EMAIL ANALYZER
# ============================================================

def analyze_eml_file(
    file_path: str
):
    """
    Analyze an EML file without opening any URL.

    Workflow:

        EML
         ↓
        Parse email
         ↓
        Extract sender / Reply-To / subject
         ↓
        Extract URLs
         ↓
        Send each URL through AEGIS scan_url()
         ↓
        Determine highest observed risk
         ↓
        Return complete analysis
    """

    # --------------------------------------------------------
    # Read EML
    # --------------------------------------------------------

    with open(
        file_path,
        "rb"
    ) as email_file:

        message = BytesParser(
            policy=policy.default
        ).parse(
            email_file
        )


    # --------------------------------------------------------
    # Basic email information
    # --------------------------------------------------------

    sender = (
        message.get("From")
        or ""
    ).strip()

    reply_to = (
        message.get("Reply-To")
        or ""
    ).strip()

    subject = (
        message.get("Subject")
        or ""
    ).strip()

    date = (
        message.get("Date")
        or ""
    ).strip()

    message_id = (
        message.get("Message-ID")
        or ""
    ).strip()


    # --------------------------------------------------------
    # Extract body
    # --------------------------------------------------------

    plain_text, html_content = (
        _extract_email_content(
            message
        )
    )


    # --------------------------------------------------------
    # Extract URLs
    # --------------------------------------------------------

    extracted_urls = []

    extracted_urls.extend(
        _extract_urls_from_text(
            plain_text
        )
    )

    extracted_urls.extend(
        _extract_urls_from_html(
            html_content
        )
    )


    # Remove duplicates while preserving order.
    unique_urls = []

    seen = set()

    for url in extracted_urls:

        normalized = url.strip()

        key = normalized.lower()

        if key in seen:
            continue

        seen.add(key)

        unique_urls.append(
            normalized
        )


    # --------------------------------------------------------
    # Analyze every URL
    # --------------------------------------------------------

    url_results = []

    for url in unique_urls:

        try:

            result = scan_url(
                url
            )

            # Make sure the frontend receives a clean,
            # predictable URL result object.
            url_result = {

                "url": url,

                "risk_level":
                    result.get(
                        "risk_level",
                        "Unknown"
                    ),

                "risk_score":
                    result.get(
                        "risk_score",
                        0
                    ),

                "confidence":
                    result.get(
                        "confidence",
                        "Low"
                    ),

                "indicators":
                    result.get(
                        "indicators",
                        []
                    ),

                "recommendation":
                    result.get(
                        "recommendation",
                        "Review the detected URL."
                    ),

                "domain":
                    result.get(
                        "domain",
                        ""
                    ),

                "protocol":
                    result.get(
                        "protocol",
                        ""
                    ),

                "threat_intelligence":
                    result.get(
                        "threat_intelligence",
                        {}
                    ),

                "ip_intelligence":
                    result.get(
                        "ip_intelligence",
                        {}
                    )

            }

            url_results.append(
                url_result
            )

        except Exception as error:

            # One bad URL should not prevent the
            # rest of the email from being analyzed.

            url_results.append({

                "url": url,

                "risk_level":
                    "Unknown",

                "risk_score":
                    0,

                "confidence":
                    "Low",

                "indicators": [
                    "URL analysis failed for this extracted link."
                ],

                "recommendation":
                    "Do not open the URL until it can be analyzed successfully.",

                "domain":
                    "",

                "protocol":
                    "",

                "threat_intelligence":
                    {},

                "ip_intelligence":
                    {},

                "analysis_error":
                    str(error)

            })


    # --------------------------------------------------------
    # Determine overall email risk
    # --------------------------------------------------------

    highest_result = _choose_highest_result(
        url_results
    )


    if highest_result:

        overall_risk_level = (
            highest_result.get(
                "risk_level",
                "Unknown"
            )
        )

        overall_risk_score = (
            highest_result.get(
                "risk_score",
                0
            )
        )

        overall_confidence = (
            highest_result.get(
                "confidence",
                "Low"
            )
        )

        overall_recommendation = (
            highest_result.get(
                "recommendation",
                "Review the detected URLs."
            )
        )

    else:

        overall_risk_level = "Minimal"
        overall_risk_score = 0
        overall_confidence = "Low"

        overall_recommendation = (
            "No URLs were extracted from the email. "
            "No URL-based threat score was generated."
        )


    # --------------------------------------------------------
    # Collect indicators from all URLs
    # --------------------------------------------------------

    all_indicators = []

    for item in url_results:

        indicators = item.get(
            "indicators",
            []
        )

        if isinstance(
            indicators,
            list
        ):

            all_indicators.extend(
                str(x)
                for x in indicators
                if str(x).strip()
            )

        elif indicators:

            all_indicators.append(
                str(indicators)
            )


    # Remove duplicate indicators.
    unique_indicators = []

    indicator_seen = set()

    for indicator in all_indicators:

        key = indicator.lower().strip()

        if key in indicator_seen:
            continue

        indicator_seen.add(key)

        unique_indicators.append(
            indicator
        )


    if not unique_indicators:

        unique_indicators.append(
            "No significant suspicious indicators detected."
        )


    # --------------------------------------------------------
    # Email-level indicators
    # --------------------------------------------------------

    if (
        reply_to
        and sender
        and reply_to.lower()
        != sender.lower()
    ):

        unique_indicators.append(
            "Reply-To address differs from the sender address."
        )


    if not subject:

        unique_indicators.append(
            "Email has no subject line."
        )


    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    return {

        "sender":
            sender,

        "reply_to":
            reply_to,

        "subject":
            subject,

        "date":
            date,

        "message_id":
            message_id,

        "risk_level":
            overall_risk_level,

        "risk_score":
            overall_risk_score,

        "confidence":
            overall_confidence,

        "indicators":
            unique_indicators,

        "recommendation":
            overall_recommendation,

        "urls":
            url_results,

        "extracted_urls":
            url_results,

        "url_count":
            len(url_results),

        "analysis_method":
            "EML parsing + AEGIS URL threat analysis",

        "safe_to_open_links":
            False if url_results else True

    }