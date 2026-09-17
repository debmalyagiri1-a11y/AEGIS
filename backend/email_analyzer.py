import re
from email import policy
from email.parser import BytesParser
from email.message import Message

from backend.detector import detect_threat


URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"]+",
    re.IGNORECASE
)


def _clean_url(url: str) -> str:
    """
    Remove common punctuation accidentally captured
    at the end of an email URL.
    """

    return url.rstrip(
        ".,;:!?)]}>\"'"
    )


def _extract_urls(text: str):
    """
    Extract URLs from email text.

    URLs are only analyzed as strings.
    They are never opened.
    """

    matches = URL_PATTERN.findall(
        text or ""
    )

    urls = []

    for url in matches:

        cleaned = _clean_url(url)

        if cleaned and cleaned not in urls:

            urls.append(cleaned)

    return urls


def _extract_body(message: Message) -> str:
    """
    Extract readable text from an email message.
    """

    if message.is_multipart():

        text_parts = []

        for part in message.walk():

            content_type = part.get_content_type()
            disposition = str(
                part.get("Content-Disposition", "")
            )

            if (
                content_type == "text/plain"
                and "attachment" not in disposition.lower()
            ):

                try:

                    payload = part.get_payload(
                        decode=True
                    )

                    if payload:

                        text_parts.append(
                            payload.decode(
                                part.get_content_charset()
                                or "utf-8",
                                errors="replace"
                            )
                        )

                except Exception:

                    continue

        return "\n".join(text_parts)

    try:

        payload = message.get_payload(
            decode=True
        )

        if payload:

            return payload.decode(
                message.get_content_charset()
                or "utf-8",
                errors="replace"
            )

    except Exception:

        pass

    payload = message.get_payload()

    if isinstance(payload, str):

        return payload

    return ""


def analyze_eml_file(file_path: str):
    """
    Analyze an .eml email file.

    This function:
    - reads email headers
    - extracts the body
    - extracts URLs
    - analyzes extracted URLs with AEGIS
    - never opens the URLs
    """

    result = {
        "success": False,
        "sender": None,
        "reply_to": None,
        "subject": None,
        "message_id": None,
        "date": None,
        "urls_found": 0,
        "urls": [],
        "url_analysis": [],
        "error": None
    }

    try:

        with open(
            file_path,
            "rb"
        ) as email_file:

            message = BytesParser(
                policy=policy.default
            ).parse(email_file)

        result["sender"] = message.get(
            "From"
        )

        result["reply_to"] = message.get(
            "Reply-To"
        )

        result["subject"] = message.get(
            "Subject"
        )

        result["message_id"] = message.get(
            "Message-ID"
        )

        result["date"] = message.get(
            "Date"
        )

        body = _extract_body(
            message
        )

        urls = _extract_urls(
            body
        )

        result["urls"] = urls

        result["urls_found"] = len(
            urls
        )

        for url in urls:

            try:

                analysis = detect_threat(
                    url
                )

                result["url_analysis"].append(
                    analysis
                )

            except Exception as error:

                result["url_analysis"].append(
                    {
                        "url": url,
                        "error": str(error)
                    }
                )

        result["success"] = True

        return result

    except FileNotFoundError:

        result["error"] = (
            "Email file was not found."
        )

        return result

    except Exception as error:

        result["error"] = (
            f"Email analysis failed: {error}"
        )

        return result