from datetime import datetime, timedelta


def analyze_login_anomaly(
    failed_attempts: int,
    previous_success: bool = False
):
    """
    Analyze login activity and determine whether it looks suspicious.

    failed_attempts:
        Number of recent failed login attempts.

    previous_success:
        Whether the user has successfully logged in recently.
    """

    if failed_attempts >= 5:
        return {
            "risk_level": "High",
            "reason": "Multiple failed login attempts detected."
        }

    if failed_attempts >= 3:
        return {
            "risk_level": "Medium",
            "reason": "Several failed login attempts detected."
        }

    if failed_attempts == 0 and previous_success:
        return {
            "risk_level": "Low",
            "reason": "Normal login activity."
        }

    return {
        "risk_level": "Low",
        "reason": "No significant login anomaly detected."
    }


def get_failed_attempt_window(minutes=15):
    """
    Returns the timestamp from which recent failed
    login attempts should be counted.
    """

    return datetime.utcnow() - timedelta(minutes=minutes)