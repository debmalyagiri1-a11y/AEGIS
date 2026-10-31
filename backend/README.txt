AEGIS Threat Intelligence Fix

1. Replace your project file: backend\detector.py with detector.py from this package.
2. Optional Render environment variable: PHISHTANK_APP_KEY=<your PhishTank application key>.
3. Optional Render environment variable: URLHAUS_AUTH_KEY=<your URLhaus Auth-Key> for URLhaus intelligence if your API access requires it.
4. Restart/deploy the backend.
5. Test a URL again.

Behavior: verified PhishTank phishing match or URLhaus malware match => Critical, score 100, Very High confidence. No reputation match is NOT treated as proof of safety. If external reputation services are unavailable and static analysis says Minimal, AEGIS reports Low instead of implying the URL is safe.
