from pydantic import BaseModel, EmailStr


# ============================================================
# USER REGISTRATION
# ============================================================

class UserCreate(BaseModel):

    name: str
    email: EmailStr
    password: str


# ============================================================
# USER LOGIN
# ============================================================

class UserLogin(BaseModel):

    email: EmailStr
    password: str


# ============================================================
# THREAT REPORT
# ============================================================

class ThreatReportCreate(BaseModel):

    user_id: int
    threat_type: str
    description: str
    severity: str = "Medium"


# ============================================================
# URL SCANNER
# ============================================================

class URLScanRequest(BaseModel):

    url: str
    user_id: int


# ============================================================
# MFA VERIFICATION
# ============================================================

class MFAVerifyRequest(BaseModel):

    user_id: int
    code: str