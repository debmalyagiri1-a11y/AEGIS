from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Request,
    File,
    UploadFile
)

from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy.orm import Session

from passlib.context import CryptContext

from datetime import datetime, timedelta

import secrets
import os
import tempfile
from backend.auth import create_token, read_token, deliver_mfa, is_local_demo, rate_limit
from fastapi.responses import JSONResponse

from backend.email_analyzer import analyze_eml_file
from backend.fact_checker import fact_check_text

from backend.database import Base, engine, SessionLocal

from backend.models import (
    User,
    ThreatReport,
    URLScan,
    LoginEvent,
    MFACode,
    AuditLog,
    QuizResult
)

from backend.schemas import (
    UserCreate,
    UserLogin,
    ThreatReportCreate,
    URLScanRequest,
    MFAVerifyRequest,
    FactCheckRequest,
)

from backend.detector import (
    scan_url,
    detect_threat
)

from backend.security import (
    analyze_login_anomaly,
    get_failed_attempt_window
)


# ============================================================
# AEGIS APPLICATION
# ============================================================

app = FastAPI(
    title="AEGIS - AI-Powered Smart Campus Cybersecurity System"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://debmalyagiri1-a11y.github.io", "http://127.0.0.1:5500", "http://localhost:5500", "http://127.0.0.1:8000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"]
)


# ============================================================
# DATABASE
# ============================================================

Base.metadata.create_all(
    bind=engine
)


# ============================================================
# PASSWORD SECURITY
# ============================================================

pwd_context = CryptContext(
    schemes=["pbkdf2_sha256", "bcrypt"],
    deprecated="auto"
)


def hash_password(password: str):
    # PBKDF2-SHA256 is used for new accounts.
    # bcrypt remains enabled so existing bcrypt password hashes
    # continue to work during migration.
    return pwd_context.hash(password)


def verify_password(
    password: str,
    stored_password: str
):

    if not stored_password:
        return False

    try:
        return pwd_context.verify(
            password,
            stored_password
        )

    except Exception as error:
        print("AEGIS LOGIN PASSWORD VERIFY ERROR:", repr(error))
        return False


# ============================================================
# DEFAULT ADMIN ACCOUNT
# ============================================================

# Administrators must be provisioned manually; never create a known-password account.
# If a legacy admin account uses Admin@123, change its password immediately.

# ============================================================
# DATABASE SESSION
# ============================================================

def get_db():

    db = SessionLocal()

    try:

        yield db

    finally:

        db.close()


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def client_ip(
    request: Request
):

    if request.client:

        return request.client.host

    return "Unknown"


def user_dict(user):

    return {

        "id": user.id,

        "user_id": user.id,

        "userId": user.id,

        "name": user.name,

        "email": user.email,

        "role": user.role

    }


# Authenticate and authorize centrally, including endpoints using arbitrary user_id.
# The database is the source of truth for roles; token roles are not trusted.
@app.middleware("http")
async def enforce_access(request: Request, call_next):
    path = request.url.path
    if request.method == "OPTIONS" or path in ("/", "/health", "/openapi.json", "/docs", "/redoc", "/login", "/register", "/verify-mfa"):
        return await call_next(request)
    authorization = request.headers.get("authorization", "")
    token = authorization[7:] if authorization.lower().startswith("bearer ") else ""
    try:
        user_id = read_token(token, purpose="access")
    except ValueError:
        return JSONResponse({"detail": "Authentication required"}, status_code=401)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return JSONResponse({"detail": "Account not found"}, status_code=401)
        admin = str(user.role).lower() == "admin"
        admin_paths = ("/audit-logs", "/login-events", "/url-scans", "/admin/", "/threat-report/")
        if (path in ("/audit-logs", "/login-events", "/url-scans", "/threat-reports") or path.startswith(("/admin/", "/threat-report/"))) and not admin:
            return JSONResponse({"detail": "Administrator access required"}, status_code=403)
        for prefix in ("/url-scan-history/", "/login-events/", "/users/", "/threat-reports/"):
            if path.startswith(prefix):
                try:
                    target = int(path[len(prefix):].split("/")[0])
                except ValueError:
                    return JSONResponse({"detail": "Invalid user ID"}, status_code=400)
                if target != user.id and not admin:
                    return JSONResponse({"detail": "Access denied"}, status_code=403)
        if path in ("/scan-url", "/threat-report") and request.method == "POST":
            # Body is parsed in endpoint; request.state.user_id is enforced there.
            request.state.user_id = user.id
            request.state.is_admin = admin
        request.state.authenticated_user_id = user.id
        request.state.is_admin = admin
    finally:
        db.close()
    return await call_next(request)

# ============================================================
# HOME
# ============================================================

@app.get("/")
def root():

    return {

        "project": "AEGIS",

        "status": "running"

    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return {

        "status": "healthy"

    }


# ============================================================
# USER REGISTRATION
# ============================================================

@app.post("/register")
def register(
    data: UserCreate,
    request: Request,
    db: Session = Depends(get_db)
):

    try:

        email = str(
            data.email
        ).strip().lower()


        if not data.name.strip():

            raise HTTPException(
                status_code=400,
                detail="Name cannot be empty"
            )


        if len(data.password) < 12:

            raise HTTPException(
                status_code=400,
                detail="Password must contain at least 12 characters"
            )


        if len(data.password.encode("utf-8")) > 72:

            raise HTTPException(
                status_code=400,
                detail="Password must be 6-72 bytes long"
            )


        existing_user = db.query(
            User
        ).filter(
            User.email == email
        ).first()


        if existing_user:

            raise HTTPException(
                status_code=400,
                detail="Email already registered"
            )


        hashed_password = hash_password(
            data.password
        )


        user = User(
            name=data.name.strip(),
            email=email,
            password=hashed_password,
            role="student"
        )


        db.add(user)

        db.commit()

        db.refresh(user)


        audit = AuditLog(
            user_id=user.id,
            action="USER_REGISTERED",
            details=f"New account registered: {email}",
            ip_address=client_ip(request)
        )


        db.add(audit)

        db.commit()


        return {
            "message": "Registration successful",
            **user_dict(user)
        }


    except HTTPException:

        raise


    except Exception as error:

        db.rollback()

        print(
            "REGISTER ERROR:",
            repr(error)
        )

        raise HTTPException(
            status_code=500,
            detail=(
                f"Registration failed: "
                f"{type(error).__name__}: {error}"
            )
        )
    

   # ============================================================
# LOGIN
# ============================================================

@app.post("/login")
def login(
    data: UserLogin,
    request: Request,
    db: Session = Depends(get_db)
):

    email = str(data.email).strip().lower()

    ip = client_ip(request)
    rate_limit("login:" + ip + ":" + email, limit=8, window=900)

    user_agent = request.headers.get(
        "User-Agent",
        "Unknown"
    )

    user = db.query(
        User
    ).filter(
        User.email == email
    ).first()

    if not user:

        db.add(
            LoginEvent(
                user_id=None,
                email=email,
                success=0,
                ip_address=ip,
                user_agent=user_agent,
                risk_level="Medium",
                anomaly_reason="Unknown email login attempt"
            )
        )

        db.commit()

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    since = get_failed_attempt_window(15)

    failed_attempts = db.query(
        LoginEvent
    ).filter(
        LoginEvent.email == email,
        LoginEvent.success == 0,
        LoginEvent.created_at >= since
    ).count()

    if not verify_password(
        data.password,
        user.password
    ):

        failed_attempts += 1

        anomaly = analyze_login_anomaly(
            failed_attempts,
            False
        )

        db.add(
            LoginEvent(
                user_id=user.id,
                email=user.email,
                success=0,
                ip_address=ip,
                user_agent=user_agent,
                risk_level=anomaly["risk_level"],
                anomaly_reason=anomaly["reason"]
            )
        )

        db.add(
            AuditLog(
                user_id=user.id,
                action="LOGIN_FAILED",
                details="Incorrect password",
                ip_address=ip
            )
        )

        db.commit()

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    anomaly = analyze_login_anomaly(
        failed_attempts,
        True
    )

    db.add(
        LoginEvent(
            user_id=user.id,
            email=user.email,
            success=1,
            ip_address=ip,
            user_agent=user_agent,
            risk_level=anomaly["risk_level"],
            anomaly_reason=anomaly["reason"]
        )
    )

    old_codes = db.query(
        MFACode
    ).filter(
        MFACode.user_id == user.id,
        MFACode.verified == 0
    ).all()

    for old_code in old_codes:
        old_code.verified = 1

    code = f"{secrets.randbelow(1000000):06d}"

    expires_at = (
        datetime.utcnow()
        + timedelta(minutes=5)
    )

    db.add(
        MFACode(
            user_id=user.id,
            code=code,
            expires_at=expires_at,
            verified=0
        )
    )

    db.add(
        AuditLog(
            user_id=user.id,
            action="MFA_CODE_GENERATED",
            details="MFA code generated",
            ip_address=ip
        )
    )

    deliver_mfa(email, code)
    db.commit()

    return {
        "mfa_challenge": create_token(user.id, "mfa", 300),
        "message": "Password verified. MFA required.",
        "mfa_required": True,
        "user": user_dict(user),
        **user_dict(user),
        "login_security": anomaly,
        "delivery": "local-demo" if is_local_demo() else "email"
    }




# ============================================================
# MFA VERIFICATION
# ============================================================

@app.post("/verify-mfa")
def verify_mfa(

    data: MFAVerifyRequest,

    request: Request,

    db: Session = Depends(get_db)

):

    try:
        challenge_user_id = read_token(data.challenge, purpose="mfa")
    except ValueError:
        raise HTTPException(401, "MFA challenge expired or invalid")
    if challenge_user_id != data.user_id:
        raise HTTPException(403, "MFA challenge does not match user")
    rate_limit(f"mfa:{data.user_id}:{client_ip(request)}", limit=6, window=300)

    user = db.query(
        User
    ).filter(
        User.id == data.user_id
    ).first()


    if not user:

        raise HTTPException(

            status_code=404,

            detail="User not found"

        )


    record = db.query(
        MFACode
    ).filter(

        MFACode.user_id ==
            user.id,

        MFACode.verified == 0

    ).order_by(

        MFACode.id.desc()

    ).first()


    if not record:

        raise HTTPException(

            status_code=400,

            detail="No active MFA code found"

        )


    if datetime.utcnow() > record.expires_at:

        record.verified = 1

        db.commit()


        raise HTTPException(

            status_code=400,

            detail="MFA code expired"

        )


    if str(data.code).strip() != str(
        record.code
    ).strip():

        raise HTTPException(

            status_code=400,

            detail="Invalid MFA code"

        )


    record.verified = 1


    db.add(

        AuditLog(

            user_id=user.id,

            action="MFA_VERIFIED",

            details=
                "MFA verification successful",

            ip_address=
                client_ip(request)

        )

    )


    db.commit()


    return {

        "message":
            "Login successful",

        "login_success":
            True,
        "access_token": create_token(user.id, "access", 3600),
        "token_type": "bearer",

        "user":
            user_dict(user),

        **user_dict(user)

    }


# ============================================================
# LOGIN EVENTS
# ============================================================

@app.get("/login-events")
def login_events(

    db: Session = Depends(get_db)

):

    events = db.query(
        LoginEvent
    ).order_by(
        LoginEvent.created_at.desc()
    ).all()


    return [

        {

            "id": x.id,

            "user_id": x.user_id,

            "email": x.email,

            "success": x.success,

            "ip_address":
                x.ip_address,

            "user_agent":
                x.user_agent,

            "risk_level":
                x.risk_level,

            "anomaly_reason":
                x.anomaly_reason,

            "created_at":
                x.created_at

        }

        for x in events

    ]


# ============================================================
# USER LOGIN EVENTS
# ============================================================

@app.get("/login-events/{user_id}")
def user_login_events(

    user_id: int,

    db: Session = Depends(get_db)

):

    existing_user = db.query(
        User
    ).filter(
        User.id == user_id
    ).first()


    if not existing_user:

        raise HTTPException(

            status_code=404,

            detail="User not found"

        )


    events = db.query(
        LoginEvent
    ).filter(
        LoginEvent.user_id == user_id
    ).order_by(
        LoginEvent.created_at.desc()
    ).all()


    return [

        {

            "id": x.id,

            "user_id": x.user_id,

            "email": x.email,

            "success": x.success,

            "ip_address":
                x.ip_address,

            "user_agent":
                x.user_agent,

            "risk_level":
                x.risk_level,

            "anomaly_reason":
                x.anomaly_reason,

            "created_at":
                x.created_at

        }

        for x in events

    ]


# ============================================================
# AUDIT LOGS
# ============================================================

@app.get("/audit-logs")
def audit_logs(

    db: Session = Depends(get_db)

):

    logs = db.query(
        AuditLog
    ).order_by(
        AuditLog.created_at.desc()
    ).all()


    return [

        {

            "id": x.id,

            "user_id": x.user_id,

            "action": x.action,

            "details": x.details,

            "ip_address":
                x.ip_address,

            "created_at":
                x.created_at

        }

        for x in logs

    ]


# ============================================================
# URL SCANNER
# ============================================================

@app.post("/scan-url")
def scan(

    data: URLScanRequest,

    request: Request,

    db: Session = Depends(get_db)

):

    if data.user_id != request.state.user_id and not request.state.is_admin:
        raise HTTPException(403, "Cannot submit data for another user")

    existing_user = db.query(
        User
    ).filter(
        User.id == data.user_id
    ).first()


    if not existing_user:

        raise HTTPException(

            status_code=404,

            detail="User not found"

        )


    try:

        result = scan_url(
            data.url
        )

    except Exception as e:

        raise HTTPException(

            status_code=400,

            detail=
                f"URL scanner error: {e}"

        )


    if not result.get(
        "valid",
        False
    ):

        raise HTTPException(

            status_code=400,

            detail=
                result.get(
                    "error",
                    "Invalid URL"
                )

        )


    indicators = result.get(
        "indicators",
        []
    )


    if isinstance(
        indicators,
        list
    ):

        indicators_text = ", ".join(
            map(
                str,
                indicators
            )
        )

    else:

        indicators_text = str(
            indicators
        )


    saved = URLScan(

        user_id=data.user_id,

        url=result.get(
            "url",
            data.url
        ),

        domain=result.get(
            "domain"
        ),

        protocol=result.get(
            "protocol"
        ),

        risk_level=result.get(
            "risk_level",
            "Low"
        ),

        risk_score=int(
            result.get(
                "risk_score",
                0
            )
        ),

        indicators=indicators_text,

        recommendation=result.get(
            "recommendation"
        )

    )


    db.add(saved)


    db.add(

        AuditLog(

            user_id=data.user_id,

            action="URL_SCANNED",

            details=
                f"Risk: {result.get('risk_level', 'Low')}",

            ip_address=
                client_ip(request)

        )

    )


    db.commit()

    db.refresh(saved)


    return {

        "message":
            "URL scanned successfully",

        "scan_id":
            saved.id,

        "result":
            result

    }


# ============================================================
# USER URL SCAN HISTORY
# ============================================================

@app.get("/url-scan-history/{user_id}")
def scan_history(

    user_id: int,

    db: Session = Depends(get_db)

):

    if not db.query(
        User
    ).filter(
        User.id == user_id
    ).first():

        raise HTTPException(

            status_code=404,

            detail="User not found"

        )


    scans = db.query(
        URLScan
    ).filter(
        URLScan.user_id == user_id
    ).order_by(
        URLScan.id.desc()
    ).all()


    return [

        {

            "id": x.id,

            "user_id":
                x.user_id,

            "url":
                x.url,

            "domain":
                x.domain,

            "protocol":
                x.protocol,

            "risk_level":
                x.risk_level,

            "risk_score":
                x.risk_score,

            "indicators":
                x.indicators,

            "recommendation":
                x.recommendation

        }

        for x in scans

    ]


# ============================================================
# ALL URL SCANS
# ============================================================

@app.get("/url-scans")
def all_scans(

    db: Session = Depends(get_db)

):

    scans = db.query(
        URLScan
    ).order_by(
        URLScan.id.desc()
    ).all()


    return [

        {

            "id": x.id,

            "user_id":
                x.user_id,

            "url":
                x.url,

            "domain":
                x.domain,

            "protocol":
                x.protocol,

            "risk_level":
                x.risk_level,

            "risk_score":
                x.risk_score,

            "indicators":
                x.indicators,

            "recommendation":
                x.recommendation

        }

        for x in scans

    ]


# ============================================================
# THREAT REPORT
# ============================================================

@app.post("/threat-report")
def report(

    data: ThreatReportCreate,

    request: Request,

    db: Session = Depends(get_db)

):

    if data.user_id != request.state.user_id and not request.state.is_admin:
        raise HTTPException(403, "Cannot submit data for another user")

    existing_user = db.query(
        User
    ).filter(
        User.id == data.user_id
    ).first()


    if not existing_user:

        raise HTTPException(

            status_code=404,

            detail="User not found"

        )


    if len(
        data.description.strip()
    ) < 5:

        raise HTTPException(

            status_code=400,

            detail="Description is too short"

        )


    threat_type = (
        data.threat_type.strip()
        or "Other"
    )


    try:

        detected = detect_threat(
            data.description.strip()
        )


        if isinstance(
            detected,
            str
        ) and detected.strip():

            threat_type = detected.strip()


    except Exception:

        pass


    report = ThreatReport(

        user_id=data.user_id,

        threat_type=threat_type,

        description=
            data.description.strip(),

        severity=
            data.severity or "Medium",

        status="Pending"

    )


    db.add(report)

    db.commit()

    db.refresh(report)


    db.add(

        AuditLog(

            user_id=data.user_id,

            action="THREAT_REPORTED",

            details=
                f"Report #{report.id} created",

            ip_address=
                client_ip(request)

        )

    )


    db.commit()


    return {

        "message":
            "Threat report submitted successfully",

        "report_id":
            report.id,

        "status":
            report.status

    }


@app.get("/threat-reports/{user_id}")
def own_reports(user_id: int, request: Request, db: Session = Depends(get_db)):
    if user_id != request.state.authenticated_user_id and not request.state.is_admin:
        raise HTTPException(403, "Access denied")
    items = db.query(ThreatReport).filter(ThreatReport.user_id == user_id).order_by(ThreatReport.id.desc()).all()
    return [{"id": x.id, "user_id": x.user_id, "threat_type": x.threat_type,
             "description": x.description, "severity": x.severity, "status": x.status} for x in items]

# ============================================================
# ALL THREAT REPORTS
# ============================================================

@app.get("/threat-reports")
def reports(

    db: Session = Depends(get_db)

):

    reports_data = db.query(
        ThreatReport
    ).order_by(
        ThreatReport.id.desc()
    ).all()


    return [

        {

            "id": x.id,

            "user_id":
                x.user_id,

            "threat_type":
                x.threat_type,

            "description":
                x.description,

            "severity":
                x.severity,

            "status":
                x.status

        }

        for x in reports_data

    ]


# ============================================================
# UPDATE THREAT STATUS
# ============================================================

@app.put(
    "/threat-report/{report_id}/status"
)
def report_status(

    report_id: int,

    status: str,

    request: Request,

    db: Session = Depends(get_db)

):

    report = db.query(
        ThreatReport
    ).filter(
        ThreatReport.id == report_id
    ).first()


    if not report:

        raise HTTPException(

            status_code=404,

            detail="Threat report not found"

        )


    allowed_statuses = [

        "Pending",

        "Investigating",

        "Resolved",

        "Rejected"

    ]


    if status not in allowed_statuses:

        raise HTTPException(

            status_code=400,

            detail="Invalid status"

        )


    old_status = report.status

    report.status = status


    db.add(

        AuditLog(

            user_id=
                report.user_id,

            action=
                "THREAT_STATUS_UPDATED",

            details=
                f"Report #{report.id}: {old_status} -> {status}",

            ip_address=
                client_ip(request)

        )

    )


    db.commit()


    return {

        "message":
            "Threat report status updated",

        "report_id":
            report.id,

        "old_status":
            old_status,

        "new_status":
            status

    }


# ============================================================
# ADMIN STATISTICS
# ============================================================

@app.get("/admin/stats")
def admin_stats(

    db: Session = Depends(get_db)

):

    return {

        "users":
            db.query(User).count(),

        "threat_reports":
            db.query(ThreatReport).count(),

        "pending_reports":
            db.query(
                ThreatReport
            ).filter(
                ThreatReport.status == "Pending"
            ).count(),

        "high_critical_reports":
            db.query(
                ThreatReport
            ).filter(
                ThreatReport.severity.in_(
                    ["High", "Critical"]
                )
            ).count(),

        "resolved_reports":
            db.query(
                ThreatReport
            ).filter(
                ThreatReport.status == "Resolved"
            ).count(),

        "login_events":
            db.query(LoginEvent).count(),

        "failed_logins":
            db.query(
                LoginEvent
            ).filter(
                LoginEvent.success == 0
            ).count(),

        "high_risk_logins":
            db.query(
                LoginEvent
            ).filter(
                LoginEvent.risk_level.in_(
                    ["High", "Critical"]
                )
            ).count(),

        "url_scans":
            db.query(URLScan).count(),

        "high_risk_urls":
            db.query(
                URLScan
            ).filter(
                URLScan.risk_level.in_(
                    ["High", "Critical"]
                )
            ).count(),

        "quiz_results":
            db.query(QuizResult).count()

    }
# ============================================================
# DASHBOARD OVERVIEW
# ============================================================

@app.get("/dashboard/overview")
def dashboard_overview(
    request: Request,
    db: Session = Depends(get_db)
):
    if not request.state.is_admin:
        uid = request.state.authenticated_user_id
        scans = db.query(URLScan).filter(URLScan.user_id == uid).order_by(URLScan.id.desc()).all()
        reports = db.query(ThreatReport).filter(ThreatReport.user_id == uid).order_by(ThreatReport.id.desc()).all()
        logins = db.query(LoginEvent).filter(LoginEvent.user_id == uid).all()
        high = sum(x.risk_level in ("High", "Critical") for x in scans)
        safe = sum(x.risk_level in ("Low", "Minimal", "Safe") for x in scans)
        return {
            "total_url_scans": len(scans), "total_threats": len(scans) + len(reports),
            "high_risk_urls": high, "safe_urls": safe,
            "failed_logins": sum(x.success == 0 for x in logins),
            "security_score": max(0, 100 - high * 10),
            "recent_threats": [{"id": x.id, "url": x.url, "risk_level": x.risk_level, "risk_score": x.risk_score} for x in scans[:10]],
            "recent_activity": [], "alerts": [],
        }
    """Return the live data required by the AEGIS dashboard."""

    # -----------------------------
    # URL scan statistics
    # -----------------------------
    total_url_scans = db.query(URLScan).count()

    critical_urls = db.query(URLScan).filter(
        URLScan.risk_level == "Critical"
    ).count()

    high_urls = db.query(URLScan).filter(
        URLScan.risk_level == "High"
    ).count()

    medium_urls = db.query(URLScan).filter(
        URLScan.risk_level == "Medium"
    ).count()

    low_urls = db.query(URLScan).filter(
        URLScan.risk_level == "Low"
    ).count()

    minimal_urls = db.query(URLScan).filter(
        URLScan.risk_level == "Minimal"
    ).count()

    high_risk_urls = critical_urls + high_urls
    safe_urls = low_urls + minimal_urls

    # -----------------------------
    # Incident statistics
    # -----------------------------
    total_threat_reports = db.query(ThreatReport).count()

    pending_reports = db.query(ThreatReport).filter(
        ThreatReport.status == "Pending"
    ).count()

    critical_reports = db.query(ThreatReport).filter(
        ThreatReport.severity == "Critical"
    ).count()

    high_reports = db.query(ThreatReport).filter(
        ThreatReport.severity == "High"
    ).count()

    # -----------------------------
    # Login statistics
    # -----------------------------
    failed_logins = db.query(LoginEvent).filter(
        LoginEvent.success == 0
    ).count()

    successful_logins = db.query(LoginEvent).filter(
        LoginEvent.success == 1
    ).count()

    # -----------------------------
    # SECURITY SCORE
    # -----------------------------
    score = 100

    score -= critical_urls * 12
    score -= high_urls * 7
    score -= medium_urls * 2

    score -= critical_reports * 10
    score -= high_reports * 6

    score -= failed_logins * 2

    score = max(0, min(100, score))

    if score >= 85:
        security_status = "Secure"
    elif score >= 70:
        security_status = "Good"
    elif score >= 50:
        security_status = "Needs attention"
    elif score >= 25:
        security_status = "At risk"
    else:
        security_status = "Critical"

    # -----------------------------
    # THREAT DISTRIBUTION
    # -----------------------------
    threat_distribution = {
        "Critical": critical_urls,
        "High": high_urls,
        "Medium": medium_urls,
        "Low": low_urls,
        "Minimal": minimal_urls
    }

    # -----------------------------
    # RECENT URL SCANS
    # -----------------------------
    recent_scans = db.query(URLScan).order_by(
        URLScan.id.desc()
    ).limit(10).all()

    # -----------------------------
    # RECENT INCIDENT REPORTS
    # -----------------------------
    recent_reports = db.query(ThreatReport).order_by(
        ThreatReport.id.desc()
    ).limit(10).all()

    recent_threats = []

    for scan_item in recent_scans:

        recent_threats.append({
            "id": scan_item.id,
            "type": "URL Scan",
            "url": scan_item.url,
            "domain": scan_item.domain,
            "severity": scan_item.risk_level or "Low",
            "status": "Analyzed",
            "description": (
                scan_item.recommendation
                or "URL analyzed by AEGIS."
            )
        })

    for report_item in recent_reports:

        recent_threats.append({
            "id": report_item.id,
            "type": report_item.threat_type or "Threat Report",
            "url": None,
            "domain": None,
            "severity": report_item.severity or "Medium",
            "status": report_item.status or "Pending",
            "description": report_item.description
        })

    recent_threats = recent_threats[:10]

    # -----------------------------
    # SECURITY ALERTS
    # -----------------------------
    alerts = []

    for scan_item in recent_scans:

        if scan_item.risk_level in [
            "Critical",
            "High"
        ]:

            alerts.append({
                "severity": scan_item.risk_level,
                "title": (
                    f"{scan_item.risk_level} URL detected"
                ),
                "description": (
                    f"{scan_item.domain or scan_item.url} "
                    f"received a risk score of "
                    f"{scan_item.risk_score}."
                )
            })

    for report_item in recent_reports:

        if report_item.severity in [
            "Critical",
            "High"
        ]:

            alerts.append({
                "severity": report_item.severity,
                "title": (
                    f"{report_item.severity} incident reported"
                ),
                "description": report_item.description
            })

    # -----------------------------
    # RECENT FAILED LOGINS
    # -----------------------------
    recent_failed = db.query(LoginEvent).filter(
        LoginEvent.success == 0
    ).order_by(
        LoginEvent.id.desc()
    ).limit(5).all()

    for login_item in recent_failed:

        if login_item.risk_level in [
            "High",
            "Critical"
        ]:

            alerts.append({
                "severity": login_item.risk_level,
                "title": "Suspicious login activity",
                "description": (
                    login_item.anomaly_reason
                    or "Repeated failed login attempts detected."
                )
            })

    alerts = alerts[:5]

    # -----------------------------
    # RECENT AUDIT ACTIVITY
    # -----------------------------
    recent_logs = db.query(AuditLog).order_by(
        AuditLog.id.desc()
    ).limit(10).all()

    recent_activity = [

        {
            "id": log.id,
            "action": log.action,
            "details": log.details or "",
            "created_at": log.created_at
        }

        for log in recent_logs
    ]

    # -----------------------------
    # FINAL DASHBOARD RESPONSE
    # -----------------------------
    return {

        "statistics": {

            "total_url_scans":
                total_url_scans,

            "total_threat_reports":
                total_threat_reports,

            "high_risk_urls":
                high_risk_urls,

            "safe_urls":
                safe_urls,

            "failed_logins":
                failed_logins,

            "successful_logins":
                successful_logins,

            "pending_reports":
                pending_reports,

            "critical_reports":
                critical_reports,

            "high_reports":
                high_reports
        },

        "security_score":
            score,

        "security_status":
            security_status,

        "threat_distribution":
            threat_distribution,

        "alerts":
            alerts,

        "recent_threats":
            recent_threats,

        "recent_activity":
            recent_activity
    }

# ============================================================
# GET USER
# ============================================================

@app.get("/users/{user_id}")
def get_user(

    user_id: int,

    db: Session = Depends(get_db)

):

    user = db.query(
        User
    ).filter(
        User.id == user_id
    ).first()


    if not user:

        raise HTTPException(

            status_code=404,

            detail="User not found"

        )


    return user_dict(user)
    # ============================================================
# PHISHING EMAIL ANALYZER
# ============================================================

@app.post("/analyze-email")
async def analyze_email(
    file: UploadFile = File(...)
):

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="No email file was provided."
        )

    if not file.filename.lower().endswith(".eml"):

        raise HTTPException(
            status_code=400,
            detail="Only .eml email files are supported."
        )

    temp_path = None

    try:

        file_content = await file.read()

        if not file_content:

            raise HTTPException(
                status_code=400,
                detail="The email file is empty."
            )

        if len(file_content) > 10 * 1024 * 1024:

            raise HTTPException(
                status_code=400,
                detail="Email file is larger than the 10 MB limit."
            )

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".eml"
        ) as temp_file:

            temp_file.write(
                file_content
            )

            temp_path = temp_file.name

        analysis = analyze_eml_file(
            temp_path
        )

        analysis["filename"] = file.filename

        return analysis

    except HTTPException:

        raise

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"Email analysis failed: {error}"
        )

    finally:

        if temp_path and os.path.exists(
            temp_path
        ):

            try:

                os.remove(
                    temp_path
                )

            except Exception:

                pass
# ============================================================
# AI FACT CHECKER
# ============================================================

@app.post("/fact-check")
def fact_check(
    data: FactCheckRequest,
):
    try:
        result = fact_check_text(data.text)

        if not result.get("success"):
            raise HTTPException(
                status_code=400,
                detail=result.get(
                    "message",
                    "Fact checking failed."
                ),
            )

        return result

    except HTTPException:
        raise

    except Exception as error:
        print(
            "AEGIS FACT CHECK ERROR:",
            repr(error)
        )

        raise HTTPException(
            status_code=500,
            detail="Fact checker encountered an internal error.",
        )

# ============================================================
# SERVER START MESSAGE
# ============================================================

print(
    "AEGIS Backend Started Successfully"
)