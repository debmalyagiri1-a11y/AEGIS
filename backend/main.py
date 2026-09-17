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

import random
import os
import tempfile

from backend.email_analyzer import analyze_eml_file

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
    MFAVerifyRequest
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
    allow_origins=["*"],
    allow_credentials=True,
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
    schemes=["bcrypt"],
    deprecated="auto"
)


def hash_password(password: str):
    print("AEGIS DEBUG - password byte length:", len(password.encode("utf-8")))
    return pwd_context.hash(password)
    password_bytes = password.encode("utf-8")

    if len(password_bytes) > 72:
        password = password_bytes[:72].decode(
            "utf-8",
            errors="ignore"
        )

    return pwd_context.hash(password)

def verify_password(
    password: str,
    stored_password: str
):

    if not stored_password:

        return False

    try:

        if stored_password.startswith(
            ("$2a$", "$2b$", "$2y$")
        ):

            return pwd_context.verify(
                password,
                stored_password
            )

        return password == stored_password

    except Exception:

        return False


# ============================================================
# DEFAULT ADMIN ACCOUNT
# ============================================================

def create_default_admin():

    db = SessionLocal()

    try:

        admin_email = "admin@aegis.com"

        existing_admin = db.query(
            User
        ).filter(
            User.email == admin_email
        ).first()

        if existing_admin:

            print(
                "AEGIS admin account already exists"
            )

            return

        admin = User(

            name="AEGIS Administrator",

            email=admin_email,

            password=hash_password(
                "Admin@123"
            ),

            role="admin"

        )

        db.add(admin)

        db.commit()

        print(
            "Default AEGIS admin account created successfully"
        )

    except Exception as e:

        db.rollback()

        print(
            f"Admin creation error: {e}"
        )

    finally:

        db.close()


# Create admin when backend starts
create_default_admin()


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


        if len(data.password) < 6:

            raise HTTPException(
                status_code=400,
                detail="Password must contain at least 6 characters"
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

    code = str(
        random.randint(
            100000,
            999999
        )
    )

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

    db.commit()

    return {
        "message": "Password verified. MFA required.",
        "mfa_required": True,
        "user": user_dict(user),
        **user_dict(user),
        "login_security": anomaly,
        "demo_mfa_code": code
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
# SERVER START MESSAGE
# ============================================================

print(
    "AEGIS Backend Started Successfully"
)