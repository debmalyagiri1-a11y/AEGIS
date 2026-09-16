from fastapi import FastAPI, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from datetime import datetime, timedelta
import random

from backend.database import Base, engine, SessionLocal

from backend.models import (
    User,
    ThreatReport,
    URLScan,
    LoginEvent,
    AuditLog,
    MFACode
)

from backend.schemas import (
    UserCreate,
    UserLogin,
    ThreatReportCreate,
    URLScanRequest,
    MFAVerifyRequest
)

from backend.detector import (
    detect_threat,
    scan_url
)

from backend.security import (
    analyze_login_anomaly,
    get_failed_attempt_window
)


# ============================================================
# AEGIS APPLICATION
# ============================================================

app = FastAPI(
    title="AEGIS",
    description="AI-Powered Smart Campus Cybersecurity System",
    version="1.2"
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
    schemes=["pbkdf2_sha256"],
    deprecated="auto"
)


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
# AUDIT LOG HELPER
# ============================================================

def create_audit_log(
    db: Session,
    user_id: int | None,
    action: str,
    details: str = "",
    ip_address: str | None = None
):

    log = AuditLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=ip_address
    )

    db.add(log)


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():

    return {

        "project":
            "AEGIS",

        "name":
            "AI-Powered Smart Campus Cybersecurity System",

        "status":
            "Backend is running",

        "database":
            "Connected"

    }


# ============================================================
# USER REGISTRATION
# ============================================================

@app.post("/register")
def register(

    user: UserCreate,

    request: Request,

    db: Session = Depends(get_db)

):

    existing_user = db.query(
        User
    ).filter(
        User.email == user.email
    ).first()


    if existing_user:

        raise HTTPException(

            status_code=400,

            detail=
                "Email already registered"

        )


    hashed_password = pwd_context.hash(
        user.password
    )


    new_user = User(

        name=user.name,

        email=user.email,

        password=hashed_password,

        role="student"

    )


    db.add(new_user)

    db.commit()

    db.refresh(new_user)


    create_audit_log(

        db=db,

        user_id=new_user.id,

        action="USER_REGISTERED",

        details=
            f"New user registered: {new_user.email}",

        ip_address=
            request.client.host
            if request.client
            else None

    )


    db.commit()


    return {

        "message":
            "Registration successful",

        "user_id":
            new_user.id,

        "name":
            new_user.name,

        "email":
            new_user.email,

        "role":
            new_user.role

    }


# ============================================================
# USER LOGIN
# ============================================================

@app.post("/login")
def login(

    user: UserLogin,

    request: Request,

    db: Session = Depends(get_db)

):

    ip_address = (

        request.client.host

        if request.client

        else None

    )


    user_agent = request.headers.get(

        "user-agent",

        "Unknown"

    )


    # --------------------------------------------------------
    # FIND USER
    # --------------------------------------------------------

    existing_user = db.query(
        User
    ).filter(
        User.email == user.email
    ).first()


    # --------------------------------------------------------
    # UNKNOWN EMAIL
    # --------------------------------------------------------

    if not existing_user:

        window_start = (
            get_failed_attempt_window(15)
        )


        failed_attempts = db.query(
            LoginEvent
        ).filter(

            LoginEvent.email == user.email,

            LoginEvent.success == 0,

            LoginEvent.created_at >= window_start

        ).count()


        failed_attempts += 1


        anomaly = analyze_login_anomaly(

            failed_attempts=failed_attempts

        )


        login_event = LoginEvent(

            user_id=None,

            email=user.email,

            success=0,

            ip_address=ip_address,

            user_agent=user_agent,

            risk_level=
                anomaly["risk_level"],

            anomaly_reason=
                anomaly["reason"],

            created_at=datetime.utcnow()

        )


        db.add(login_event)


        create_audit_log(

            db=db,

            user_id=None,

            action="FAILED_LOGIN",

            details=(

                f"Unknown email. "

                f"Risk: "
                f"{anomaly['risk_level']}. "

                f"Reason: "
                f"{anomaly['reason']}"

            ),

            ip_address=ip_address

        )


        db.commit()


        raise HTTPException(

            status_code=401,

            detail=
                "Invalid email or password"

        )


    # --------------------------------------------------------
    # PASSWORD VERIFICATION
    # --------------------------------------------------------

    password_correct = pwd_context.verify(

        user.password,

        existing_user.password

    )


    # --------------------------------------------------------
    # WRONG PASSWORD
    # --------------------------------------------------------

    if not password_correct:

        window_start = (
            get_failed_attempt_window(15)
        )


        failed_attempts = db.query(
            LoginEvent
        ).filter(

            LoginEvent.user_id ==
                existing_user.id,

            LoginEvent.success == 0,

            LoginEvent.created_at >=
                window_start

        ).count()


        failed_attempts += 1


        anomaly = analyze_login_anomaly(

            failed_attempts=
                failed_attempts

        )


        login_event = LoginEvent(

            user_id=
                existing_user.id,

            email=
                existing_user.email,

            success=0,

            ip_address=
                ip_address,

            user_agent=
                user_agent,

            risk_level=
                anomaly["risk_level"],

            anomaly_reason=
                anomaly["reason"],

            created_at=
                datetime.utcnow()

        )


        db.add(login_event)


        create_audit_log(

            db=db,

            user_id=
                existing_user.id,

            action=
                "FAILED_LOGIN",

            details=(

                f"Failed password attempt. "

                f"Attempts in last 15 minutes: "

                f"{failed_attempts}. "

                f"Risk: "

                f"{anomaly['risk_level']}"

            ),

            ip_address=
                ip_address

        )


        db.commit()


        raise HTTPException(

            status_code=401,

            detail=
                "Invalid email or password"

        )


    # ========================================================
    # PASSWORD CORRECT
    # ========================================================

    previous_success = (

        db.query(
            LoginEvent
        ).filter(

            LoginEvent.user_id ==
                existing_user.id,

            LoginEvent.success == 1

        ).first()

        is not None

    )


    anomaly = analyze_login_anomaly(

        failed_attempts=0,

        previous_success=
            previous_success

    )


    # --------------------------------------------------------
    # LOGIN EVENT
    # --------------------------------------------------------

    login_event = LoginEvent(

        user_id=
            existing_user.id,

        email=
            existing_user.email,

        success=1,

        ip_address=
            ip_address,

        user_agent=
            user_agent,

        risk_level=
            anomaly["risk_level"],

        anomaly_reason=
            anomaly["reason"],

        created_at=
            datetime.utcnow()

    )


    db.add(login_event)


    # --------------------------------------------------------
    # GENERATE MFA CODE
    # --------------------------------------------------------

    mfa_code = str(
        random.randint(
            100000,
            999999
        )
    )


    expires_at = (
        datetime.utcnow()
        + timedelta(minutes=5)
    )


    # --------------------------------------------------------
    # REMOVE OLD UNUSED CODES
    # --------------------------------------------------------

    old_codes = db.query(
        MFACode
    ).filter(

        MFACode.user_id ==
            existing_user.id,

        MFACode.verified == 0

    ).all()


    for old_code in old_codes:

        old_code.verified = 1


    # --------------------------------------------------------
    # SAVE NEW MFA CODE
    # --------------------------------------------------------

    new_mfa = MFACode(

        user_id=
            existing_user.id,

        code=
            mfa_code,

        expires_at=
            expires_at,

        verified=0

    )


    db.add(new_mfa)


    create_audit_log(

        db=db,

        user_id=
            existing_user.id,

        action=
            "MFA_CODE_GENERATED",

        details=
            "MFA verification code generated.",

        ip_address=
            ip_address

    )


    db.commit()


    # --------------------------------------------------------
    # RETURN MFA REQUIRED
    # --------------------------------------------------------

    return {

        "message":
            "Password verified. MFA verification required.",

        "mfa_required":
            True,

        "user_id":
            existing_user.id,

        "name":
            existing_user.name,

        "email":
            existing_user.email,

        "role":
            existing_user.role,

        "login_security": {

            "risk_level":
                anomaly["risk_level"],

            "reason":
                anomaly["reason"]

        },

        # DEVELOPMENT / TESTING ONLY
        "demo_mfa_code":
            mfa_code

    }


# ============================================================
# MFA VERIFICATION
# ============================================================

@app.post("/verify-mfa")
def verify_mfa(

    request_data: MFAVerifyRequest,

    request: Request,

    db: Session = Depends(get_db)

):

    ip_address = (

        request.client.host

        if request.client

        else None

    )


    # --------------------------------------------------------
    # CHECK USER
    # --------------------------------------------------------

    existing_user = db.query(
        User
    ).filter(
        User.id ==
            request_data.user_id
    ).first()


    if not existing_user:

        raise HTTPException(

            status_code=404,

            detail=
                "User not found"

        )


    # --------------------------------------------------------
    # FIND LATEST UNUSED CODE
    # --------------------------------------------------------

    mfa = db.query(
        MFACode
    ).filter(

        MFACode.user_id ==
            request_data.user_id,

        MFACode.verified == 0

    ).order_by(

        MFACode.id.desc()

    ).first()


    if not mfa:

        create_audit_log(

            db=db,

            user_id=
                existing_user.id,

            action=
                "MFA_FAILED",

            details=
                "No active MFA code found.",

            ip_address=
                ip_address

        )


        db.commit()


        raise HTTPException(

            status_code=401,

            detail=
                "No active MFA code found"

        )


    # --------------------------------------------------------
    # CHECK EXPIRATION
    # --------------------------------------------------------

    if datetime.utcnow() > mfa.expires_at:

        mfa.verified = 1


        create_audit_log(

            db=db,

            user_id=
                existing_user.id,

            action=
                "MFA_FAILED",

            details=
                "MFA code expired.",

            ip_address=
                ip_address

        )


        db.commit()


        raise HTTPException(

            status_code=401,

            detail=
                "MFA code has expired"

        )


    # --------------------------------------------------------
    # CHECK CODE
    # --------------------------------------------------------

    if request_data.code != mfa.code:

        create_audit_log(

            db=db,

            user_id=
                existing_user.id,

            action=
                "MFA_FAILED",

            details=
                "Incorrect MFA code.",

            ip_address=
                ip_address

        )


        db.commit()


        raise HTTPException(

            status_code=401,

            detail=
                "Invalid MFA code"

        )


    # --------------------------------------------------------
    # MFA SUCCESS
    # --------------------------------------------------------

    mfa.verified = 1


    create_audit_log(

        db=db,

        user_id=
            existing_user.id,

        action=
            "MFA_VERIFIED",

        details=
            "Multi-factor authentication completed.",

        ip_address=
            ip_address

    )


    db.commit()


    return {

        "message":
            "MFA verification successful",

        "login_success":
            True,

        "user_id":
            existing_user.id,

        "name":
            existing_user.name,

        "email":
            existing_user.email,

        "role":
            existing_user.role

    }


# ============================================================
# LOGIN EVENTS
# ============================================================

@app.get("/login-events")
def get_login_events(

    db: Session = Depends(get_db)

):

    events = db.query(
        LoginEvent
    ).order_by(
        LoginEvent.id.desc()
    ).all()


    return [

        {

            "id":
                event.id,

            "user_id":
                event.user_id,

            "email":
                event.email,

            "success":
                bool(event.success),

            "ip_address":
                event.ip_address,

            "user_agent":
                event.user_agent,

            "risk_level":
                event.risk_level,

            "anomaly_reason":
                event.anomaly_reason,

            "created_at":
                event.created_at.isoformat()
                if event.created_at
                else None

        }

        for event in events

    ]


# ============================================================
# USER LOGIN EVENTS
# ============================================================

@app.get("/login-events/{user_id}")
def get_user_login_events(

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

            detail=
                "User not found"

        )


    events = db.query(
        LoginEvent
    ).filter(
        LoginEvent.user_id ==
            user_id
    ).order_by(
        LoginEvent.id.desc()
    ).all()


    return [

        {

            "id":
                event.id,

            "user_id":
                event.user_id,

            "email":
                event.email,

            "success":
                bool(event.success),

            "ip_address":
                event.ip_address,

            "user_agent":
                event.user_agent,

            "risk_level":
                event.risk_level,

            "anomaly_reason":
                event.anomaly_reason,

            "created_at":
                event.created_at.isoformat()
                if event.created_at
                else None

        }

        for event in events

    ]


# ============================================================
# AUDIT LOGS
# ============================================================

@app.get("/audit-logs")
def get_audit_logs(

    db: Session = Depends(get_db)

):

    logs = db.query(
        AuditLog
    ).order_by(
        AuditLog.id.desc()
    ).all()


    return [

        {

            "id":
                log.id,

            "user_id":
                log.user_id,

            "action":
                log.action,

            "details":
                log.details,

            "ip_address":
                log.ip_address,

            "created_at":
                log.created_at.isoformat()
                if log.created_at
                else None

        }

        for log in logs

    ]


# ============================================================
# URL SCANNER
# ============================================================

@app.post("/scan-url")
def scan_url_endpoint(

    request: URLScanRequest,

    db: Session = Depends(get_db)

):

    existing_user = db.query(
        User
    ).filter(
        User.id ==
            request.user_id
    ).first()


    if not existing_user:

        raise HTTPException(

            status_code=404,

            detail=
                "User not found"

        )


    result = scan_url(
        request.url
    )


    if not result["valid"]:

        return {

            "message":
                "URL scan completed",

            "result":
                result

        }


    indicators_text = " | ".join(
        result["indicators"]
    )


    new_scan = URLScan(

        user_id=
            request.user_id,

        url=
            result["url"],

        domain=
            result["domain"],

        protocol=
            result["protocol"],

        risk_level=
            result["risk_level"],

        risk_score=
            result["risk_score"],

        indicators=
            indicators_text,

        recommendation=
            result["recommendation"]

    )


    db.add(new_scan)


    create_audit_log(

        db=db,

        user_id=
            request.user_id,

        action=
            "URL_SCAN",

        details=(

            f"Scanned {result['url']} | "

            f"Risk: {result['risk_level']} | "

            f"Score: {result['risk_score']}"

        )

    )


    db.commit()

    db.refresh(new_scan)


    return {

        "message":
            "URL scan completed and saved",

        "scan_id":
            new_scan.id,

        "result":
            result

    }


# ============================================================
# USER URL SCAN HISTORY
# ============================================================

@app.get("/url-scan-history/{user_id}")
def get_user_scan_history(

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

            detail=
                "User not found"

        )


    scans = db.query(
        URLScan
    ).filter(
        URLScan.user_id ==
            user_id
    ).order_by(
        URLScan.id.desc()
    ).all()


    return [

        {

            "id":
                scan.id,

            "user_id":
                scan.user_id,

            "url":
                scan.url,

            "domain":
                scan.domain,

            "protocol":
                scan.protocol,

            "risk_level":
                scan.risk_level,

            "risk_score":
                scan.risk_score,

            "indicators":
                scan.indicators,

            "recommendation":
                scan.recommendation

        }

        for scan in scans

    ]


# ============================================================
# ALL URL SCANS
# ============================================================

@app.get("/url-scans")
def get_all_url_scans(

    db: Session = Depends(get_db)

):

    scans = db.query(
        URLScan
    ).order_by(
        URLScan.id.desc()
    ).all()


    return [

        {

            "id":
                scan.id,

            "user_id":
                scan.user_id,

            "url":
                scan.url,

            "domain":
                scan.domain,

            "protocol":
                scan.protocol,

            "risk_level":
                scan.risk_level,

            "risk_score":
                scan.risk_score,

            "indicators":
                scan.indicators,

            "recommendation":
                scan.recommendation

        }

        for scan in scans

    ]


# ============================================================
# THREAT REPORT
# ============================================================

@app.post("/threat-report")
def create_threat_report(

    report: ThreatReportCreate,

    db: Session = Depends(get_db)

):

    existing_user = db.query(
        User
    ).filter(
        User.id ==
            report.user_id
    ).first()


    if not existing_user:

        raise HTTPException(

            status_code=404,

            detail=
                "User not found"

        )


    detection_result = detect_threat(

        report.threat_type,

        report.description

    )


    detected_type = detection_result[
        "detected_type"
    ]


    detected_risk = detection_result[
        "risk_level"
    ]


    matched_keywords = detection_result[
        "matched_keywords"
    ]


    new_report = ThreatReport(

        user_id=
            report.user_id,

        threat_type=
            detected_type,

        description=
            report.description,

        severity=
            detected_risk,

        status=
            "Pending"

    )


    db.add(new_report)


    create_audit_log(

        db=db,

        user_id=
            report.user_id,

        action=
            "THREAT_REPORTED",

        details=(

            f"Threat type: "
            f"{detected_type} | "

            f"Risk: "
            f"{detected_risk}"

        )

    )


    db.commit()

    db.refresh(new_report)


    return {

        "message":
            "Threat report submitted successfully",

        "report_id":
            new_report.id,

        "status":
            new_report.status,

        "original_threat_type":
            report.threat_type,

        "detected_threat_type":
            detected_type,

        "risk_level":
            detected_risk,

        "matched_keywords":
            matched_keywords

    }


# ============================================================
# ALL THREAT REPORTS
# ============================================================

@app.get("/threat-reports")
def get_threat_reports(

    db: Session = Depends(get_db)

):

    reports = db.query(
        ThreatReport
    ).order_by(
        ThreatReport.id.desc()
    ).all()


    return [

        {

            "id":
                report.id,

            "user_id":
                report.user_id,

            "threat_type":
                report.threat_type,

            "description":
                report.description,

            "severity":
                report.severity,

            "status":
                report.status

        }

        for report in reports

    ]


# ============================================================
# UPDATE THREAT STATUS
# ============================================================

@app.put("/threat-report/{report_id}/status")
def update_threat_status(

    report_id: int,

    status: str,

    db: Session = Depends(get_db)

):

    report = db.query(
        ThreatReport
    ).filter(
        ThreatReport.id ==
            report_id
    ).first()


    if not report:

        raise HTTPException(

            status_code=404,

            detail=
                "Threat report not found"

        )


    allowed_statuses = [

        "Pending",

        "Investigating",

        "Resolved"

    ]


    if status not in allowed_statuses:

        raise HTTPException(

            status_code=400,

            detail=(

                "Invalid status. "

                "Use Pending, Investigating "
                "or Resolved."

            )

        )


    old_status = report.status


    report.status = status


    create_audit_log(

        db=db,

        user_id=
            report.user_id,

        action=
            "THREAT_STATUS_UPDATED",

        details=(

            f"Report #{report.id}: "

            f"{old_status} -> {status}"

        )

    )


    db.commit()

    db.refresh(report)


    return {

        "message":
            "Threat report status updated successfully",

        "report_id":
            report.id,

        "status":
            report.status

    }