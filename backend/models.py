from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime

from backend.database import Base


class User(Base):

    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    name = Column(
        String,
        nullable=False
    )

    email = Column(
        String,
        unique=True,
        index=True,
        nullable=False
    )

    password = Column(
        String,
        nullable=False
    )

    role = Column(
        String,
        default="student"
    )


class ThreatReport(Base):

    __tablename__ = "threat_reports"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        nullable=False
    )

    threat_type = Column(
        String,
        nullable=False
    )

    description = Column(
        String,
        nullable=False
    )

    severity = Column(
        String,
        default="Medium"
    )

    status = Column(
        String,
        default="Pending"
    )


class URLScan(Base):

    __tablename__ = "url_scans"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        nullable=False
    )

    url = Column(
        String,
        nullable=False
    )

    domain = Column(
        String,
        nullable=True
    )

    protocol = Column(
        String,
        nullable=True
    )

    risk_level = Column(
        String,
        nullable=False
    )

    risk_score = Column(
        Integer,
        nullable=False
    )

    indicators = Column(
        String,
        nullable=True
    )

    recommendation = Column(
        String,
        nullable=True
    )


# ==========================================
# LOGIN EVENTS
# ==========================================

class LoginEvent(Base):

    __tablename__ = "login_events"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        nullable=True
    )

    email = Column(
        String,
        nullable=False
    )

    success = Column(
        Integer,
        default=0
    )

    ip_address = Column(
        String,
        nullable=True
    )

    user_agent = Column(
        String,
        nullable=True
    )

    risk_level = Column(
        String,
        default="Low"
    )

    anomaly_reason = Column(
        String,
        nullable=True
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


# ==========================================
# MFA CODES
# ==========================================

class MFACode(Base):

    __tablename__ = "mfa_codes"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        nullable=False
    )

    code = Column(
        String,
        nullable=False
    )

    expires_at = Column(
        DateTime,
        nullable=False
    )

    verified = Column(
        Integer,
        default=0
    )


# ==========================================
# AUDIT LOGS
# ==========================================

class AuditLog(Base):

    __tablename__ = "audit_logs"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        nullable=True
    )

    action = Column(
        String,
        nullable=False
    )

    details = Column(
        String,
        nullable=True
    )

    ip_address = Column(
        String,
        nullable=True
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


# ==========================================
# AWARENESS QUIZ RESULTS
# ==========================================

class QuizResult(Base):

    __tablename__ = "quiz_results"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        nullable=False
    )

    score = Column(
        Integer,
        nullable=False
    )

    total_questions = Column(
        Integer,
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )