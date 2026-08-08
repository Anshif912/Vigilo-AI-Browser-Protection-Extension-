import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Text, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from database.db import Base

def generate_uuid():
    return str(uuid.uuid4())

def current_iso_timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    target_brand = Column(String(255), nullable=False)
    attack_type = Column(String(255), nullable=False)
    status = Column(String(50), default="ACTIVE")
    state = Column(String(50), default="NEW")  # NEW | UNDER_REVIEW | RESOLVED
    threat_level = Column(String(50), default="Critical")
    first_seen = Column(String(50), default=current_iso_timestamp)
    last_seen = Column(String(50), default=current_iso_timestamp)
    occurrences = Column(Integer, default=1)
    created_at = Column(String(50), default=current_iso_timestamp)

    # Relationships
    threat_records = relationship("ThreatRecord", back_populates="campaign", cascade="all, delete-orphan")
    timeline_events = relationship("ThreatTimeline", back_populates="campaign", cascade="all, delete-orphan")

class ThreatRecord(Base):
    __tablename__ = "threat_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    campaign_id = Column(String(36), ForeignKey("campaigns.id"), nullable=True)
    analysis_id = Column(String(100), nullable=False, index=True)
    timestamp = Column(String(50), default=current_iso_timestamp)
    url = Column(Text, nullable=False)
    domain = Column(String(255), nullable=False, index=True)
    status = Column(String(50), nullable=False)  # Critical | Suspicious
    threat_score = Column(Integer, nullable=False)
    website_identity = Column(String(255), nullable=False)
    attack_type = Column(String(255), nullable=False)
    reason = Column(Text, nullable=False)
    information_at_risk = Column(Text, nullable=True)  # JSON encoded list
    why_blocked = Column(Text, nullable=True)          # JSON encoded list
    recommended_action = Column(Text, nullable=True)
    browser = Column(String(100), default="Chrome")

    # v2.5 Enterprise Single Source of Truth Fields
    category = Column(String(100), default="Credential Phishing")
    sub_category = Column(String(100), default="Subdomain Impersonation")
    confidence = Column(Integer, default=85)
    confidence_level = Column(String(50), default="High")
    risk_reasoning_summary = Column(Text, nullable=True)
    score_breakdown_json = Column(Text, nullable=True)     # JSON encoded list of factor objects
    structured_evidence_json = Column(Text, nullable=True) # JSON encoded evidence object
    ioc_json = Column(Text, nullable=True)                 # JSON encoded IOC object
    analysis_trace_json = Column(Text, nullable=True)     # JSON encoded trace list
    data_provenance_json = Column(Text, nullable=True)     # JSON encoded provenance object
    threat_fingerprint = Column(String(255), nullable=True)
    # v3.1 Enterprise Connection Security & Overall Status Fields
    connection_security = Column(String(50), default="Secure")
    transport_protocol = Column(String(50), default="HTTPS")
    tls_status = Column(String(50), default="TLS 1.3 / Enabled")
    security_reason = Column(Text, nullable=True)
    overall_status = Column(String(50), default="Safe")

    engine_version = Column(String(50), default="3.1.0")
    feature_schema = Column(String(50), default="3.1")
    brand_db_version = Column(String(50), default="2026.07")
    external_intel_json = Column(Text, nullable=True)       # JSON encoded threat feeds map

    # Phase 2.5 Enhancements
    campaign_confidence = Column(Integer, default=90)
    confidence_factors = Column(Text, nullable=True)  # JSON encoded list of factor objects
    investigation_ready = Column(Boolean, default=False)
    investigation_completeness = Column(Integer, default=0) # 0 to 100 percentage
    processing_status = Column(String(50), default="PENDING")  # PENDING | PROCESSING | COMPLETE | FAILED
    pipeline_started_at = Column(String(50), nullable=True)
    pipeline_completed_at = Column(String(50), nullable=True)
    processing_duration_ms = Column(Integer, default=0)
    pipeline_stages = Column(Text, nullable=True)     # JSON encoded list of stage statuses
    pipeline_version = Column(Integer, default=1)
    schema_version = Column(Integer, default=1)
    created_at = Column(String(50), default=current_iso_timestamp)

    # Relationships
    campaign = relationship("Campaign", back_populates="threat_records")
    evidence = relationship("ThreatEvidence", back_populates="threat", uselist=False, cascade="all, delete-orphan")
    score_breakdown = relationship("ThreatScoreBreakdown", back_populates="threat", uselist=False, cascade="all, delete-orphan")
    ioc = relationship("ThreatIOC", back_populates="threat", uselist=False, cascade="all, delete-orphan")
    tags = relationship("ThreatTag", back_populates="threat", cascade="all, delete-orphan")
    timeline_events = relationship("ThreatTimeline", back_populates="threat", cascade="all, delete-orphan")

class ThreatEvidence(Base):
    __tablename__ = "threat_evidence"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    threat_id = Column(String(36), ForeignKey("threat_records.id"), nullable=False, unique=True)
    ai_summary = Column(Text, nullable=False)
    reason = Column(Text, nullable=False)
    why_blocked = Column(Text, nullable=True)          # JSON encoded list
    information_at_risk = Column(Text, nullable=True)  # JSON encoded list
    screenshot_path = Column(String(255), nullable=True)
    html_snapshot = Column(Text, nullable=True)
    created_at = Column(String(50), default=current_iso_timestamp)

    threat = relationship("ThreatRecord", back_populates="evidence")

class ThreatScoreBreakdown(Base):
    __tablename__ = "threat_score_breakdowns"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    threat_id = Column(String(36), ForeignKey("threat_records.id"), nullable=False, unique=True)
    brand_impersonation = Column(Integer, default=0)
    domain_similarity = Column(Integer, default=0)
    credential_collection = Column(Integer, default=0)
    urgency_keywords = Column(Integer, default=0)
    known_pattern = Column(Integer, default=0)
    total_score = Column(Integer, nullable=False)
    created_at = Column(String(50), default=current_iso_timestamp)

    threat = relationship("ThreatRecord", back_populates="score_breakdown")

class ThreatTimeline(Base):
    __tablename__ = "threat_timelines"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    campaign_id = Column(String(36), ForeignKey("campaigns.id"), nullable=True)
    threat_id = Column(String(36), ForeignKey("threat_records.id"), nullable=True)
    event_type = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(50), default="INFO")  # INFO | SUCCESS | WARNING | CRITICAL
    actor = Column(String(50), default="SYSTEM")    # SYSTEM | AI | USER
    created_at = Column(String(50), default=current_iso_timestamp)

    campaign = relationship("Campaign", back_populates="timeline_events")
    threat = relationship("ThreatRecord", back_populates="timeline_events")

class ThreatIOC(Base):
    __tablename__ = "threat_iocs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    threat_id = Column(String(36), ForeignKey("threat_records.id"), nullable=False, unique=True)
    domain = Column(String(255), nullable=False)
    tld = Column(String(50), nullable=False)
    domain_length = Column(Integer, nullable=False)
    website_identity = Column(String(255), nullable=False)
    attack_type = Column(String(255), nullable=False)
    keywords = Column(Text, nullable=True)  # JSON list
    contains_brand = Column(Boolean, default=False)
    contains_login_terms = Column(Boolean, default=False)
    contains_banking_terms = Column(Boolean, default=False)
    risk_category = Column(String(100), nullable=False)
    fingerprint = Column(String(255), nullable=False)
    created_at = Column(String(50), default=current_iso_timestamp)

    threat = relationship("ThreatRecord", back_populates="ioc")

class ThreatTag(Base):
    __tablename__ = "threat_tags"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    threat_id = Column(String(36), ForeignKey("threat_records.id"), nullable=False)
    tag = Column(String(100), nullable=False)
    confidence = Column(Integer, default=95)
    created_at = Column(String(50), default=current_iso_timestamp)

    threat = relationship("ThreatRecord", back_populates="tags")
