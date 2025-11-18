"""
worker/db.py

Central module for SQLite database access for Blackbox.
Defines:
- SQLite path and engine
- SessionLocal (session factory)
- ORM Models: Job, Run, HashResult, ProfileLog
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
    Float,
    JSON,
    func,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker


# --- Basic Paths ---

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "blackbox.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

# --- Engine and Session factory ---

engine = create_engine(
    DATABASE_URL,
    future=True,
    echo=False,  # set True if you want to see SQL in console
    connect_args={"check_same_thread": False},  # required for SQLite + threads
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)

Base = declarative_base()



# --- ORM Models ---



class Job(Base):
    """
    jobs table:
    - Represents an audit request / queued job that the worker must process.

    Examples of type:
        - wifi_recon
        - wifi_active
        - bt_recon
        - bt_active
        - hash_lookup

    For type == "hash_lookup", the params field usually looks like:

        {
            "mode": "hash" | "wpa_capture" | "leakcheck",
            "value": "...",         # hash or identifier, depending on mode
            "hash_algo": "md5",     # optional, e.g. for OnlineHashCrack
            "pcap_path": "...",     # for wpa_capture
            "bssid": "...",         # optional
            "ssid": "...",          # optional
            "services": ["onlinehashcrack", "leakcheck", "wpa_sec"]
        }
    """

    __tablename__ = "jobs"

    id = Column(Integer, primary_key=True, index=True)

    # job type: wifi_recon, bt_recon, wifi_active, bt_active, hash_lookup, etc.
    type = Column(String(50), nullable=False, index=True)

    # profile used (stealth_recon, aggressive_recon, wifi_audit, etc.)
    profile = Column(String(50), nullable=True, index=True)

    # job parameters in JSON (e.g., channels, BSSID, hash_lookup modes, etc.)
    params = Column(JSON, nullable=True)

    # status: queued, running, finished, error
    status = Column(String(20), nullable=False, default="queued", index=True)

    # timestamps
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # 1:N relationship with runs
    runs = relationship(
        "Run",
        back_populates="job",
        cascade="all, delete-orphan",
    )

    # 1:N relationship with hash_results (if the job is of type hash_lookup, for example)
    hash_results = relationship(
        "HashResult",
        back_populates="job",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return (
            f"<Job id={self.id} type={self.type} "
            f"status={self.status} profile={self.profile}>"
        )



class Run(Base):
    """
    runs table:
    - Records specific executions of modules (including the worker itself).
    - Linked to a job.
    """

    __tablename__ = "runs"

    id = Column(Integer, primary_key=True, index=True)

    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False, index=True)


    # module executed: wifi_recon, bt_active, worker, etc.
    module = Column(String(50), nullable=False, index=True)

    stdout = Column(Text, nullable=True)
    stderr = Column(Text, nullable=True)
    exit_code = Column(Integer, nullable=True)

    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)

    job = relationship("Job", back_populates="runs")

    def __repr__(self) -> str:
        return f"<Run id={self.id} job_id={self.job_id} module={self.module}>"



class HashResult(Base):
    """
    hash_results table:
    - Responses from hash cracking services or external intelligence.

    Typical field usage:

        service:
            - "onlinehashcrack"
            - "leakcheck"
            - "wpa_sec"
            - other services that may be integrated later.

        hash:
            - mode = "hash":
                    original hash (MD5, SHA1, etc.).
            - mode = "leakcheck":
                    identifier queried (email, username, truncated hash).
            - mode = "wpa_capture":
                    MD5 of the .pcap/.pcapng file prepared for WPA-sec.

        plaintext:
            - could be the password (in controlled labs),
            - a message like "3 breach(es) detected",
            - or "capture_prepared" for prepared WPA captures.
    """

    __tablename__ = "hash_results"

    id = Column(Integer, primary_key=True, index=True)

    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=True, index=True)

    # Name of the remote service or module that generated the result
    service = Column(String(100), nullable=False, index=True)

    # Main identifier: hash, email, md5 of the pcap, etc.
    hash = Column(String(512), nullable=False, index=True)

    # Plaintext result (if applicable) or summary
    plaintext = Column(String(512), nullable=True)

    # Confidence or score (0.0–1.0, percentage, etc.)
    confidence = Column(Float, nullable=True)

    # If in the future you want to store raw responses or flags,
    # you can add a JSON field "metadata" here.
    # metadata = Column(JSON, nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    job = relationship("Job", back_populates="hash_results")

    def __repr__(self) -> str:
        hash_preview = (self.hash[:16] + "...") if self.hash else "None"
        return f"<HashResult id={self.id} service={self.service} hash={hash_preview}>"



class ProfileLog(Base):
    """
    profiles_log table (optional):
    - Audits profile and tethering changes.
    - Useful to know who/what triggered a profile change and when.
    """

    __tablename__ = "profiles_log"

    id = Column(Integer, primary_key=True, index=True)


    old_profile = Column(String(50), nullable=True)
    new_profile = Column(String(50), nullable=False, index=True)
    reason = Column(String(255), nullable=True)
    triggered_by = Column(String(50), nullable=True)  # api, cli, systemd, etc.


    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    def __repr__(self) -> str:
        return (
            f"<ProfileLog id={self.id} "
            f"{self.old_profile} -> {self.new_profile} "
            f"reason={self.reason}>"
        )


class AuditData(Base):
    """
    audit_data table:
    - Stores detailed data collected during audits (networks, devices, etc.)
    """

    __tablename__ = "audit_data"

    id = Column(Integer, primary_key=True, index=True)

    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False, index=True)

    # Type of data: wifi_network, bt_device, usb_device, etc.
    data_type = Column(String(50), nullable=False, index=True)

    # JSON data containing the collected information
    data = Column(JSON, nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    job = relationship("Job", backref="audit_data")

    def __repr__(self) -> str:
        return f"<AuditData id={self.id} job_id={self.job_id} type={self.data_type}>"


class Vulnerability(Base):
    """
    vulnerabilities table:
    - Stores found vulnerabilities during audits
    """

    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)

    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False, index=True)

    # Type of vulnerability: wifi, bt, usb, etc.
    vuln_type = Column(String(50), nullable=False, index=True)

    # Severity: critical, high, medium, low, info
    severity = Column(String(20), nullable=False)

    # Description of the vulnerability
    description = Column(Text, nullable=False)

    # Additional data (CVEs, affected devices, etc.)
    details = Column(JSON, nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    job = relationship("Job", backref="vulnerabilities")

    def __repr__(self) -> str:
        return f"<Vulnerability id={self.id} job_id={self.job_id} type={self.vuln_type} severity={self.severity}>"


class VendorMAC(Base):
    """
    vendor_macs table:
    - Stores MAC address to vendor mappings
    """

    __tablename__ = "vendor_macs"

    id = Column(Integer, primary_key=True, index=True)

    mac_prefix = Column(String(6), nullable=False, unique=True, index=True)  # First 6 chars of MAC

    vendor = Column(String(100), nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<VendorMAC mac_prefix={self.mac_prefix} vendor={self.vendor}>"


class AIEmbedding(Base):
    """
    ai_embeddings table:
    - Stores vector embeddings for semantic search and similarity matching
    - Generated by MiniLM-L6 model for offline AI capabilities
    """

    __tablename__ = "ai_embeddings"

    id = Column(Integer, primary_key=True, index=True)

    # What object this embedding represents
    object_type = Column(String(50), nullable=False, index=True)  # "job", "run", "vulnerability", "audit_data"

    object_id = Column(Integer, nullable=False, index=True)  # ID in the source table

    # Model information
    model_name = Column(String(50), nullable=False)  # "MiniLM-L6-int8", etc.

    # The embedding vector (serialized as JSON for SQLite compatibility)
    vector = Column(JSON, nullable=False)  # List of floats

    # Optional metadata
    content_hash = Column(String(64), nullable=True)  # Hash of the original content for deduplication

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    def __repr__(self) -> str:
        return f"<AIEmbedding object_type={self.object_type} object_id={self.object_id} model={self.model_name}>"


class AILabel(Base):
    """
    ai_labels table:
    - Stores AI-generated classifications and labels
    - Generated by ALBERT-tiny and other classifiers for offline categorization
    """

    __tablename__ = "ai_labels"

    id = Column(Integer, primary_key=True, index=True)

    # What object this label applies to
    object_type = Column(String(50), nullable=False, index=True)  # "job", "run", "vulnerability", "audit_data"

    object_id = Column(Integer, nullable=False, index=True)  # ID in the source table

    # Label information
    label_type = Column(String(50), nullable=False, index=True)  # "vuln_type", "attack_family", "domain", "severity"

    label_value = Column(String(100), nullable=False, index=True)  # "sql_injection", "bruteforce", "network", "high"

    # Confidence score (0.0 to 1.0)
    score = Column(Float, nullable=False)

    # Model information
    model_name = Column(String(50), nullable=False)  # "ALBERT-tiny", etc.

    # Optional additional metadata
    classification_metadata = Column(JSON, nullable=True)  # Additional classification details

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    def __repr__(self) -> str:
        return f"<AILabel object_type={self.object_type} object_id={self.object_id} type={self.label_type} value={self.label_value} score={self.score}>"
