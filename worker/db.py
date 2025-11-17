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
