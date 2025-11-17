"""
worker/db.py

Módulo central de acceso a la base de datos SQLite para Blackbox.
Define:
- Ruta y engine de SQLite
- SessionLocal (factory de sesiones)
- Modelos ORM: Job, Run, HashResult, ProfileLog
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

# --- Paths básicos ---

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "blackbox.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

# --- Engine y Session factory ---

engine = create_engine(
    DATABASE_URL,
    future=True,
    echo=False,  # pon True si quieres ver el SQL en consola
    connect_args={"check_same_thread": False},  # necesario para SQLite + threads
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)

Base = declarative_base()


# --- Modelos ORM ---


class Job(Base):
    """
    Tabla jobs:
    - Representa una solicitud de auditoría / trabajo en cola que el worker debe procesar.

    Ejemplos de type:
      - wifi_recon
      - wifi_active
      - bt_recon
      - bt_active
      - hash_lookup

    Para type == "hash_lookup", el campo params suele tener forma:

      {
        "mode": "hash" | "wpa_capture" | "leakcheck",
        "value": "...",         # hash o identificador, según el modo
        "hash_algo": "md5",     # opcional, p.ej. para OnlineHashCrack
        "pcap_path": "...",     # para wpa_capture
        "bssid": "...",         # opcional
        "ssid": "...",          # opcional
        "services": ["onlinehashcrack", "leakcheck", "wpa_sec"]
      }
    """

    __tablename__ = "jobs"

    id = Column(Integer, primary_key=True, index=True)

    # tipo de job: wifi_recon, bt_recon, wifi_active, bt_active, hash_lookup, etc.
    type = Column(String(50), nullable=False, index=True)

    # perfil usado (stealth_recon, aggressive_recon, wifi_audit, etc.)
    profile = Column(String(50), nullable=True, index=True)

    # parámetros del job en JSON (por ejemplo, canales, BSSID, modos de hash_lookup, etc.)
    params = Column(JSON, nullable=True)

    # estado: queued, running, finished, error
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

    # relación 1:N con runs
    runs = relationship(
        "Run",
        back_populates="job",
        cascade="all, delete-orphan",
    )

    # relación 1:N con hash_results (si el job es de tipo hash_lookup, por ejemplo)
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
    Tabla runs:
    - Registra ejecuciones concretas de módulos (incluido el propio worker).
    - Se vincula a un job.
    """

    __tablename__ = "runs"

    id = Column(Integer, primary_key=True, index=True)

    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False, index=True)

    # módulo que ejecuta: wifi_recon, bt_active, worker, etc.
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
    Tabla hash_results:
    - Respuestas de servicios de cracking de hashes o inteligencia externa.

    Uso típico de campos:

      service:
        - "onlinehashcrack"
        - "leakcheck"
        - "wpa_sec"
        - otros servicios que se integren más adelante.

      hash:
        - mode = "hash":
            hash original (MD5, SHA1, etc.).
        - mode = "leakcheck":
            identificador consultado (email, username, hash truncado).
        - mode = "wpa_capture":
            MD5 del fichero .pcap/.pcapng preparado para WPA-sec.

      plaintext:
        - puede ser el password (en labs controlados),
        - un mensaje tipo "3 breach(es) detected",
        - o "capture_prepared" para capturas WPA preparadas.
    """

    __tablename__ = "hash_results"

    id = Column(Integer, primary_key=True, index=True)

    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=True, index=True)

    # Nombre del servicio remoto o módulo que generó el resultado
    service = Column(String(100), nullable=False, index=True)

    # Identificador principal: hash, email, md5 del pcap, etc.
    hash = Column(String(512), nullable=False, index=True)

    # Resultado en texto plano (si aplica) o resumen
    plaintext = Column(String(512), nullable=True)

    # Confianza o score (0.0–1.0, porcentaje, etc.)
    confidence = Column(Float, nullable=True)

    # Si en el futuro quieres guardar respuestas crudas o flags,
    # puedes añadir aquí un campo JSON "metadata".
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
    Tabla profiles_log (opcional):
    - Audita cambios de perfil y tethering.
    - Útil para saber quién/qué disparó un cambio de perfil y cuándo.
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
