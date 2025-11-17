import os
import io
import sys
import time
import contextlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any

import yaml
import subprocess

from sqlalchemy.orm import Session

from worker.db import SessionLocal, Job, Run
from modules import wifi_recon, wifi_active, bt_recon, bt_active, hash_ops

logger = logging.getLogger(__name__)

# --- Paths base del proyecto y config/perfiles ---

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config" / "config.yaml"
PROFILES_PATH = BASE_DIR / "config" / "profiles.yaml"
PROFILE_SWITCHER = BASE_DIR / "scripts" / "profile_switcher.py"

# --- 3.1 Mapa tipo de job → perfil requerido ---

JOB_PROFILE_MAP: Dict[str, Optional[str]] = {
    # Jobs de Wi-Fi usan el perfil wifi_audit
    "wifi_recon": "wifi_audit",
    "wifi_active": "wifi_audit",

    # Jobs de Bluetooth usan el perfil bluetooth_audit
    "bt_recon": "bluetooth_audit",
    "bt_active": "bluetooth_audit",

    # Jobs de hashing / inteligencia externa NO requieren cambio de perfil
    # (hash_lookup solo llama servicios remotos/API).
    "hash_lookup": None,

    # Tipos futuros (web / LAN). De momento no se usan en la UI,
    # pero el mapa ya queda preparado para cuando añadas módulos nuevos.
    "web_recon": "stealth_recon",
    "web_attack": "aggressive_recon",
    "lan_recon": "stealth_recon",
    "lan_attack": "aggressive_recon",
}

# --- Utilidades para leer config/perfiles ---


def _load_yaml(path: Path) -> Dict[str, Any]:
    """
    Carga un YAML y devuelve siempre un dict (nunca None).
    Si el archivo no existe o está vacío, devuelve {}.
    """
    if not path.is_file():
        logger.debug("YAML file %s not found; returning empty dict", path)
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        return {}
    if not isinstance(data, dict):
        logger.warning("YAML %s did not produce a dict; got %r", path, type(data))
        return {}
    return data


def get_active_profile() -> Optional[str]:
    """
    Lee el perfil activo desde config.yaml (sección profiles.active_profile).

    Devuelve:
        - str con el nombre de perfil (ej. "wifi_audit"), o
        - None si no está definido.
    """
    cfg = _load_yaml(CONFIG_PATH)
    profiles_cfg = cfg.get("profiles", {})
    active = profiles_cfg.get("active_profile")
    if active:
        logger.debug("Active profile from config.yaml: %s", active)
    else:
        logger.debug("No active profile defined in config.yaml")
    return active


def get_profile_for_job(job_type: str) -> Optional[str]:
    """
    Usa JOB_PROFILE_MAP como fuente única de verdad para saber qué perfil
    debe estar activo para un tipo de job dado.

    Ejemplos:
        job_type="wifi_recon"   -> "wifi_audit"
        job_type="bt_recon"     -> "bluetooth_audit"
        job_type="hash_lookup"  -> None (no requiere cambio de perfil)
        job_type desconocido    -> None
    """
    profile = JOB_PROFILE_MAP.get(job_type)
    logger.debug("Profile for job type %s -> %s", job_type, profile)
    return profile


def ensure_profile_for_job(job: Job) -> None:
    """
    Garantiza que el perfil adecuado esté activo antes de ejecutar un job.

    - Si JOB_PROFILE_MAP[job.type] es None → no hace nada.
    - Si tiene un nombre de perfil → invoca profile_switcher.py set <perfil>.
    - La idempotencia (no cambiar si ya está activo, no cambiar si hay jobs
      running) la gestiona el propio profile_switcher.
    """
    required_profile = JOB_PROFILE_MAP.get(job.type)

    if not required_profile:
        # Ningún cambio de perfil necesario para este tipo de job
        return

    env = os.environ.copy()
    # Permite que profile_switcher sepa quién disparó el cambio
    env.setdefault("BLACKBOX_TRIGGERED_BY", "worker")

    cmd = [sys.executable, str(PROFILE_SWITCHER), "set", required_profile]

    try:
        subprocess.run(cmd, check=True, env=env)
    except subprocess.CalledProcessError as exc:
        # Si falla el cambio de perfil, es mejor registrar y propagar el error
        # para que el job no se ejecute en un contexto incorrecto.
        print(f"[WorkerEngine] Failed to switch profile to {required_profile}: {exc}")
        raise

def process_job(session: Session, job: Job) -> None:
    """
    Procesa un job desde la cola.

    Flujo alto nivel:
    1. Asegurar perfil correcto según job.type (profile_switcher).
    2. Marcar job como running.
    3. Ejecutar módulo asociado (wifi_recon, bt_recon, hash_lookup, etc.)
       capturando stdout/stderr.
    4. Crear un registro Run con stdout, stderr, exit_code, started_at, finished_at.
    5. Actualizar estado del job (finished/error).
    """
    # 1) Asegurar perfil correcto
    ensure_profile_for_job(job)

    # 2) Marcar como running
    job.status = "running"
    session.commit()

    # Inicializar contexto de captura
    started_at = datetime.now(timezone.utc)
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    exit_code = 0

    try:
        # 3) Ejecutar módulo según job.type capturando stdout/stderr
        with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
            if job.type == "wifi_recon":
                logger.info("Executing wifi_recon for job id=%s", job.id)
                wifi_recon.run(job.profile)

            elif job.type == "wifi_active":
                logger.info("Executing wifi_active for job id=%s", job.id)
                wifi_active.run(job.profile)

            elif job.type == "bt_recon":
                logger.info("Executing bt_recon for job id=%s", job.id)
                bt_recon.run(job.profile)

            elif job.type == "bt_active":
                logger.info("Executing bt_active for job id=%s", job.id)
                bt_active.run(job.profile)

            elif job.type == "hash_lookup":
                logger.info("Executing hash_lookup for job id=%s", job.id)
                hash_ops.run_hash_lookup(session, job)

            else:
                logger.warning("Unknown job type %s (id=%s)", job.type, job.id)
                exit_code = 1
                # Creamos también un Run para el tipo desconocido
                finished_at = datetime.now(timezone.utc)
                run = Run(
                    job_id=job.id,
                    module=job.type,
                    stdout=stdout_buf.getvalue(),
                    stderr=stderr_buf.getvalue() or f"Unknown job type: {job.type}",
                    exit_code=exit_code,
                    started_at=started_at,
                    finished_at=finished_at,
                )
                session.add(run)
                job.status = "error"
                session.commit()
                return

        # 4) Si llegamos aquí sin excepciones: marcar como finished
        finished_at = datetime.utcnow()

        run = Run(
            job_id=job.id,
            module=job.type,
            stdout=stdout_buf.getvalue(),
            stderr=stderr_buf.getvalue(),
            exit_code=exit_code,
            started_at=started_at,
            finished_at=finished_at,
        )
        session.add(run)

        job.status = "finished"
        session.commit()

    except Exception as exc:
        # 5) En caso de error, registrar Run con exit_code != 0
        logger.exception("Error processing job id=%s: %s", job.id, exc)
        exit_code = 1
        finished_at = datetime.utcnow()

        run = Run(
            job_id=job.id,
            module=job.type,
            stdout=stdout_buf.getvalue(),
            stderr=(stderr_buf.getvalue() + f"\nException: {exc!r}"),
            exit_code=exit_code,
            started_at=started_at,
            finished_at=finished_at,
        )
        session.add(run)

        job.status = "error"
        session.commit()


class WorkerEngine:
    """
    Core worker loop.

    En esta fase el loop sigue siendo simple, pero ya:
      - Lee jobs en estado 'queued' desde la DB.
      - Llama a process_job(session, job) para cada job.
      - Delega el cambio de perfil en ensure_profile_for_job(job).
    """

    def __init__(self, poll_interval: int = 30) -> None:
        self.poll_interval = poll_interval
        self._running = False

    def start(self) -> None:
        self._running = True
        print(f"[WorkerEngine] Starting main loop (interval={self.poll_interval}s)")
        logger.info("WorkerEngine started (interval=%ss)", self.poll_interval)

        try:
            while self._running:
                # 1) Abrir sesión a la DB
                with SessionLocal() as session:
                    # 2) Leer jobs en estado 'queued'
                    jobs = (
                        session.query(Job)
                        .filter(Job.status == "queued")
                        .order_by(Job.created_at.asc())
                        .all()
                    )

                    # 3) Procesar cada job encontrado
                    for job in jobs:
                        logger.info(
                            "Processing queued job id=%s type=%s status=%s",
                            job.id,
                            job.type,
                            job.status,
                        )
                        process_job(session, job)

                # 4) Esperar antes de volver a consultar la cola
                time.sleep(self.poll_interval)

        except KeyboardInterrupt:
            print("[WorkerEngine] Interrupted by user.")
            logger.info("WorkerEngine interrupted by user.")
        finally:
            self._running = False
            print("[WorkerEngine] Stopped.")
            logger.info("WorkerEngine stopped.")


def main() -> None:
    # Puedes hacer este valor configurable desde config.yaml si quieres
    engine = WorkerEngine(poll_interval=5)
    engine.start()


if __name__ == "__main__":
    main()
