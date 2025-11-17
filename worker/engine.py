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

# --- Project base paths and config/profiles ---

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config" / "config.yaml"
PROFILES_PATH = BASE_DIR / "config" / "profiles.yaml"
PROFILE_SWITCHER = BASE_DIR / "scripts" / "profile_switcher.py"

# --- 3.1 Map job type → required profile ---

JOB_PROFILE_MAP: Dict[str, Optional[str]] = {
    # Wi-Fi jobs use the wifi_audit profile
    "wifi_recon": "wifi_audit",
    "wifi_active": "wifi_audit",

    # Bluetooth jobs use the bluetooth_audit profile
    "bt_recon": "bluetooth_audit",
    "bt_active": "bluetooth_audit",

    # Hashing/external intelligence jobs DO NOT require profile change
    # (hash_lookup only calls remote services/APIs).
    "hash_lookup": None,

    # Future types (web / LAN). Not used in the UI yet,
    # but the map is ready for when you add new modules.
    "web_recon": "stealth_recon",
    "web_attack": "aggressive_recon",
    "lan_recon": "stealth_recon",
    "lan_attack": "aggressive_recon",
}

# --- Utilities to read config/profiles ---


def _load_yaml(path: Path) -> Dict[str, Any]:
    """
    Loads a YAML and always returns a dict (never None).
    If the file does not exist or is empty, returns {}.
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
    Reads the active profile from config.yaml (section profiles.active_profile).

    Returns:
        - str with the profile name (e.g. "wifi_audit"), or
        - None if not defined.
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
    Uses JOB_PROFILE_MAP as the single source of truth to know which profile
    should be active for a given job type.

    Examples:
        job_type="wifi_recon"   -> "wifi_audit"
        job_type="bt_recon"     -> "bluetooth_audit"
        job_type="hash_lookup"  -> None (does not require profile change)
        unknown job_type        -> None
    """
    profile = JOB_PROFILE_MAP.get(job_type)
    logger.debug("Profile for job type %s -> %s", job_type, profile)
    return profile


def ensure_profile_for_job(job: Job) -> None:
    """
    Ensures that the correct profile is active before executing a job.

    - If JOB_PROFILE_MAP[job.type] is None → does nothing.
    - If it has a profile name → invokes profile_switcher.py set <profile>.
    - Idempotency (not changing if already active, not changing if there are running jobs)
      is handled by profile_switcher itself.
    """
    required_profile = JOB_PROFILE_MAP.get(job.type)

    if not required_profile:
        # Ningún cambio de perfil necesario para este tipo de job
        return

    env = os.environ.copy()
    # Allows profile_switcher to know who triggered the change
    env.setdefault("BLACKBOX_TRIGGERED_BY", "worker")

    cmd = [sys.executable, str(PROFILE_SWITCHER), "set", required_profile]

    try:
        subprocess.run(cmd, check=True, env=env)
    except subprocess.CalledProcessError as exc:
        # If profile switching fails, it's better to log and propagate the error
        # so the job does not run in an incorrect context.
        print(f"[WorkerEngine] Failed to switch profile to {required_profile}: {exc}")
        raise

def process_job(session: Session, job: Job) -> None:
    """
    Processes a job from the queue.

    High-level flow:
    1. Ensure correct profile according to job.type (profile_switcher).
    2. Mark job as running.
    3. Execute associated module (wifi_recon, bt_recon, hash_lookup, etc.)
       capturing stdout/stderr.
    4. Create a Run record with stdout, stderr, exit_code, started_at, finished_at.
    5. Update job status (finished/error).
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
                # Also create a Run for the unknown type
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

    At this stage the loop is still simple, but already:
        - Reads jobs in 'queued' state from the DB.
        - Calls process_job(session, job) for each job.
        - Delegates profile switching to ensure_profile_for_job(job).
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
    # You can make this value configurable from config.yaml if you want
    engine = WorkerEngine(poll_interval=5)
    engine.start()


if __name__ == "__main__":
    main()
