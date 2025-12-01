import os
import io
import sys
import time
import contextlib
import logging
import gc
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any

import yaml
import subprocess

from sqlalchemy.orm import Session

from worker.db import SessionLocal, Job, Run
from modules.core.plugin_manager import get_plugin_manager

logger = logging.getLogger(__name__)

# --- Project base paths and config/profiles ---

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config" / "config.yaml"
PROFILES_PATH = BASE_DIR / "config" / "profiles.yaml"
PROFILE_SWITCHER = BASE_DIR / "scripts" / "profile_switcher.py"

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


def ensure_profile_for_job(job: Job, required_profile: Optional[str]) -> None:
    """
    Ensures that the correct profile is active before executing a job.

    - If required_profile is None → does nothing.
    - If it has a profile name → invokes profile_switcher.py set <profile>.
    - Idempotency (not changing if already active, not changing if there are running jobs)
      is handled by profile_switcher itself.
    """
    if not required_profile:
        # No profile change necessary for this job type
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
    1. Find plugin for job.type.
    2. Ensure correct profile according to plugin metadata.
    3. Mark job as running.
    4. Execute plugin capturing stdout/stderr.
    5. Create a Run record with stdout, stderr, exit_code, started_at, finished_at.
    6. Update job status (finished/error).
    """
    plugin_manager = get_plugin_manager()
    
    # Find plugin
    plugin = None
    for category in plugin_manager.plugins:
        if job.type in plugin_manager.plugins[category]:
            plugin = plugin_manager.plugins[category][job.type]
            break
            
    if not plugin:
        logger.warning("Unknown job type %s (id=%s)", job.type, job.id)
        # Also create a Run for the unknown type
        finished_at = datetime.now(timezone.utc)
        run = Run(
            job_id=job.id,
            module=job.type,
            stdout="",
            stderr=f"Unknown job type: {job.type}",
            exit_code=1,
            started_at=datetime.now(timezone.utc),
            finished_at=finished_at,
        )
        session.add(run)
        job.status = "error"
        session.commit()
        return

    # 1) Ensure correct profile
    ensure_profile_for_job(job, plugin.metadata.required_profile)

    # 2) Mark as running
    job.status = "running"
    session.commit()

    # Initialize capture context
    started_at = datetime.now(timezone.utc)
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    exit_code = 0

    try:
        # 3) Execute plugin capturing stdout/stderr
        with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
            logger.info(f"Executing plugin {plugin.name} for job id={job.id}")
            plugin.run(job)

        # 4) If we get here without exceptions: mark as finished
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

        # 4.1) AI Processing: Enrich findings with offline intelligence
        try:
            from ai.pipeline import process_job_completion
            ai_success = process_job_completion(job.id, session)
            if ai_success:
                logger.info("AI processing completed for job id=%s", job.id)
            else:
                logger.warning("AI processing failed for job id=%s", job.id)
        except ImportError:
            logger.debug("AI pipeline not available, skipping AI processing")
        except Exception as ai_exc:
            logger.warning("AI processing error for job id=%s: %s", job.id, ai_exc)

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

    finally:
        # Optimization #5: Memory Cleanup
        # Force garbage collection after each job to free up resources
        # This is critical for resource-constrained environments (e.g., Pi Zero)
        gc.collect()


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
                # 1) Open session to the DB
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
