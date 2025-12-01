"""
Hash Lookup Plugin.
Wraps modules/hash_ops.py functionality.
"""

import logging
from pathlib import Path
from modules import hash_ops
from worker.db import SessionLocal

logger = logging.getLogger(__name__)

def run(job) -> None:
    """Run hash lookup."""
    logger.info(f"Running hash_lookup plugin for job {job.id}")
    with SessionLocal() as session:
        hash_ops.run_hash_lookup(session, job)

def upload_to_wpasec(file_path: Path) -> bool:
    """Wrapper for hash_ops.upload_to_wpasec"""
    return hash_ops.upload_to_wpasec(file_path)
