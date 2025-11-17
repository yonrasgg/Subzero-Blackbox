#!/usr/bin/env python3
"""
scripts/init_db.py

Initializes the Blackbox SQLite database (data/blackbox.db).
- Creates the file if it does not exist.
- Creates the tables defined in worker/db.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import text

 # Ensure the project root directory is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from worker.db import Base, engine, SessionLocal, Job  # noqa: E402



def init_db() -> None:
    """
    Creates the tables if they do not exist.
    In the future, a more robust migration system (Alembic) could be integrated here.
    """
    print(f"[init_db] Using database at: {engine.url}")
    print("[init_db] Creating tables (if not exist)...")
    Base.metadata.create_all(bind=engine)
    print("[init_db] Tables created/verified.")

    # Optional small test: count jobs
    with SessionLocal() as session:
        result = session.execute(text("SELECT COUNT(*) FROM jobs"))
        (jobs_count,) = result.fetchone()
        print(f"[init_db] Existing jobs in the database: {jobs_count}")



def seed_example_job() -> None:
    """
    Creates an example job if there are none, to validate that the ORM works.
    """
    with SessionLocal() as session:
        existing = session.query(Job).count()
        if existing > 0:
            print(f"[init_db] The jobs table already has {existing} records. No dummy created.")
            return

        dummy = Job(
            type="wifi_recon",
            profile="stealth_recon",
            params={"note": "dummy job created by init_db.py"},
            status="queued",
        )
        session.add(dummy)
        session.commit()
        session.refresh(dummy)
        print(f"[init_db] Example job created with id={dummy.id}.")


if __name__ == "__main__":
    init_db()
    seed_example_job()
    print("[init_db] OK.")
