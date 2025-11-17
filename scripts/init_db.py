#!/usr/bin/env python3
"""
scripts/init_db.py

Inicializa la base de datos SQLite de Blackbox (data/blackbox.db).
- Crea el archivo si no existe.
- Crea las tablas definidas en worker/db.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import text

# Aseguramos que el directorio raíz del proyecto esté en sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from worker.db import Base, engine, SessionLocal, Job  # noqa: E402


def init_db() -> None:
    """
    Crea las tablas si no existen.
    En un futuro, aquí podríamos integrar un sistema de migraciones más serio (Alembic).
    """
    print(f"[init_db] Usando base de datos en: {engine.url}")
    print("[init_db] Creando tablas (si no existen)...")
    Base.metadata.create_all(bind=engine)
    print("[init_db] Tablas creadas/verificadas.")

    # Pequeña prueba opcional: contar jobs
    with SessionLocal() as session:
        result = session.execute(text("SELECT COUNT(*) FROM jobs"))
        (jobs_count,) = result.fetchone()
        print(f"[init_db] jobs existentes en la base: {jobs_count}")


def seed_example_job() -> None:
    """
    Crea un job de ejemplo si no hay ninguno, para validar que el ORM funciona.
    """
    with SessionLocal() as session:
        existing = session.query(Job).count()
        if existing > 0:
            print(f"[init_db] La tabla jobs ya tiene {existing} registros. No se crea dummy.")
            return

        dummy = Job(
            type="wifi_recon",
            profile="stealth_recon",
            params={"note": "dummy job creado por init_db.py"},
            status="queued",
        )
        session.add(dummy)
        session.commit()
        session.refresh(dummy)
        print(f"[init_db] Job de ejemplo creado con id={dummy.id}.")


if __name__ == "__main__":
    init_db()
    seed_example_job()
    print("[init_db] OK.")
