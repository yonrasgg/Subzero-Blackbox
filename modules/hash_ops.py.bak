#!/usr/bin/env python3
"""
modules/hash_ops.py

Módulo de operaciones de hashes e inteligencia externa para Blackbox.

- Integra servicios remotos (OnlineHashCrack, LeakCheck, etc.).
- Registra resultados en la tabla hash_results.
- Diseñado para ser llamado desde el worker:
    run_hash_lookup(session, job)
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

import requests
import yaml
from dotenv import load_dotenv
from sqlalchemy.orm import Session

from worker.db import HashResult, Job

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config" / "config.yaml"
DOTENV_PATH = BASE_DIR / ".env"

# Cargamos variables de entorno desde .env (si existe)
if DOTENV_PATH.is_file():
    load_dotenv(DOTENV_PATH)


# ---------------------------------------------------------------------------
# Helpers de configuración y entorno
# ---------------------------------------------------------------------------

def _load_hash_services_config() -> Dict[str, Any]:
    """
    Carga la sección hash_services de config/config.yaml.

    Devuelve {} si no existe o está vacía.
    """
    if not CONFIG_PATH.is_file():
        logger.warning("config.yaml not found at %s", CONFIG_PATH)
        return {}

    data = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
    cfg = data.get("hash_services", {})
    if not isinstance(cfg, dict):
        logger.warning("hash_services in config.yaml is not a dict")
        return {}
    return cfg


def _get_env(name: str) -> Optional[str]:
    value = os.getenv(name)
    if not value:
        logger.warning("Environment variable %s is not set", name)
    return value


# ---------------------------------------------------------------------------
# Helper DB: guardar resultados
# ---------------------------------------------------------------------------

def _store_hash_result(
    session: Session,
    job: Optional[Job],
    service: str,
    hash_value: str,
    plaintext: Optional[str],
) -> HashResult:
    """
    Crea un HashResult y lo guarda en la DB.
    """
    result = HashResult(
        job_id=job.id if job else None,
        service=service,
        hash=hash_value,
        plaintext=plaintext,
        confidence=None,
    )
    session.add(result)
    session.commit()
    session.refresh(result)

    logger.info(
        "Stored HashResult id=%s service=%s hash_prefix=%s...",
        result.id,
        service,
        hash_value[:12],
    )
    return result


# ---------------------------------------------------------------------------
# OnlineHashCrack (https://api.onlinehashcrack.com/v2)
# ---------------------------------------------------------------------------

def _call_onlinehashcrack(
    cfg: Dict[str, Any],
    hash_value: str,
    hash_algo: str,
) -> Optional[Dict[str, Any]]:
    """
    Envía un hash a OnlineHashCrack usando su API v2.

    NOTA:
    - Solo usar con hashes que tengas derecho legal de auditar.
    - Evitar enviar hashes directamente identificables de usuarios reales
      sin consentimiento explícito.
    """
    service_name = "onlinehashcrack"
    service_cfg = cfg.get(service_name, {})
    if not service_cfg.get("enabled", False):
        logger.info("%s is disabled in config.yaml", service_name)
        return None

    api_key_env = service_cfg.get("api_key_env")
    if not api_key_env:
        logger.error("%s.api_key_env not set in config.yaml", service_name)
        return None

    api_key = _get_env(api_key_env)
    if not api_key:
        logger.error("No API key in env for %s", service_name)
        return None

    timeout = service_cfg.get("timeout", 20)
    default_algo_mode = service_cfg.get("default_algo_mode", 0)

    # Aquí podrías mapear hash_algo -> algo_mode. De momento usamos el default.
    algo_mode = default_algo_mode

    url = "https://api.onlinehashcrack.com/v2"
    payload = {
        "api_key": api_key,
        "agree_terms": "yes",
        "algo_mode": algo_mode,
        "hashes": [hash_value],
    }

    logger.info("Calling OnlineHashCrack for hash (algo=%s)", hash_algo)

    try:
        resp = requests.post(url, json=payload, timeout=timeout)
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.error("OnlineHashCrack request failed: %s", exc)
        return None

    try:
        data = resp.json()
    except ValueError:
        logger.error("OnlineHashCrack returned non-JSON response")
        return None

    logger.debug("OnlineHashCrack response: %s", data)
    return data


# ---------------------------------------------------------------------------
# LeakCheck público (https://leakcheck.io/api/public)
# ---------------------------------------------------------------------------

def _call_leakcheck_public(
    cfg: Dict[str, Any],
    value: str,
) -> Optional[Dict[str, Any]]:
    """
    Consulta LeakCheck usando la API pública.

    value puede ser:
    - email
    - username
    - email hash truncado (según docs de LeakCheck)

    Devuelve el JSON tal cual, o None si falla.
    """
    service_name = "leakcheck"
    service_cfg = cfg.get(service_name, {})
    if not service_cfg.get("enabled", False):
        logger.info("%s is disabled in config.yaml", service_name)
        return None

    timeout = service_cfg.get("timeout", 10)
    url = "https://leakcheck.io/api/public"

    params = {"check": value}

    logger.info("Calling LeakCheck for value=%s", value)

    try:
        resp = requests.get(url, params=params, timeout=timeout)
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.error("LeakCheck request failed: %s", exc)
        return None

    try:
        data = resp.json()
    except ValueError:
        logger.error("LeakCheck returned non-JSON response")
        return None

    logger.debug("LeakCheck response: %s", data)
    return data


# ---------------------------------------------------------------------------
# Orquestador principal: run_hash_lookup
# ---------------------------------------------------------------------------

def run_hash_lookup(session: Session, job: Job) -> None:
    """
    Punto principal llamado desde el worker para jobs tipo 'hash_lookup'.

    Espera que job.params contenga:
      - mode: "hash" | "leakcheck" | "wpa_capture" (en el futuro)
      - value: hash/email/username, según el modo
      - hash_algo (opcional, ej: "md5")
      - services: lista de servicios a usar

    Ejemplos de params:

      {"mode": "hash", "value": "ABCD...", "hash_algo": "md5",
       "services": ["onlinehashcrack", "leakcheck"]}

      {"mode": "leakcheck", "value": "example@example.com",
       "services": ["leakcheck"]}
    """
    params = job.params or {}
    mode = params.get("mode")
    services = params.get("services", []) or []

    logger.info(
        "run_hash_lookup(job_id=%s) mode=%s services=%s",
        job.id,
        mode,
        services,
    )

    cfg = _load_hash_services_config()

    if mode == "hash":
        hash_value = params.get("value")
        hash_algo = params.get("hash_algo", "unknown")

        if not hash_value:
            logger.error("hash_lookup job missing 'value' for mode='hash'")
            return

        # OnlineHashCrack
        if "onlinehashcrack" in services:
            data = _call_onlinehashcrack(cfg, hash_value=hash_value, hash_algo=hash_algo)
            # Normalmente no devuelve plaintext directamente; registramos el intento.
            _store_hash_result(
                session,
                job,
                service="onlinehashcrack",
                hash_value=hash_value,
                plaintext=None,
            )
            logger.debug("OnlineHashCrack data stored (attempt) for job_id=%s", job.id)

        # Podrías añadir aquí otros servicios de cracking tradicionales.

    elif mode == "leakcheck":
        value = params.get("value")
        if not value:
            logger.error("hash_lookup job missing 'value' for mode='leakcheck'")
            return

        if "leakcheck" in services:
            data = _call_leakcheck_public(cfg, value=value)
            if data is None:
                return
            found = data.get("found", 0)
            if found:
                plaintext = f"{found} breach(es) detected"
            else:
                plaintext = "no breaches found"

            _store_hash_result(
                session,
                job,
                service="leakcheck",
                hash_value=value,
                plaintext=plaintext,
            )

    else:
        logger.warning(
            "Unsupported hash_lookup mode=%s for job id=%s",
            mode,
            job.id,
        )
