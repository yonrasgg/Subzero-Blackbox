#!/usr/bin/env python3
"""
modules/hash_ops.py

Module for hash operations and external intelligence for Blackbox.

- Integrates remote services (OnlineHashCrack, LeakCheck, etc.).
- Stores results in the hash_results table.
- Designed to be called from the worker:
    run_hash_lookup(session, job)
"""

from __future__ import annotations

import logging
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


# Load environment variables from .env (if exists)
if DOTENV_PATH.is_file():
    load_dotenv(DOTENV_PATH)



# ---------------------------------------------------------------------------
# Config and environment helpers
# ---------------------------------------------------------------------------

def _load_hash_services_config() -> Dict[str, Any]:
    """
    Loads the hash_services section from config/config.yaml.

    Returns {} if it does not exist or is empty.
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


def _get_api_key(service: str) -> Optional[str]:
    """Get API key from config (merging secrets.yaml if exists) or environment variables."""
    import os
    
    # First try to get from config
    if not CONFIG_PATH.is_file():
        # Fallback to environment variables
        env_var_map = {
            "onlinehashcrack": "ONLINEHASHCRACK_API_KEY",
            "wpasec": "WPASEC_API_KEY",
            "wigle": "WIGLE_API_TOKEN"
        }
        env_var = env_var_map.get(service)
        if env_var:
            return os.getenv(env_var)
        return None
    
    # Load main config
    cfg = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
    
    # Merge secrets.yaml if it exists
    secrets_path = CONFIG_PATH.parent / "secrets.yaml"
    if secrets_path.is_file():
        secrets = yaml.safe_load(secrets_path.read_text(encoding="utf-8")) or {}
        # Deep merge secrets into config
        def deep_merge(base, update):
            for key, value in update.items():
                if isinstance(value, dict) and key in base and isinstance(base[key], dict):
                    deep_merge(base[key], value)
                else:
                    base[key] = value
        deep_merge(cfg, secrets)
    
    apis = cfg.get("apis", {})
    key_name = _load_hash_services_config().get(service, {}).get("api_key")
    if key_name:
        api_key = apis.get(key_name)
        if api_key:
            return api_key
    
    # Fallback to environment variables
    env_var_map = {
        "onlinehashcrack": "ONLINEHASHCRACK_API_KEY",
        "wpasec": "WPASEC_API_KEY",
        "wigle": "WIGLE_API_TOKEN"
    }
    env_var = env_var_map.get(service)
    if env_var:
        return os.getenv(env_var)
    
    return None



# ---------------------------------------------------------------------------
# DB Helper: store results
# ---------------------------------------------------------------------------

def _store_hash_result(
    session: Session,
    job: Optional[Job],
    service: str,
    hash_value: str,
    plaintext: Optional[str],
) -> HashResult:
    """
    Creates a HashResult and saves it in the DB.
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
    Sends a hash to OnlineHashCrack using its API v2.
    """
    service_name = "onlinehashcrack"
    service_cfg = cfg.get(service_name, {})
    if not service_cfg.get("enabled", False):
        logger.info("%s is disabled in config.yaml", service_name)
        return None

    api_key = _get_api_key(service_name)
    if not api_key:
        return None

    timeout = service_cfg.get("timeout", 20)
    default_algo_mode = service_cfg.get("default_algo_mode", 0)

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
# LeakCheck public (https://leakcheck.io/api/public)
# ---------------------------------------------------------------------------

def _call_leakcheck_public(
    cfg: Dict[str, Any],
    value: str,
) -> Optional[Dict[str, Any]]:
    """
    Queries LeakCheck using the public API.

    value can be:
    - email
    - username
    - truncated email hash (according to LeakCheck docs)

    Returns the JSON as is, or None if it fails.
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
# WPA-Sec (https://wpa-sec.stanev.org)
# ---------------------------------------------------------------------------

def upload_to_wpasec(file_path: Path) -> bool:
    """
    Uploads a capture file to wpa-sec.stanev.org.
    """
    cfg = _load_hash_services_config()
    service_name = "wpa_sec"
    service_cfg = cfg.get(service_name, {})
    
    if not service_cfg.get("enabled", False):
        logger.info("%s is disabled in config.yaml", service_name)
        return False

    api_key = _get_api_key(service_name)
    if not api_key:
        logger.warning("No API key for wpa-sec")
        return False

    url = "https://wpa-sec.stanev.org/?api&upload"
    timeout = service_cfg.get("timeout", 30)

    logger.info("Uploading %s to wpa-sec...", file_path.name)

    try:
        with open(file_path, 'rb') as f:
            files = {'file': f}
            cookies = {'key': api_key}
            resp = requests.post(url, files=files, cookies=cookies, timeout=timeout)
            resp.raise_for_status()
            logger.info("Upload successful: %s", resp.text)
            return True
    except Exception as e:
        logger.error("Failed to upload to wpa-sec: %s", e)
        return False


# ---------------------------------------------------------------------------
# Main orchestrator: run_hash_lookup
# ---------------------------------------------------------------------------

def run_hash_lookup(session: Session, job: Job) -> None:
    """
    Main entry point called from the worker for 'hash_lookup' jobs.

    Expects job.params to contain:
      - mode: "hash" | "leakcheck" | "wpa_capture" (in the future)
      - value: hash/email/username, depending on the mode
      - hash_algo (optional, e.g.: "md5")
      - services: list of services to use

    Example params:

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
            # Normally does not return plaintext directly; we log the attempt.
            _store_hash_result(
                session,
                job,
                service="onlinehashcrack",
                hash_value=hash_value,
                plaintext=None,
            )
            logger.debug("OnlineHashCrack data stored (attempt) for job_id=%s", job.id)

        # You could add other traditional cracking services here.

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
