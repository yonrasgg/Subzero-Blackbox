from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel


class JobCreate(BaseModel):
    """
    Payload de creación de jobs.

    type:
      - wifi_recon
      - bt_recon
      - wifi_active
      - bt_active
      - hash_lookup
      - etc.

    profile:
      - Nombre del perfil de red (wifi_audit, bluetooth_audit, ...)
      - Puede ser null si el job no requiere cambio de perfil
        (por ejemplo, hash_lookup).

    params:
      - Diccionario flexible con parámetros específicos del job.
      - Para type == "hash_lookup", ejemplos:

        {"mode": "hash",
         "value": "8124BC0A5335C27F086F24BA2C7A4810",
         "hash_algo": "md5",
         "services": ["onlinehashcrack", "leakcheck"]}

        {"mode": "wpa_capture",
         "pcap_path": "/opt/blackbox/data/captures/wpa_handshake_01.pcap",
         "bssid": "AA:BB:CC:DD:EE:FF",
         "ssid": "MiRed",
         "services": ["wpa_sec"]}

        {"mode": "leakcheck",
         "value": "example@example.com",
         "services": ["leakcheck"]}
    """
    type: str
    profile: Optional[str] = None
    params: Optional[Dict[str, Any]] = None


class JobOut(BaseModel):
    """
    Representación pública de un Job.

    Incluye params para poder inspeccionar qué se pidió exactamente,
    especialmente útil para jobs tipo hash_lookup.
    """
    id: int
    type: str
    profile: Optional[str]
    status: str
    params: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True  # SQLAlchemy -> Pydantic
