from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel


class JobCreate(BaseModel):
    """
    Job creation payload.

    type:
      - wifi_recon
      - bt_recon
      - wifi_active
      - bt_active
      - hash_lookup
      - etc.

    profile:
      - Name of the network profile (wifi_audit, bluetooth_audit, ...)
      - Can be null if the job does not require a profile change
        (for example, hash_lookup).

    params:
      - Flexible dictionary with job-specific parameters.
      - For type == "hash_lookup", examples:

        {"mode": "hash",
         "value": "8124BC0A5335C27F086F24BA2C7A4810",
         "hash_algo": "md5",
         "services": ["onlinehashcrack", "leakcheck"]}

        {"mode": "wpa_capture",
         "pcap_path": "/opt/blackbox/data/captures/wpa_handshake_01.pcap",
         "bssid": "AA:BB:CC:DD:EE:FF",
         "ssid": "MyNetwork",
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
  Public representation of a Job.

  Includes params to inspect exactly what was requested,
  especially useful for jobs like hash_lookup.
  """
    id: int
    type: str
    profile: Optional[str]
    status: str
    params: Optional[Dict[str, Any]] = None

    class Config:
      from_attributes = True  # SQLAlchemy -> Pydantic
