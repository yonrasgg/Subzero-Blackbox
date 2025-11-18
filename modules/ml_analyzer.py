#!/usr/bin/env python3
"""
modules/ml_analyzer.py

Machine Learning analyzer for audit data.

- Clustering of Wi-Fi networks
- Predictive risk analysis
- Optimized for low-resource environments.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict

from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import yaml

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config" / "config.yaml"
DATA_DIR = BASE_DIR / "data"


def _load_config() -> Dict[str, Any]:
    """Load config.yaml and merge with secrets.yaml if it exists."""
    if not CONFIG_PATH.is_file():
        return {}
    
    # Load main config
    data = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
    
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
        deep_merge(data, secrets)
    
    return data


def cluster_wifi_networks(job_id: int) -> Dict[str, Any]:
    """Cluster Wi-Fi networks from recon data using K-Means."""
    json_path = DATA_DIR / f"wifi_recon_job_{job_id}.json"
    if not json_path.is_file():
        return {"error": "No Wi-Fi recon data found for job."}

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        logger.error("Error loading Wi-Fi data: %s", e)
        return {"error": str(e)}

    networks = data.get("networks", [])
    if not networks:
        return {"error": "No networks found in data."}

    # Extract features: signal strength, security type (encoded), channel
    features = []
    network_names = []
    for net in networks:
        signal = net.get("signal", -100)
        security = net.get("security", "open")
        channel = net.get("channel", 1)

        # Encode security: open=0, wep=1, wpa=2, wpa2=3, wpa3=4
        sec_map = {"open": 0, "wep": 1, "wpa": 2, "wpa2": 3, "wpa3": 4}
        sec_encoded = sec_map.get(security.lower(), 0)

        features.append([signal, sec_encoded, channel])
        network_names.append(net.get("ssid", "unknown"))

    if len(features) < 2:
        return {"clusters": [{"networks": network_names, "centroid": features[0] if features else []}]}

    # Standardize features
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)

    # K-Means clustering (assume 3 clusters for simplicity)
    n_clusters = min(3, len(features))
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    labels = kmeans.fit_predict(features_scaled)

    # Group networks by cluster
    clusters = {}
    for i, label in enumerate(labels):
        if label not in clusters:
            clusters[label] = {"networks": [], "centroid": kmeans.cluster_centers_[label].tolist()}
        clusters[label]["networks"].append(network_names[i])

    return {"clusters": list(clusters.values())}


def predict_risk(network_data: Dict[str, Any]) -> str:
    """Simple rule-based risk prediction for a network."""
    security = network_data.get("security", "open").lower()
    signal = network_data.get("signal", -100)

    risk = "low"
    if security in ["open", "wep"]:
        risk = "high"
    elif security == "wpa":
        risk = "medium"
    elif signal < -80:
        risk = "medium"  # Weak signal

    return risk