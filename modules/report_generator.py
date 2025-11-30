#!/usr/bin/env python3
"""
modules/report_generator.py

Generates AI-powered reports for audit jobs using Google Generative AI.

- Loads collected data from JSON files and DB.
- Uses Gemini to analyze and summarize findings.
- Optimized for low-resource environments.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from google import genai
import yaml
from dotenv import load_dotenv
from sqlalchemy.orm import Session

from worker.db import HashResult
from modules import ml_analyzer

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config" / "config.yaml"
DATA_DIR = BASE_DIR / "data"
DOTENV_PATH = BASE_DIR / ".env"

# Load environment variables from .env (if exists)
if DOTENV_PATH.is_file():
    load_dotenv(DOTENV_PATH)


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


def _get_google_api_key() -> Optional[str]:
    """Get Google AI API key from config or environment variables."""
    import os
    
    # First try to get from config
    cfg = _load_config()
    api_key = cfg.get("apis", {}).get("google_api_key")
    if api_key:
        return api_key
    
    # Fallback to environment variables
    api_key = os.getenv("GOOGLE_AI_API_KEY")
    if api_key:
        return api_key
    
    # If no key found, return None
    return None


def _load_job_data(job_type: str, job_id: int) -> Dict[str, Any]:
    """Load collected data for the job."""
    data = {}

    # Load from JSON files based on job_type
    json_files = {
        "wifi_recon": f"wifi_recon_job_{job_id}.json",
        "wifi_active": f"wifi_active_job_{job_id}.json",
        "bt_recon": f"bt_recon_job_{job_id}.json",
        "bt_active": f"bt_active_job_{job_id}.json",
    }

    if job_type in json_files:
        json_path = DATA_DIR / json_files[job_type]
        if json_path.is_file():
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    loaded_data = json.load(f)
                    data["collected_data"] = loaded_data
                    if "vulnerabilities" in loaded_data:
                        data["vulnerabilities"] = loaded_data["vulnerabilities"]
            except Exception as e:
                logger.error("Error loading JSON for %s job %s: %s", job_type, job_id, e)
                data["collected_data"] = {}

    # For hash_lookup, data is in DB, but we'll handle separately
    data["job_type"] = job_type
    data["job_id"] = job_id

    return data


def _load_hash_results(session: Session, job_id: int) -> list:
    """Load hash results from DB for hash_lookup jobs."""
    results = session.query(HashResult).filter(HashResult.job_id == job_id).all()
    return [
        {
            "service": r.service,
            "hash": r.hash,
            "plaintext": r.plaintext,
            "confidence": r.confidence,
        }
        for r in results
    ]


def generate_report(session: Session, job_type: str, job_id: int, run_stdout: str = "", run_stderr: str = "") -> str:
    """Generate an AI-powered report for the audit job using Google Gemini."""
    api_key = _get_google_api_key()
    if not api_key:
        return """# AI Report Generation Unavailable

**Configuration Required:**
To enable AI-powered report generation, you need to configure a Google Gemini API key:

1. **Get API Key**: Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. **Configure**: Add to `config/secrets.yaml`:
   ```yaml
   apis:
     google_api_key: "your_api_key_here"
   ```
3. **Alternative**: Set environment variable `GOOGLE_AI_API_KEY`

**Manual Analysis Available:**
Even without AI reports, you can analyze the raw audit data manually through the web interface.
"""

    try:
        client = genai.Client(api_key=api_key)
        
        # Test the API key with a simple request first
        client.models.generate_content(
            model="gemini-1.5-flash",
            contents="Test connection"
        )
        
    except Exception as e:
        error_msg = str(e)
        if "API_KEY_INVALID" in error_msg or "API key not valid" in error_msg:
            return """# AI Report Generation Failed

**Invalid API Key:**
The configured Google Gemini API key is not valid.

**Troubleshooting:**
1. **Verify API Key**: Ensure it's correct in `config/secrets.yaml`
2. **Check Permissions**: Make sure the API key has Gemini API access
3. **Regenerate Key**: Create a new key at [Google AI Studio](https://makersuite.google.com/app/apikey)

**Manual Analysis Available:**
You can still analyze audit data manually through the web interface.
"""
        else:
            logger.error("Error testing Google Gemini API: %s", e)
            return f"""# AI Report Generation Error

**Connection Issue:**
Unable to connect to Google Gemini API: {error_msg}

**Possible Causes:**
- Network connectivity issues
- API service temporarily unavailable
- Invalid model name or parameters

**Manual Analysis Available:**
Raw audit data is still available for manual analysis.
"""

    # Load data
    data = _load_job_data(job_type, job_id)
    if job_type == "hash_lookup":
        data["hash_results"] = _load_hash_results(session, job_id)

    # Add ML analysis if applicable
    if job_type == "wifi_recon":
        ml_result = ml_analyzer.cluster_wifi_networks(job_id)
        data["ml_analysis"] = ml_result

    # Prepare prompt for structured JSON output to reduce tokens
    prompt = f"""
You are an expert cybersecurity auditor. Analyze the following audit data and generate a report in JSON format.

Data collected:
{json.dumps(data, indent=2)}

Run output (stdout):
{run_stdout}

Run errors (stderr):
{run_stderr}

Output a JSON object with keys: "executive_summary", "detailed_findings", "recommendations", "conclusion". Include analysis of any vulnerabilities found. Keep each section concise.
"""

    try:
        # Increment API usage counter
        from api.main import increment_api_usage
        increment_api_usage()

        response = client.models.generate_content(
            model="gemini-1.5-flash",
            contents=prompt
        )
        content = response.text

        # Try to parse as JSON
        try:
            report_json = json.loads(content)
            # Format as readable text
            report = f"""
# AI-Generated Security Report

## Executive Summary
{report_json.get('executive_summary', 'N/A')}

## Detailed Findings
{report_json.get('detailed_findings', 'N/A')}

## Recommendations
{report_json.get('recommendations', 'N/A')}

## Conclusion
{report_json.get('conclusion', 'N/A')}

---
*Report generated by Google Gemini AI*
"""
            return report
        except json.JSONDecodeError:
            # Fallback to raw text
            return f"""# AI-Generated Report

{content}

---
*Report generated by Google Gemini AI*
"""

    except Exception as e:
        logger.error("Error generating report with Google Gemini: %s", e)
        error_msg = str(e)
        
        if "API_KEY_INVALID" in error_msg or "API key not valid" in error_msg:
            return """# AI Report Generation Failed

**API Key Issue:**
The Google Gemini API key appears to be invalid or expired.

**Resolution Steps:**
1. Check your API key in `config/secrets.yaml`
2. Verify the key has Gemini API permissions
3. Generate a new key if necessary

**Manual Analysis:**
Raw audit data remains available for manual review.
"""
        elif "quota" in error_msg.lower() or "rate limit" in error_msg.lower():
            return """# AI Report Generation Limited

**Quota/Ratelimit Exceeded:**
Your Google Gemini API usage has exceeded current limits.

**Resolution:**
- Wait for quota reset
- Upgrade your API plan
- Reduce report generation frequency

**Manual Analysis:**
Audit data is still available for manual analysis.
"""
        else:
            return f"""# AI Report Generation Error

**Technical Issue:**
{error_msg}

**Manual Analysis:**
Raw audit data is available for manual review through the web interface.
"""