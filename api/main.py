"""
api/main.py

FastAPI app for Blackbox:
- API Endpoints (JSON): /health, /jobs
- UI HTML (Jinja2): /ui/dashboard, /ui/jobs, /ui/config
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Request,
    status,
    Form,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session
import yaml
import psutil
import json
import logging


from worker.db import SessionLocal, Job, Run  # Usa los modelos del Step 2
from worker.db import Vulnerability, AuditData, ProfileLog
from modules import report_generator
from modules.cve_lookup import CVELookup

logger = logging.getLogger(__name__)

# --- Paths and templates ---

BASE_DIR = Path(__file__).resolve().parent.parent

# Load security environment variables for AI libraries
import os
security_env_path = BASE_DIR / "config" / "security.env"
if security_env_path.exists():
    from dotenv import load_dotenv
    load_dotenv(security_env_path)
    logger.info("Security environment variables loaded from config/security.env")
else:
    logger.warning("Security environment file not found at config/security.env")

TEMPLATES_DIR = BASE_DIR / "api" / "templates"
CONFIG_PATH = BASE_DIR / "config" / "config.yaml"
PROFILES_PATH = BASE_DIR / "config" / "profiles.yaml"
API_USAGE_PATH = BASE_DIR / "api_usage.json"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

app = FastAPI(title="Blackbox API + UI")

# --- CORS (adjust according to your LAN) ---

origins = [
    "http://localhost",
    "http://localhost:8010",
    # Add here "http://YOUR_PI_IP:8010" if you access directly by IP
    # or "http://blackbox.local:8010" if you use mDNS/hostname
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# --- DB Dependency ---

def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Basic Auth for UI ---

security = HTTPBasic()

UI_USER = "admin"
UI_PASS = "change-this"  # change it later, or read from config/env


def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    correct_username = secrets.compare_digest(credentials.username, UI_USER)
    correct_password = secrets.compare_digest(credentials.password, UI_PASS)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# --- Utilities for config/profiles ---

def _load_yaml(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    
    # If loading config.yaml, merge secrets.yaml if it exists
    if path.name == "config.yaml":
        secrets_path = path.parent / "secrets.yaml"
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


def get_active_profile_info() -> Dict[str, Any]:
    cfg = _load_yaml(CONFIG_PATH)
    profiles_all = _load_yaml(PROFILES_PATH).get("profiles", {})
    active_name = cfg.get("profiles", {}).get("active_profile")

    if not active_name:
        return {"active_profile": None, "internet_via": None, "modules_enabled": []}

    data = profiles_all.get(active_name, {})
    return {
        "active_profile": active_name,
        "internet_via": data.get("internet_via"),
        "modules_enabled": data.get("modules_enabled", []),
    }


def load_api_usage() -> int:
    if not API_USAGE_PATH.is_file():
        return 0
    try:
        with open(API_USAGE_PATH, 'r') as f:
            data = json.load(f)
        return data.get("total_calls", 0)
    except Exception:
        return 0


def increment_api_usage():
    current = load_api_usage()
    with open(API_USAGE_PATH, 'w') as f:
        json.dump({"total_calls": current + 1}, f)

# --- Pydantic Models for Jobs ---

class JobCreate(BaseModel):
    type: str
    profile: Optional[str] = None
    params: Optional[Dict[str, Any]] = None


class JobOut(BaseModel):
    id: int
    type: str
    profile: Optional[str]
    status: str

    model_config = ConfigDict(from_attributes=True)

# --- Basic JSON API ---

@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "blackbox-api"}


@app.get("/api/hardware")
def get_hardware() -> Dict[str, Any]:
    """Get real-time hardware stats: CPU, memory, battery."""
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    battery = psutil.sensors_battery()
    
    data = {
        "cpu_percent": cpu_percent,
        "memory_percent": memory.percent,
        "memory_used_gb": round(memory.used / (1024**3), 2),
        "memory_total_gb": round(memory.total / (1024**3), 2),
    }
    
    if battery:
        data["battery_percent"] = battery.percent
        data["battery_plugged"] = battery.power_plugged
    else:
        data["battery_percent"] = None
        data["battery_plugged"] = None
    
    return data


@app.get("/api/ai_assistant")
def get_ai_assistant() -> Dict[str, Any]:
    """Get AI assistant state: Rayden level, messages."""
    try:
        from ai.dialogue import get_dialogue

        # Calculate level based on API usage and jobs
        api_calls = load_api_usage()
        # Simple level calculation
        level = min(10, api_calls // 10 + 1)  # Level up every 10 API calls
        size_percent = (level / 10) * 100  # Size of Rayden inside cube

        # Get contextual dialogue based on system state
        context = "idle"  # Default context
        if api_calls < 5:
            context = "boot"  # Early stage
        elif api_calls > 50:
            context = "success"  # Experienced system

        dialogue = get_dialogue(context=context)
        message = dialogue["text"] if dialogue else "Sistema operativo. Modo de espera activado."

        return {
            "level": level,
            "rayden_size": size_percent,
            "message": message,
            "character": dialogue.get("speaker", "system") if dialogue else "system",
            "emotion": dialogue.get("emotion", "neutral") if dialogue else "neutral",
            "absorbing": api_calls < 5  # If low activity, absorbing
        }

    except Exception as e:
        logger.error(f"Error getting AI assistant state: {e}")
        # Fallback to original implementation
        api_calls = load_api_usage()
        level = min(10, api_calls // 10 + 1)
        size_percent = (level / 10) * 100

        messages = [
            "Rayden: ¡Hola! Estoy aprendiendo sobre redes Wi-Fi vulnerables.",
            "Subzero: Keep security high, or I'll freeze more.",
            "Rayden: I detected a correlation: open networks are risky.",
            "Subzero: Absorbing energy... Keep auditing!",
        ]
        message = messages[level % len(messages)]

        return {
            "level": level,
            "rayden_size": size_percent,
            "message": message,
            "absorbing": api_calls < 5
        }


@app.get("/api/api_usage")
def get_api_usage() -> Dict[str, Any]:
    """Get API usage stats: total calls to various APIs."""
    # Simulated API usage data - in a real implementation, this would track actual API calls
    # For now, return incremental data
    import random
    
    # Use a simple file-based counter for persistence
    counter_file = BASE_DIR / "api_usage_counter.json"
    if counter_file.exists():
        import json
        with open(counter_file, 'r') as f:
            counters = json.load(f)
    else:
        counters = {
            "google_gemini": 0,
            "onlinehashcrack": 0,
            "wpasec": 0,
            "wigle": 0,
            "total": 0
        }
    
    # Simulate some API calls (increment randomly)
    if random.random() < 0.3:  # 30% chance to increment
        api = random.choice(["google_gemini", "onlinehashcrack", "wpasec", "wigle"])
        counters[api] += 1
        counters["total"] += 1
    
    # Save back
    import json
    with open(counter_file, 'w') as f:
        json.dump(counters, f)
    
    return counters


@app.get("/api/cves")
def get_cves(
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    keyword: Optional[str] = None,
    cvss_severity: Optional[str] = None,
    limit: int = 10
) -> Dict[str, Any]:
    """Query CVEs from various APIs based on parameters."""
    cve_lookup = CVELookup()
    results = {"opencve": [], "nvd": [], "cve_search": []}

    try:
        if vendor or product:
            results["opencve"] = cve_lookup.query_opencve_cves(vendor=vendor, product=product, limit=limit)
    except ValueError as e:
        results["opencve_error"] = str(e)

    try:
        if keyword or cvss_severity:
            results["nvd"] = cve_lookup.query_nvd_cves(keyword=keyword, cvss_severity=cvss_severity, limit=limit)
    except Exception as e:
        results["nvd_error"] = str(e)

    try:
        if vendor:
            results["cve_search"] = cve_lookup.query_cve_search(vendor=vendor, product=product)
    except Exception as e:
        results["cve_search_error"] = str(e)

    increment_api_usage()  # Track API usage
    return results


@app.post("/api/parse_embedded")
def parse_embedded(content: str, content_type: str = "html") -> Dict[str, Any]:
    """Parse embedded HTML/XML content and correlate with vulnerabilities."""
    cve_lookup = CVELookup()
    parsed = cve_lookup.parse_embedded_data(content, content_type)
    correlations = cve_lookup.correlate_vulnerabilities(parsed, "general")  # Can specify audit_type later
    increment_api_usage()
    return {"parsed_data": parsed, "correlations": correlations}


@app.get("/api/ai/stats")
def get_ai_stats(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Get AI system statistics and status."""
    try:
        from ai.pipeline import get_ai_stats
        stats = get_ai_stats(db)
        increment_api_usage()
        return stats
    except ImportError:
        return {
            "error": "AI modules not available",
            "pipeline_status": {"embeddings_available": False, "classification_available": False}
        }
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/ai/search")
def ai_search_similar(
    query: str,
    top_k: int = 5,
    object_types: Optional[List[str]] = None,
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Search for similar findings using AI embeddings."""
    try:
        from ai.embeddings import search_similar
        results = search_similar(query, top_k=top_k, object_types=object_types, session=db)
        increment_api_usage()
        return {"query": query, "results": results}
    except ImportError:
        raise HTTPException(status_code=503, detail="AI embeddings not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI search failed: {str(e)}")


@app.post("/api/ai/chat")
def ai_chat(
    question: str,
    context_limit: int = 3,
    include_dialogue: bool = True,
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """AI-powered chat with audit context using offline intelligence."""
    try:
        from ai.pipeline import build_context_for_question, ai_pipeline

        # Build context from offline AI
        context = build_context_for_question(question, db, top_k=context_limit)

        # Determine dialogue context based on question content
        dialogue_context = "system"  # default
        question_lower = question.lower()

        if any(word in question_lower for word in ["wifi", "red", "inalámbrica", "network"]):
            dialogue_context = "wifi_audit"
        elif any(word in question_lower for word in ["bluetooth", "bt", "bluetooth"]):
            dialogue_context = "bt_audit"
        elif any(word in question_lower for word in ["usb", "hid", "dispositivo"]):
            dialogue_context = "usb_audit"
        elif any(word in question_lower for word in ["hash", "contraseña", "password", "crack"]):
            dialogue_context = "hashing"
        elif any(word in question_lower for word in ["error", "fallo", "problema"]):
            dialogue_context = "error"
        elif any(word in question_lower for word in ["éxito", "completado", "terminado", "success"]):
            dialogue_context = "success"
        elif any(word in question_lower for word in ["job", "trabajo", "tarea"]):
            dialogue_context = "notification"

        # For now, return offline response
        # In the future, this could enhance with Google Gen AI if available
        response = {
            "question": question,
            "offline_response": True,
            "context_summary": context.get("context_summary", "No relevant context found"),
            "similar_findings_count": len(context.get("similar_findings", [])),
            "ai_available": context.get("ai_available", {}),
            "dialogue_context": dialogue_context
        }

        # Add dialogue enhancement if requested
        if include_dialogue:
            enhanced_response = ai_pipeline.enhance_response_with_dialogue(response.copy(), dialogue_context)
            response.update({
                "dialogue": enhanced_response.get("dialogue"),
                "character_response": enhanced_response.get("character_response"),
                "character_speaker": enhanced_response.get("character_speaker"),
                "character_emotion": enhanced_response.get("character_emotion"),
                "personality": enhanced_response.get("personality"),
                "style": enhanced_response.get("style")
            })

        # Try to enhance with Google Gen AI if available
        try:
            from modules.report_generator import _get_google_api_key
            api_key = _get_google_api_key()
            if api_key:
                import google.generativeai as genai
                genai.configure(api_key=api_key)

                # Determine which character to use for the AI response
                character_name = response.get("character_speaker", "Rayden")
                personality_desc = "an electric, energetic AI" if character_name == "rayden" else "a cold, precise AI"

                # Build enhanced prompt with offline context and character personality
                enhanced_prompt = f"""
You are {character_name}, {personality_desc} cybersecurity assistant in Subzero-Blackbox.

User Question: {question}

Offline AI Context (from local audit database):
{context.get('context_summary', 'No context available')}

Similar findings: {len(context.get('similar_findings', []))} found

Character Style: {response.get('style', 'professional')}
Personality: {response.get('personality', 'helpful')}

Please provide a helpful, security-focused response in character. If you have specific recommendations based on the context, include them.
Keep your response concise but informative, and stay in character.
"""

                model = genai.GenerativeModel('gemini-1.5-flash')
                gemini_response = model.generate_content(enhanced_prompt)

                response["online_response"] = True
                response["enhanced_answer"] = gemini_response.text
                increment_api_usage()  # Count as API usage

        except Exception as gemini_error:
            logger.debug(f"Google Gen AI enhancement failed: {gemini_error}")
            response["online_response"] = False
            response["enhancement_error"] = "Online AI enhancement unavailable"

        return response

    except ImportError:
        raise HTTPException(status_code=503, detail="AI pipeline not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI chat failed: {str(e)}")


@app.post("/api/ai/classify")
def ai_classify_text(
    text: str,
    classification_types: Optional[List[str]] = None,
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Classify text using offline AI classifiers."""
    try:
        from ai.classifier import classify_vulnerability

        if not classification_types:
            classification_types = ["vuln_type", "attack_family", "domain", "severity"]

        # For vulnerability-like text, use specialized classification
        if any(keyword in text.lower() for keyword in ["vulnerable", "exploit", "attack", "security", "risk"]):
            classifications = classify_vulnerability(text)
        else:
            # Use general classifiers
            from ai.classifier import classifier_manager
            classifications = {}
            for clf_type in classification_types:
                result = classifier_manager.classify_text(text, clf_type)
                if result:
                    classifications[clf_type] = result

        increment_api_usage()
        return {
            "text_preview": text[:100] + "..." if len(text) > 100 else text,
            "classifications": classifications
        }

    except ImportError:
        raise HTTPException(status_code=503, detail="AI classification not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI classification failed: {str(e)}")


@app.get("/api/ai/dialogue")
def get_ai_dialogue(
    context: Optional[str] = None,
    speaker: Optional[str] = None,
    emotion: Optional[str] = None
) -> Dict[str, Any]:
    """Get a contextual dialogue from Subzero or Rayden."""
    try:
        from ai.pipeline import ai_pipeline
        dialogue = ai_pipeline.generate_dialogue_response(context, emotion, speaker)

        if not dialogue:
            raise HTTPException(status_code=404, detail="No dialogue found for the given criteria")

        increment_api_usage()
        return {
            "dialogue": dialogue,
            "context": context,
            "filters": {"speaker": speaker, "emotion": emotion}
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dialogue generation failed: {str(e)}")


@app.get("/api/ai/conversation")
def get_ai_conversation(
    context: str,
    length: int = 2
) -> Dict[str, Any]:
    """Get a conversation sequence between Subzero and Rayden."""
    try:
        from ai.pipeline import ai_pipeline

        if length < 1 or length > 10:
            raise HTTPException(status_code=400, detail="Conversation length must be between 1 and 10")

        conversation = ai_pipeline.generate_conversation(context, length)

        if not conversation:
            raise HTTPException(status_code=404, detail=f"No conversation found for context: {context}")

        increment_api_usage()
        return {
            "conversation": conversation,
            "context": context,
            "length": len(conversation)
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Conversation generation failed: {str(e)}")


@app.get("/api/ai/dialogue/stats")
def get_dialogue_stats() -> Dict[str, Any]:
    """Get dialogue system statistics."""
    try:
        from ai.dialogue import dialogue_manager
        stats = dialogue_manager.get_stats()
        increment_api_usage()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get dialogue stats: {str(e)}")


@app.post("/jobs", response_model=JobOut)
def create_job(job_in: JobCreate, db: Session = Depends(get_db)) -> JobOut:
    """
    Creates a job in 'queued' state.
    The worker will pick it up and update its state.
    """
    job = Job(
        type=job_in.type,
        profile=job_in.profile,
        params=job_in.params or {},
        status="queued",
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job  # FastAPI serializes it according to JobOut


@app.get("/jobs", response_model=List[JobOut])
def list_jobs(db: Session = Depends(get_db)) -> List[JobOut]:
    jobs = db.query(Job).order_by(Job.created_at.desc()).all()
    return jobs

# --- UI: HTML routes ---

@app.get("/", response_class=RedirectResponse)
def root_redirect() -> RedirectResponse:
    """
    Redirects to /ui/home.
    """
    return RedirectResponse(url="/ui/home")


@app.get("/ui/home", response_class=HTMLResponse, include_in_schema=False)
def ui_home(
    request: Request,
    username: str = Depends(verify_credentials),
) -> HTMLResponse:
    return templates.TemplateResponse(
        "home.html",
        {
            "request": request,
            "user": username,
        },
    )


@app.get("/ui/dashboard", response_class=HTMLResponse)
def ui_dashboard(
    request: Request,
    username: str = Depends(verify_credentials),
    db: Session = Depends(get_db),
) -> Any:
    """
    Main dashboard page.
    Shows:
    - Job stats
    - Active profile info
    - 'Start Wi-Fi Audit' and 'Start BT Audit' buttons
    """
    # Basic job stats
    total_jobs = db.query(Job).count()
    queued = db.query(Job).filter(Job.status == "queued").count()
    running = db.query(Job).filter(Job.status == "running").count()
    finished = db.query(Job).filter(Job.status == "finished").count()
    error = db.query(Job).filter(Job.status == "error").count()

    last_jobs = (
        db.query(Job)
        .order_by(Job.created_at.desc())
        .limit(10)
        .all()
    )

    profile_info = get_active_profile_info()

    context = {
        "request": request,
        "user": username,
        "stats": {
            "total_jobs": total_jobs,
            "queued": queued,
            "running": running,
            "finished": finished,
            "error": error,
        },
        "jobs": last_jobs,
	"active_profile": profile_info["active_profile"],
        "internet_via": profile_info["internet_via"],
        "modules_enabled": profile_info["modules_enabled"],
    }
    return templates.TemplateResponse("dashboard.html", context)


@app.get("/ui/jobs", response_class=HTMLResponse)
def ui_jobs(
    request: Request,
    username: str = Depends(verify_credentials),
    db: Session = Depends(get_db),
) -> Any:
    """
    HTML view to see the full job queue only.
    """
    jobs = db.query(Job).order_by(Job.created_at.desc()).all()
    return templates.TemplateResponse(
        "jobs.html",
        {
            "request": request,
            "user": username,
            "jobs": jobs,
        },
    )


@app.get("/ui/config", response_class=HTMLResponse)
def ui_config(
    request: Request,
    username: str = Depends(verify_credentials),
) -> Any:
    info = get_active_profile_info()
    config = _load_yaml(CONFIG_PATH)
    return templates.TemplateResponse(
        "config.html",
        {
            "request": request,
            "user": username,
            "active_profile": info["active_profile"],
            "internet_via": info["internet_via"],
            "modules_enabled": info["modules_enabled"],
            "config": config,
        },
    )


@app.get("/ui/audits_config", response_class=HTMLResponse)
def ui_audits_config(
    request: Request,
    username: str = Depends(verify_credentials),
) -> Any:
    config = _load_yaml(CONFIG_PATH)
    profiles = _load_yaml(PROFILES_PATH)
    return templates.TemplateResponse(
        "audits_config.html",
        {
            "request": request,
            "user": username,
            "config": config,
            "profiles": profiles,
        },
    )


@app.get("/ui/logs", response_class=HTMLResponse, include_in_schema=False)
def ui_logs(
    request: Request,
    username: str = Depends(verify_credentials),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    # Get recent jobs with their runs
    recent_jobs = (
        db.query(Job)
        .order_by(Job.created_at.desc())
        .limit(20)
        .all()
    )
    
    # Get vulnerabilities
    vulnerabilities = (
        db.query(Vulnerability)
        .order_by(Vulnerability.created_at.desc())
        .limit(50)
        .all()
    )
    
    # Get audit data
    audit_data = (
        db.query(AuditData)
        .order_by(AuditData.created_at.desc())
        .limit(100)
        .all()
    )
    
    # Get profile logs
    profile_logs = (
        db.query(ProfileLog)
        .order_by(ProfileLog.created_at.desc())
        .limit(20)
        .all()
    )
    
    return templates.TemplateResponse(
        "logs.html",
        {
            "request": request,
            "user": username,
            "jobs": recent_jobs,
            "vulnerabilities": vulnerabilities,
            "audit_data": audit_data,
            "profile_logs": profile_logs,
        },
    )


@app.post("/ui/config/save", include_in_schema=False)
def ui_save_config(
    request: Request,
    username: str = Depends(verify_credentials),
    ui_username: str = Form(...),
    ui_password: str = Form(...),
    google_api_key: str = Form(...),
    onlinehashcrack_api_key: str = Form(...),
    wpasec_api_key: str = Form(...),
    wigle_api_name: str = Form(...),
    wigle_api_token: str = Form(...),
) -> HTMLResponse:
    config = _load_yaml(CONFIG_PATH)
    config["ui"] = {"username": ui_username, "password": ui_password}
    config["apis"] = {
        "google_api_key": google_api_key,
        "onlinehashcrack_api_key": onlinehashcrack_api_key,
        "wpasec_api_key": wpasec_api_key,
        "wigle_api_name": wigle_api_name,
        "wigle_api_token": wigle_api_token,
    }
    # Save to file
    import yaml
    with open(CONFIG_PATH, 'w') as f:
        yaml.dump(config, f)
    # Reload and return
    info = get_active_profile_info()
    config = _load_yaml(CONFIG_PATH)
    return templates.TemplateResponse(
        "config.html",
        {
            "request": request,
            "user": username,
            "active_profile": info["active_profile"],
            "internet_via": info["internet_via"],
            "modules_enabled": info["modules_enabled"],
            "config": config,
            "message": "Configuration saved successfully.",
        },
    )


@app.post("/ui/audits_config/save", include_in_schema=False)
def ui_save_audits_config(
    request: Request,
    username: str = Depends(verify_credentials),
    wifi_timeout: Optional[int] = Form(None),
    wifi_max_networks: Optional[int] = Form(None),
    enable_vulnerability_scan: Optional[str] = Form(None),
    scan_types: Optional[List[str]] = Form(None),
    captured_data_analysis: Optional[List[str]] = Form(None),
    bt_enable_vulnerability_scan: Optional[str] = Form(None),
    bt_scan_types: Optional[List[str]] = Form(None),
    bt_captured_data_analysis: Optional[List[str]] = Form(None),
    usb_enable_vulnerability_scan: Optional[str] = Form(None),
    usb_scan_types: Optional[List[str]] = Form(None),
    usb_captured_data_analysis: Optional[List[str]] = Form(None),
) -> HTMLResponse:
    config = _load_yaml(CONFIG_PATH)
    if "wifi_audits" not in config:
        config["wifi_audits"] = {}
    config["wifi_audits"]["enable_vulnerability_scan"] = enable_vulnerability_scan == "on"
    config["wifi_audits"]["scan_types"] = scan_types or []
    config["wifi_audits"]["captured_data_analysis"] = {
        "manufacturer_mac": "manufacturer_mac" in (captured_data_analysis or []),
        "ip_recognition": "ip_recognition" in (captured_data_analysis or []),
        "exposed_services": "exposed_services" in (captured_data_analysis or []),
        "captive_portals": "captive_portals" in (captured_data_analysis or []),
    }
    if "bt_audits" not in config:
        config["bt_audits"] = {}
    config["bt_audits"]["enable_vulnerability_scan"] = bt_enable_vulnerability_scan == "on"
    config["bt_audits"]["scan_types"] = bt_scan_types or []
    config["bt_audits"]["captured_data_analysis"] = {
        "device_info": "device_info" in (bt_captured_data_analysis or []),
        "service_discovery": "service_discovery" in (bt_captured_data_analysis or []),
        "pairing_info": "pairing_info" in (bt_captured_data_analysis or []),
    }
    if "usb_audits" not in config:
        config["usb_audits"] = {}
    config["usb_audits"]["enable_vulnerability_scan"] = usb_enable_vulnerability_scan == "on"
    config["usb_audits"]["scan_types"] = usb_scan_types or []
    config["usb_audits"]["captured_data_analysis"] = {
        "device_identification": "device_identification" in (usb_captured_data_analysis or []),
        "firmware_analysis": "firmware_analysis" in (usb_captured_data_analysis or []),
        "data_exfiltration": "data_exfiltration" in (usb_captured_data_analysis or []),
    }
    # Save to file
    import yaml
    with open(CONFIG_PATH, 'w') as f:
        yaml.dump(config, f)
    # Reload and return
    config = _load_yaml(CONFIG_PATH)
    return templates.TemplateResponse(
        "audits_config.html",
        {
            "request": request,
            "user": username,
            "config": config,
            "message": "Audits configuration saved successfully.",
        },
    )


@app.get("/ui/jobs/{job_id}", response_class=HTMLResponse, include_in_schema=False)
def ui_job_detail(
    request: Request,
    job_id: int,
    username: str = Depends(verify_credentials),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    run = db.query(Run).filter(Run.job_id == job_id).first()
    # For now, simple detail
    return templates.TemplateResponse(
        "job_detail.html",
        {
            "request": request,
            "user": username,
            "job": job,
            "run": run,
        },
    )


@app.get("/ui/jobs/{job_id}/report", response_class=HTMLResponse, include_in_schema=False)
def ui_job_report(
    request: Request,
    job_id: int,
    username: str = Depends(verify_credentials),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    run = db.query(Run).filter(Run.job_id == job_id).first()
    report = report_generator.generate_report(
        db, job.type, job.id,
        run.stdout if run else "",
        run.stderr if run else ""
    )
    return templates.TemplateResponse(
        "job_report.html",
        {
            "request": request,
            "user": username,
            "job": job,
            "run": run,
            "report": report,
        },
    )


@app.get("/ui/jobs/{job_id}/attack", response_class=HTMLResponse, include_in_schema=False)
def ui_job_attack(
    request: Request,
    job_id: int,
    username: str = Depends(verify_credentials),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    # Placeholder for attack config
    return templates.TemplateResponse(
        "job_attack.html",
        {
            "request": request,
            "user": username,
            "job": job,
        },
    )

# --- UI actions that trigger jobs ---

@app.post("/ui/jobs/start/wifi")
def ui_start_wifi_job(
    request: Request,
    username: str = Depends(verify_credentials),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """
    Creates a Wi-Fi job.
    type=wifi_recon, profile=wifi_audit.
    """
    job = Job(
        type="wifi_recon",
        profile="wifi_audit",
        params={"source": "ui"},
        status="queued",
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Recalculate stats and latest jobs to return to dashboard
    total_jobs = db.query(Job).count()
    queued = db.query(Job).filter(Job.status == "queued").count()
    running = db.query(Job).filter(Job.status == "running").count()
    finished = db.query(Job).filter(Job.status == "finished").count()
    error = db.query(Job).filter(Job.status == "error").count()
    last_jobs = (
        db.query(Job)
        .order_by(Job.created_at.desc())
        .limit(10)
        .all()
    )

    profile_info = get_active_profile_info()

    context = {
        "request": request,
        "user": username,
        "stats": {
            "total_jobs": total_jobs,
            "queued": queued,
            "running": running,
            "finished": finished,
            "error": error,
        },
        "jobs": last_jobs,
        "active_profile": profile_info["active_profile"],
        "internet_via": profile_info["internet_via"],
        "modules_enabled": profile_info["modules_enabled"],
        "message": f"Wi-Fi audit job queued with id={job.id}",
    }
    return templates.TemplateResponse("dashboard.html", context)


@app.post("/ui/jobs/start/bt")
def ui_start_bt_job(
    request: Request,
    username: str = Depends(verify_credentials),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """
    Creates a Bluetooth job.
    type=bt_recon, profile=bluetooth_audit.
    """
    job = Job(
        type="bt_recon",
        profile="bluetooth_audit",
        params={"source": "ui"},
        status="queued",
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    total_jobs = db.query(Job).count()
    queued = db.query(Job).filter(Job.status == "queued").count()
    running = db.query(Job).filter(Job.status == "running").count()
    finished = db.query(Job).filter(Job.status == "finished").count()
    error = db.query(Job).filter(Job.status == "error").count()
    last_jobs = (
        db.query(Job)
        .order_by(Job.created_at.desc())
        .limit(10)
        .all()
    )

    profile_info = get_active_profile_info()

    context = {
        "request": request,
        "user": username,
        "stats": {
            "total_jobs": total_jobs,
            "queued": queued,
            "running": running,
            "finished": finished,
            "error": error,
        },
        "jobs": last_jobs,
        "active_profile": profile_info["active_profile"],
        "internet_via": profile_info["internet_via"],
        "modules_enabled": profile_info["modules_enabled"],
        "message": f"BT audit job queued with id={job.id}",
    }
    return templates.TemplateResponse("dashboard.html", context)


@app.post("/ui/jobs/start/usb_hid")
def ui_start_usb_hid_job(
    request: Request,
    username: str = Depends(verify_credentials),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """
    Creates a USB HID audit job.
    type=usb_hid_audit, profile=usb_audit.
    """
    job = Job(
        type="usb_hid_audit",
        profile="usb_audit",
        params={"source": "ui"},
        status="queued",
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    total_jobs = db.query(Job).count()
    queued = db.query(Job).filter(Job.status == "queued").count()
    running = db.query(Job).filter(Job.status == "running").count()
    finished = db.query(Job).filter(Job.status == "finished").count()
    error = db.query(Job).filter(Job.status == "error").count()
    last_jobs = (
        db.query(Job)
        .order_by(Job.created_at.desc())
        .limit(10)
        .all()
    )

    profile_info = get_active_profile_info()

    context = {
        "request": request,
        "user": username,
        "stats": {
            "total_jobs": total_jobs,
            "queued": queued,
            "running": running,
            "finished": finished,
            "error": error,
        },
        "jobs": last_jobs,
        "active_profile": profile_info["active_profile"],
        "internet_via": profile_info["internet_via"],
        "modules_enabled": profile_info["modules_enabled"],
        "message": f"USB HID audit job queued with id={job.id}",
    }
    return templates.TemplateResponse("dashboard.html", context)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
