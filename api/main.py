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

from worker.db import SessionLocal, Job  # Usa los modelos del Step 2


# --- Paths and templates ---

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "api" / "templates"
CONFIG_PATH = BASE_DIR / "config" / "config.yaml"
PROFILES_PATH = BASE_DIR / "config" / "profiles.yaml"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

app = FastAPI(title="Blackbox API + UI")

# --- CORS (ajusta según tu LAN) ---

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
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


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
    return job  # FastAPI lo serializa según JobOut


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


@app.get("/ui/logs", response_class=HTMLResponse, include_in_schema=False)
def ui_logs(
    request: Request,
    username: str = Depends(verify_credentials),
) -> HTMLResponse:
    # Placeholder for logs
    logs = ["Log entry 1", "Log entry 2"]  # Replace with real logs
    return templates.TemplateResponse(
        "logs.html",
        {
            "request": request,
            "user": username,
            "logs": logs,
        },
    )


@app.post("/ui/config/save", include_in_schema=False)
def ui_save_config(
    request: Request,
    username: str = Depends(verify_credentials),
    ui_username: str = Form(...),
    ui_password: str = Form(...),
    google_api_key: str = Form(...),
    online_hashcat_api_key: str = Form(...),
    leakcheck_api_key: str = Form(...),
    wiggle_api_key: str = Form(...),
) -> HTMLResponse:
    config = _load_yaml(CONFIG_PATH)
    config["ui"] = {"username": ui_username, "password": ui_password}
    config["apis"] = {
        "google_api_key": google_api_key,
        "online_hashcat_api_key": online_hashcat_api_key,
        "leakcheck_api_key": leakcheck_api_key,
        "wiggle_api_key": wiggle_api_key,
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
    # For now, simple detail
    return templates.TemplateResponse(
        "job_detail.html",
        {
            "request": request,
            "user": username,
            "job": job,
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
    # Placeholder for report with AI
    return templates.TemplateResponse(
        "job_report.html",
        {
            "request": request,
            "user": username,
            "job": job,
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
