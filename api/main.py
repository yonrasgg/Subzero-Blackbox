"""
api/main.py

FastAPI app para Blackbox:
- Endpoints API (JSON): /health, /jobs
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
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session
import yaml

from worker.db import SessionLocal, Job  # Usa los modelos del Step 2

# --- Paths y templates ---

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
    # Añade aquí "http://IP_DE_TU_PI:8010" si accedes por IP directa
    # o "http://blackbox.local:8010" si usas mDNS/hostname
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

# --- Auth basica para UI ---

security = HTTPBasic()

UI_USER = "admin"
UI_PASS = "change-this"  # cambiarlo mas adelante, o lee de config/env


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

# --- Utilidades de config/perfiles ---

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

# --- Modelos Pydantic para Jobs ---

class JobCreate(BaseModel):
    type: str
    profile: Optional[str] = None
    params: Optional[Dict[str, Any]] = None


class JobOut(BaseModel):
    id: int
    type: str
    profile: Optional[str]
    status: str

    class Config:
        from_attributes = True  # para SQLAlchemy 2.x

# --- API JSON básica ---

@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "blackbox-api"}


@app.post("/jobs", response_model=JobOut)
def create_job(job_in: JobCreate, db: Session = Depends(get_db)) -> JobOut:
    """
    Crea un job en estado 'queued'.
    El worker lo recogerá y actualizará su estado.
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

# --- UI: rutas HTML ---

@app.get("/", response_class=RedirectResponse)
def root_redirect() -> RedirectResponse:
    """
    Redirige a /ui/dashboard.
    """
    return RedirectResponse(url="/ui/dashboard")


@app.get("/ui/dashboard", response_class=HTMLResponse)
def ui_dashboard(
    request: Request,
    username: str = Depends(verify_credentials),
    db: Session = Depends(get_db),
) -> Any:
    """
    Página principal del panel.
    Muestra:
    - Stats de jobs
    - Información del perfil activo
    - Botones de 'Start Wi-Fi Audit' y 'Start BT Audit'
    """
    # Stats básicos de jobs
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
    Vista HTML sólo para ver la cola completa de jobs.
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
    return templates.TemplateResponse(
        "config.html",
        {
            "request": request,
            "user": username,
            "active_profile": info["active_profile"],
            "internet_via": info["internet_via"],
            "modules_enabled": info["modules_enabled"],
        },
    )

# --- Acciones UI que disparan jobs ---

@app.post("/ui/jobs/start/wifi")
def ui_start_wifi_job(
    request: Request,
    username: str = Depends(verify_credentials),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """
    Crea un job Wi-Fi.
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

    # Recalcular stats y últimos jobs para volver al dashboard
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
    Crea un job Bluetooth.
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
