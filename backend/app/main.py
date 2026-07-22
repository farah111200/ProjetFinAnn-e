import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import Base, engine, SessionLocal
from app import models  # noqa: F401 (nécessaire pour que les tables soient enregistrées)
from app.models import User, UserRole
from app.core.config import settings
from app.core.security import hash_password
from app.services.scheduler import start_scheduler
from app.routes import auth, scans, schedule, audit, stats

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)

app = FastAPI(title="AI Pentest Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # à restreindre en production
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(schedule.router)
app.include_router(audit.router)
app.include_router(stats.router)


@app.on_event("startup")
def on_startup():
    # Crée les tables si elles n'existent pas encore
    Base.metadata.create_all(bind=engine)

    # Crée un compte admin par défaut si la base est vide (pratique en dev/démo)
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            admin = User(
                username=settings.FIRST_ADMIN_USERNAME,
                email=settings.FIRST_ADMIN_EMAIL,
                password_hash=hash_password(settings.FIRST_ADMIN_PASSWORD),
                role=UserRole.ADMIN,
            )
            db.add(admin)
            db.commit()
    finally:
        db.close()

    start_scheduler()


@app.get("/")
def root():
    return {"message": "Backend AI Pentest opérationnel"}


@app.get("/health")
def health_check():
    return {"status": "ok"}
