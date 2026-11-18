import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import Base, engine, migrate_auth_schema
from .routers import admin, auth, scans, survey
from .services import ml

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    migrate_auth_schema()
    ml.load_model()                          # trains a starter model if none exists
    yield


app = FastAPI(title="CPhishTank API", version="1.0.0",
              description="Explainable phishing detection for email and SMS.", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.CORS_ORIGINS, allow_origin_regex=r"(chrome|moz)-extension://.*",
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
for r in (auth.router, scans.router, survey.router, admin.router):
    app.include_router(r)


@app.get("/api/health")
def health():
    m = ml.metrics()
    return {"status": "ok", "model_loaded": ml._bundle is not None, "model_trained_at": m.get("trained_at")}
