"""Version 1 API routers."""

from fastapi import APIRouter

from app.api.v1 import auth, experiments, health, lab, streams, verification

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(streams.router)
api_router.include_router(verification.router)
api_router.include_router(lab.router)
api_router.include_router(experiments.router)
