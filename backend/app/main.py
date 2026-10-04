"""FastAPI application entry point."""

from fastapi import FastAPI

from app.api.v1 import api_router
from app.core.config import get_settings


def create_app() -> FastAPI:
    # Load settings now so a missing required variable stops startup immediately.
    get_settings()
    app = FastAPI(title="TraceLock", version="0.1.0")
    app.include_router(api_router, prefix="/api/v1")
    return app


app = create_app()
