"""FastAPI application entry point."""

from fastapi import FastAPI

from app.api.deps import get_policy
from app.api.upload_limit import UploadLimitMiddleware
from app.api.v1 import api_router
from app.core.config import get_settings
from app.core.errors import install_error_handlers


def create_app() -> FastAPI:
    # Load settings now so a missing required variable stops startup immediately.
    get_settings()
    get_policy()  # fail closed: an invalid access policy stops startup
    app = FastAPI(title="TraceLock", version="0.1.0")
    install_error_handlers(app)
    app.add_middleware(UploadLimitMiddleware)
    app.include_router(api_router, prefix="/api/v1")
    return app


app = create_app()
