"""Application factory. Routers and middleware are added by later tasks."""

from __future__ import annotations

from fastapi import FastAPI

from custos.config import Settings
from custos.errors import install_error_handlers


def create_app(settings: Settings) -> FastAPI:
    app = FastAPI(title="Custos", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    install_error_handlers(app)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
