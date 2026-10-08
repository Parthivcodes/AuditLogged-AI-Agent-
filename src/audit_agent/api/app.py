"""FastAPI application factory for the read-only audit log server."""

from pathlib import Path

from fastapi import FastAPI

from audit_agent.api.routes import router


def create_app(db_path: Path | str | None = None) -> FastAPI:
    """Factory to create a read-only audit API application instance."""
    app = FastAPI(
        title="Audit Agent Read-Only API",
        description="Immutable, tamper-evident audit log query and verification service.",
        version="0.1.0",
    )

    if db_path is not None:
        app.state.db_path = Path(db_path)

    app.include_router(router)
    return app


app = create_app()
