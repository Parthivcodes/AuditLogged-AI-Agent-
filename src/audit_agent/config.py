"""Configuration settings loaded from environment variables and optional .env file.

Uses only Python standard library (no external python-dotenv dependency).
"""

import os
from dataclasses import dataclass
from pathlib import Path


def load_env_file(path: str | Path = ".env", override: bool = False) -> dict[str, str]:
    """Parse a simple .env file and set environment variables.

    Ignores blank lines and comments starting with '#'. Strips surrounding quotes.
    """
    env_path = Path(path)
    loaded: dict[str, str] = {}
    if not env_path.is_file():
        return loaded

    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and (
            (val.startswith('"') and val.endswith('"'))
            or (val.startswith("'") and val.endswith("'"))
        ):
            val = val[1:-1]
        loaded[key] = val
        if override or key not in os.environ:
            os.environ[key] = val

    return loaded


@dataclass(frozen=True)
class Settings:
    """Application settings for Audit Agent."""

    anthropic_api_key: str | None
    model: str
    db_path: Path
    max_steps: int
    data_dir: Path
    output_dir: Path
    api_host: str = "127.0.0.1"
    api_port: int = 8000

    @classmethod
    def from_env(cls, env_file: str | Path | None = ".env") -> "Settings":
        if env_file:
            load_env_file(env_file)

        return cls(
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY") or None,
            model=os.environ.get("AUDIT_AGENT_MODEL", "claude-sonnet-4-5"),
            db_path=Path(os.environ.get("AUDIT_DB_PATH", "audit.db")),
            max_steps=int(os.environ.get("AUDIT_MAX_STEPS", "10")),
            data_dir=Path(os.environ.get("AUDIT_DATA_DIR", "data")),
            output_dir=Path(os.environ.get("AUDIT_OUTPUT_DIR", "output")),
            api_host=os.environ.get("AUDIT_API_HOST", "127.0.0.1"),
            api_port=int(os.environ.get("AUDIT_API_PORT", "8000")),
        )


def get_settings() -> Settings:
    """Return default settings loaded from environment and default .env."""
    return Settings.from_env()
