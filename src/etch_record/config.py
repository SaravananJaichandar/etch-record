"""Config resolution: env vars first, no on-disk config file for MVP.

Missing env vars raise a `ConfigError` the CLI catches and turns into
a friendly stderr message + exit code 1.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Config:
    project_id: str
    app_token: str
    base_url: str


def load() -> Config:
    project_id = os.environ.get("ETCH_PROJECT_ID", "").strip()
    app_token = os.environ.get("ETCH_APP_TOKEN", "").strip()
    base_url = os.environ.get("ETCH_BASE_URL", "https://etch.systems").rstrip("/")

    missing = []
    if not project_id:
        missing.append("ETCH_PROJECT_ID")
    if not app_token:
        missing.append("ETCH_APP_TOKEN")
    if missing:
        raise ConfigError(
            "Missing required environment variable(s): "
            + ", ".join(missing)
            + "\nSet in your shell rc (~/.zshrc):\n"
            + "  export ETCH_PROJECT_ID=your_project_id\n"
            + "  export ETCH_APP_TOKEN=wm_your_app_token\n"
        )

    return Config(
        project_id=project_id,
        app_token=app_token,
        base_url=base_url,
    )
