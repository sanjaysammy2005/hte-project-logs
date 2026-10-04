"""Capture the test conditions recorded with every experiment run (EXPERIMENTS §2)."""

import os
import platform
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

_PACKAGES = ["fastapi", "sqlalchemy", "psycopg", "pydantic", "alembic"]


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _proc_value(path: str, key: str) -> str | None:
    content = _read(path) or ""
    for line in content.splitlines():
        if line.startswith(key):
            return line.split(":", 1)[1].strip()
    return None


def capture_environment(db: Session, git_commit: str | None = None) -> dict[str, Any]:
    versions = {}
    for name in _PACKAGES:
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:  # pragma: no cover
            versions[name] = None
    return {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "cpu_model": _proc_value("/proc/cpuinfo", "model name"),
        "cpu_count": os.cpu_count(),
        "memory_total": _proc_value("/proc/meminfo", "MemTotal"),
        "container_memory_limit": _read("/sys/fs/cgroup/memory.max"),
        "container_cpu_limit": _read("/sys/fs/cgroup/cpu.max"),
        "postgresql": db.scalar(text("SELECT version()")),
        "packages": versions,
        "git_commit": git_commit or os.environ.get("TRACELOCK_GIT_COMMIT") or "unknown",
        "timer": "time.perf_counter (monotonic)",
    }
