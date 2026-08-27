from __future__ import annotations

import sys
import time
from pathlib import Path


def heartbeat_path(component: str) -> Path:
    return Path(f"/tmp/sentimail-v3-{component}.heartbeat")


def status_path(component: str) -> Path:
    return Path(f"/tmp/sentimail-v3-{component}.status")


def pulse(component: str) -> None:
    heartbeat_path(component).touch()


def set_status(component: str, status: str) -> None:
    status_path(component).write_text(status, encoding="utf-8")


def healthy(component: str, maximum_age_seconds: int) -> bool:
    path = heartbeat_path(component)
    if not path.exists() or time.time() - path.stat().st_mtime > maximum_age_seconds:
        return False
    state = status_path(component)
    return not state.exists() or state.read_text(encoding="utf-8").strip() == "ok"


def main() -> None:
    if len(sys.argv) != 3 or not healthy(sys.argv[1], int(sys.argv[2])):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
