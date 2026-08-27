from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyzipper

BACKUP_DIR = Path("/backups")
HEARTBEAT = BACKUP_DIR / ".last-success"


def log(event: str, **fields: object) -> None:
    print(
        json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": event,
                **fields,
            },
            ensure_ascii=False,
        ),
        flush=True,
    )


def password() -> bytes:
    path = Path(os.environ["BACKUP_PASSWORD_FILE"])
    value = path.read_text(encoding="utf-8").strip().encode()
    if len(value) < 32:
        raise RuntimeError("backup password must contain at least 32 characters")
    return value


def pg_environment() -> dict[str, str]:
    password = Path(os.environ["DATABASE_PASSWORD_FILE"]).read_text(
        encoding="utf-8"
    ).strip()
    if not password:
        raise RuntimeError("database password is empty")
    return {
        **os.environ,
        "PGPASSWORD": password,
        "PGHOST": os.environ.get("PGHOST", "db"),
        "PGPORT": os.environ.get("PGPORT", "5432"),
        "PGDATABASE": os.environ.get("PGDATABASE", "sentimail_v3"),
        "PGUSER": os.environ.get("PGUSER", "sentimail_v3"),
    }


def run_backup() -> None:
    BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    final_path = BACKUP_DIR / f"sentimail-v3-{now:%Y%m%dT%H%M%SZ}.dump.zip"
    pending_path = BACKUP_DIR / f".{final_path.name}.pending"
    try:
        with tempfile.TemporaryDirectory(dir=BACKUP_DIR) as temporary_directory:
            dump_path = Path(temporary_directory) / "sentimail-v3.dump"
            subprocess.run(
                ["pg_dump", "--format=custom", "--no-owner", "--no-acl", "--file", str(dump_path)],
                env=pg_environment(),
                check=True,
                timeout=1800,
            )
            with pyzipper.AESZipFile(
                pending_path,
                "w",
                compression=pyzipper.ZIP_DEFLATED,
                encryption=pyzipper.WZ_AES,
            ) as archive:
                archive.setpassword(password())
                archive.setencryption(pyzipper.WZ_AES, nbits=256)
                archive.write(dump_path, arcname="sentimail-v3.dump")
            os.chmod(pending_path, 0o600)
            verify_path = Path(temporary_directory) / "verify.dump"
            with pyzipper.AESZipFile(pending_path) as archive:
                archive.setpassword(password())
                if archive.testzip() is not None:
                    raise RuntimeError("encrypted backup integrity check failed")
                verify_path.write_bytes(archive.read("sentimail-v3.dump"))
            subprocess.run(
                ["pg_restore", "--list", str(verify_path)],
                check=True,
                stdout=subprocess.DEVNULL,
                timeout=300,
            )
        pending_path.replace(final_path)
    finally:
        if pending_path.exists():
            pending_path.unlink()
    HEARTBEAT.touch(mode=0o600)
    cutoff = now - timedelta(days=int(os.environ.get("BACKUP_RETENTION_DAYS", "14")))
    for old_path in BACKUP_DIR.glob("sentimail-v3-*.dump.zip"):
        if old_path != final_path and datetime.fromtimestamp(
            old_path.stat().st_mtime, timezone.utc
        ) < cutoff:
            old_path.unlink()
    log("backup.complete", filename=final_path.name, size_bytes=final_path.stat().st_size)


def check_health(maximum_age_seconds: int) -> None:
    if not HEARTBEAT.exists() or time.time() - HEARTBEAT.stat().st_mtime > maximum_age_seconds:
        raise SystemExit(1)


def main() -> None:
    if len(sys.argv) == 3 and sys.argv[1] == "--check":
        check_health(int(sys.argv[2]))
        return
    interval = int(os.environ.get("BACKUP_INTERVAL_SECONDS", "86400"))
    while True:
        try:
            run_backup()
        except Exception as exc:
            log("backup.error", error=type(exc).__name__, detail=str(exc)[:300])
        time.sleep(interval)


if __name__ == "__main__":
    main()
