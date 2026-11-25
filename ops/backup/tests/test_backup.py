"""Chiffrement et vérification du dump sans rechargement intégral en mémoire."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pyzipper
import pytest

path = Path(__file__).resolve().parents[1] / "backup.py"
spec = importlib.util.spec_from_file_location("backup_under_test", path)
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


def _settings(monkeypatch, tmp_path):
    directory = tmp_path / "backups"
    monkeypatch.setattr(backup, "BACKUP_DIR", directory)
    monkeypatch.setattr(backup, "HEARTBEAT", directory / ".last-success")
    monkeypatch.setattr(backup, "password", lambda: b"synthetic-test-password-32-bytes-long")
    monkeypatch.setattr(backup, "pg_environment", lambda: {})
    return directory


def test_verification_en_flux_garde_integrite_et_pg_restore(monkeypatch, tmp_path):
    directory = _settings(monkeypatch, tmp_path)
    data = b"synthetic-pg-dump\x00" * 100000
    expected = hashlib.sha256(data).hexdigest()
    restored = []

    def run(command, **_kwargs):
        if command[0] == "pg_dump":
            Path(command[-1]).write_bytes(data)
        else:
            assert command[:2] == ["pg_restore", "--list"]
            restored.append(hashlib.sha256(Path(command[-1]).read_bytes()).hexdigest())
        return SimpleNamespace(returncode=0)

    def forbidden_read(*_args, **_kwargs):
        raise AssertionError("AESZipFile.read rechargerait tout le dump")

    monkeypatch.setattr(backup.subprocess, "run", run)
    monkeypatch.setattr(pyzipper.AESZipFile, "read", forbidden_read)
    backup.run_backup()
    assert restored == [expected]
    assert backup.HEARTBEAT.exists()
    [archive_path] = list(directory.glob("*.dump.zip"))
    with pyzipper.AESZipFile(archive_path) as archive:
        archive.setpassword(backup.password())
        assert archive.getinfo("sentimail-v3.dump").compress_type == pyzipper.ZIP_DEFLATED
        assert archive.testzip() is None
        with archive.open("sentimail-v3.dump") as stream:
            digest = hashlib.sha256()
            while chunk := stream.read(65536):
                digest.update(chunk)
        assert digest.hexdigest() == expected


def test_une_integrite_invalide_ne_publie_pas_de_sauvegarde(monkeypatch, tmp_path):
    directory = _settings(monkeypatch, tmp_path)
    restored = []

    def run(command, **_kwargs):
        if command[0] == "pg_dump":
            Path(command[-1]).write_bytes(b"synthetic dump")
        else:
            restored.append(command)

    monkeypatch.setattr(backup.subprocess, "run", run)
    monkeypatch.setattr(pyzipper.AESZipFile, "testzip", lambda _self: "corrupt.dump")
    with pytest.raises(RuntimeError, match="integrity check failed"):
        backup.run_backup()
    assert not restored
    assert not backup.HEARTBEAT.exists()
    assert not list(directory.glob("*.dump.zip"))
    assert not list(directory.glob("*.pending"))
