"""API réelle et processus jetables : santé, délai, capacité et arrêt OCR."""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
import types

import fastapi  # noqa: F401 - les tests HTTP utilisent la vraie application
import httpx
import pytest


def _load_server():
    # Les bibliothèques système sont absentes du Mac. Le protocole HTTP et la
    # gestion de processus restent réels ; seul YARA est simulé ici.
    yara = types.ModuleType("yara")
    yara.Rules = object
    yara.Error = RuntimeError
    yara.compile = lambda **_kwargs: types.SimpleNamespace(match=lambda **_kwargs: [])
    sys.modules.setdefault("yara", yara)
    path = Path(__file__).resolve().parents[1] / "server.py"
    spec = importlib.util.spec_from_file_location("file_process_api", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


server = _load_server()
PAYLOAD = {"filename": "plain.txt", "content_b64": base64.b64encode(b"texte sans charge").decode()}


def _client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app), base_url="http://sandbox.test")


async def _wait_file(path: Path) -> None:
    async with asyncio.timeout(5):
        while not path.exists():
            await asyncio.sleep(0.01)


def _alive(pid: int) -> bool:
    # Un zombie est terminé ; sous Linux il peut attendre le reaper du conteneur.
    stat = Path(f"/proc/{pid}/stat")
    if stat.exists() and stat.read_text().split()[2] == "Z":
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


@pytest.mark.asyncio
async def test_sante_responsive_et_timeout_tue_parent_et_descendant(monkeypatch, tmp_path):
    pids = tmp_path / "pids.json"
    code = (
        "import json,os,subprocess,sys,time; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
        f"open({str(pids)!r},'w').write(json.dumps([os.getpid(),child.pid])); "
        "time.sleep(60)"
    )
    monkeypatch.setattr(server, "_worker_command", lambda: (sys.executable, "-c", code))
    monkeypatch.setattr(server, "FILE_ANALYSIS_TIMEOUT_SECONDS", 1.0)
    monkeypatch.setattr(server, "_analysis_slots", asyncio.Semaphore(1))
    async with _client() as client:
        request = asyncio.create_task(client.post("/analyze", json=PAYLOAD))
        await _wait_file(pids)
        started = time.monotonic()
        response = await client.get("/health")
        assert response.json() == {"status": "ok"}
        assert time.monotonic() - started < 0.5
        failure = await request
    assert failure.status_code == 504
    assert failure.json()["detail"] == "analysis_deadline_exceeded"
    parent, descendant = json.loads(pids.read_text())
    async with asyncio.timeout(2):
        while _alive(parent) or _alive(descendant):
            await asyncio.sleep(0.01)


@pytest.mark.asyncio
async def test_annulation_ne_laisse_pas_un_processus_analyser(monkeypatch, tmp_path):
    marker = tmp_path / "pid"
    code = f"import os,time; open({str(marker)!r},'w').write(str(os.getpid())); time.sleep(60)"
    monkeypatch.setattr(server, "_worker_command", lambda: (sys.executable, "-c", code))
    monkeypatch.setattr(server, "_analysis_slots", asyncio.Semaphore(1))
    async with _client() as client:
        task = asyncio.create_task(client.post("/analyze", json=PAYLOAD))
        await _wait_file(marker)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert not _alive(int(marker.read_text()))


@pytest.mark.asyncio
async def test_attente_de_capacite_compte_dans_deadline_sans_lancer_de_processus(monkeypatch):
    monkeypatch.setattr(server, "_analysis_slots", asyncio.Semaphore(0))
    monkeypatch.setattr(server, "FILE_ANALYSIS_TIMEOUT_SECONDS", 0.05)
    def forbidden():
        raise AssertionError("aucun processus ne doit démarrer sans capacité")
    monkeypatch.setattr(server, "_worker_command", forbidden)
    async with _client() as client:
        response = await client.post("/analyze", json=PAYLOAD)
    assert response.status_code == 504


@pytest.mark.asyncio
async def test_deux_requetes_ne_depassent_pas_la_capacite(monkeypatch, tmp_path):
    events = tmp_path / "events.jsonl"
    code = f"""
import json,os,sys,time
request=json.load(sys.stdin)
fd=os.open({str(events)!r},os.O_CREAT|os.O_APPEND|os.O_WRONLY,0o600)
os.write(fd,(json.dumps(['start',os.getpid()])+'\\n').encode())
time.sleep(0.15)
os.write(fd,(json.dumps(['end',os.getpid()])+'\\n').encode())
os.close(fd)
print(json.dumps({{'result':{{'filename':request['filename'],'analysis_incomplete':False}}}}))
"""
    monkeypatch.setattr(server, "_worker_command", lambda: (sys.executable, "-c", code))
    monkeypatch.setattr(server, "_analysis_slots", asyncio.Semaphore(1))
    async with _client() as client:
        results = await asyncio.gather(*(client.post("/analyze", json=PAYLOAD) for _ in range(2)))
    assert all(r.status_code == 200 for r in results)
    actual = [json.loads(line) for line in events.read_text().splitlines()]
    assert [kind for kind, _pid in actual] == ["start", "end", "start", "end"]
    assert actual[0][1] != actual[2][1]


@pytest.mark.asyncio
async def test_protocole_reel_conserve_resultat_et_erreurs_400_413(monkeypatch):
    source = str(Path(server.__file__).resolve())
    bootstrap = f"""
import runpy,sys,types
yara=types.ModuleType('yara')
yara.Rules=object
yara.Error=RuntimeError
yara.compile=lambda **kw: types.SimpleNamespace(match=lambda **kw: [])
sys.modules['yara']=yara
sys.path.insert(0,{str(Path(source).parent)!r})
sys.argv=[{source!r},'--analyze-worker']
runpy.run_path({source!r},run_name='__main__')
"""
    monkeypatch.setattr(server, "_worker_command", lambda: (sys.executable, "-c", bootstrap))
    monkeypatch.setattr(server, "_analysis_slots", asyncio.Semaphore(1))
    async with _client() as client:
        response = await client.post("/analyze", json=PAYLOAD)
        assert response.status_code == 200
        result = response.json()
        assert result["filename"] == "plain.txt"
        assert result["analysis_incomplete"] is False
        assert result["size_bytes"] == len(b"texte sans charge")
        invalid = await client.post("/analyze", json={**PAYLOAD, "content_b64": "invalid!"})
        assert invalid.status_code == 400
        oversized = base64.b64encode(b"x" * (server.MAX_BYTES+1)).decode()
        too_big = await client.post("/analyze", json={**PAYLOAD, "content_b64": oversized})
        assert too_big.status_code == 413
