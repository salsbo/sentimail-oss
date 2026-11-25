"""Compare deux calculs purs avant toute acceptation, sans second envoi."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from contextvars import ContextVar
from functools import lru_cache
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

from sentimail_v3.judgment import dossier as dossier_core
from sentimail_v3.judgment import commit, fast_paths, prompt, response
from sentimail_v3.llm import LlmError
from sentimail_v3.judgment.events import _log
from sentimail_v3.supervision import core_rollout

ORACLE_SHA256 = "70a94f106b5462813c2742400a4ec90ff9969749e15bf6a35c11b72bddf2781f"
_legacy_run: ContextVar[Any] = ContextVar("sentimail_legacy_run", default=None)


class CoreComparisonError(RuntimeError):
    """Le nouveau calcul ne peut pas devenir contraignant sans comparaison."""


@lru_cache(maxsize=1)
def reference() -> ModuleType:
    """Charge la version figée, jamais une réexportation des fonctions nouvelles."""
    path = Path(__file__).resolve().parents[3] / "tests/reference/verdict_engine_b07a5ec.py"
    if hashlib.sha256(path.read_bytes()).hexdigest() != ORACLE_SHA256:
        raise CoreComparisonError("empreinte de référence incorrecte")
    spec = importlib.util.spec_from_file_location("sentimail_core_reference_b07a5ec", path)
    if spec is None or spec.loader is None:
        raise CoreComparisonError("référence indisponible")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, default=str).encode()).hexdigest()


def _attempt(function: Callable, *args: Any) -> dict[str, Any]:
    try:
        return {"status": "ok", "value": function(*copy.deepcopy(args))}
    except Exception as exc:
        return {"status": "error", "type": type(exc).__name__, "detail": str(exc)}


def compare_case(dossier: dict, deep: dict, settings: Any, response_text: str) -> dict[str, Any]:
    """Même entrée complète et même réponse enregistrée ; aucun appel réseau."""
    old = reference()
    values = []
    for prepare, make_prompt, parse, execute in (
        (old._prepare_for_judgment, old._prompt, old._parse_final_response, old._judgment_execution),
        (dossier_core._prepare_for_judgment, prompt._prompt, response._parse_final_response,
         response._judgment_execution),
    ):
        prepared = _attempt(prepare, dossier, deep, settings)
        value: dict[str, Any] = {"prepared": _hash(prepared)}
        if prepared["status"] == "ok":
            ready = prepared["value"]
            suppress = old._authenticated_suppression if prepare == old._prepare_for_judgment else response._authenticated_suppression
            value["policy_b"] = _attempt(suppress, ready)
            value["prompt"] = _hash(_attempt(make_prompt, ready))
            parsed = _attempt(parse, response_text, ready)
            value["parsed"] = _hash(parsed)
            if parsed["status"] == "ok":
                result, contradictions = parsed["value"]
                value["execution"] = _attempt(execute, result)
                value["contradictions"] = contradictions
        values.append(value)
    return {"legacy": values[0], "candidate": values[1],
            "agreement": _hash(values[0]) == _hash(values[1])}


async def compare_express(pool: Any, message_id: str) -> dict[str, Any]:
    """Le banc fournit un lecteur immuable : les deux voies OTP restent réelles."""
    values = []
    for api in (reference(), fast_paths):
        try:
            result = await api._express_judgment(pool, message_id)
            execute = reference()._judgment_execution if api is not fast_paths else response._judgment_execution
            values.append({"result": result, "execution": execute(result) if result else None})
        except Exception as exc:
            values.append({"error": type(exc).__name__, "detail": str(exc)})
    return {"legacy": values[0], "candidate": values[1],
            "agreement": _hash(values[0]) == _hash(values[1])}


async def compare_retry(attempts: int, transient: bool, accepted: bool = False) -> dict[str, Any]:
    """Vérifie les échéances et écritures prévues, sans toucher une vraie file."""
    values = []
    old = reference()
    original = getattr(old, "_unadapted_mark_error", old._mark_error)
    for mark in (original, commit._mark_error):
        class Ledger:
            def __init__(self):
                self.state = {"status": "complete" if accepted else "running", "completed": accepted,
                              "error_type": None, "error_detail": None, "retry_in_seconds": None}
                self.writes = []

            async def execute(self, query, *args):
                guarded = "status<>'complete'" in query and "v.is_binding" in query
                if accepted and guarded:
                    return "UPDATE 0"
                self.state.update(status="error", error_type=args[1], error_detail=args[2],
                                  completed=args[3], retry_in_seconds=args[4])
                self.writes.append(dict(self.state))
                return "UPDATE 1"

        ledger = Ledger()
        error = LlmError("délai total dépassé") if transient else ValueError("réponse synthétique invalide")
        try:
            plan = await mark(ledger, {"id": "benchmark", "attempts": attempts}, error)
            values.append({"plan": vars(plan), "state": ledger.state, "writes": ledger.writes})
        except Exception as exc:
            values.append({"error": type(exc).__name__, "detail": str(exc)})
    return {"legacy": values[0], "candidate": values[1],
            "agreement": _hash(values[0]) == _hash(values[1])}


def compare_final(dossier: dict, result: dict) -> dict[str, Any]:
    """Compare aussi les voies sans modèle, sur les faits effectivement acceptés."""
    old = reference()
    raw = result.get("raw_response")
    values = []
    for api in (old, response):
        value = {"validation": _attempt(api._validate_final_judgment, result, dossier),
                 "execution": _attempt(api._judgment_execution, result)}
        if result.get("delivery_decision") == "suppress":
            value["policy_b"] = _attempt(api._authenticated_suppression, dossier)
        elif isinstance(raw, dict) and "final_verdict" in raw:
            value["parsed"] = _attempt(api._parse_final_response, json.dumps(raw), dossier)
        values.append(value)
    return {"legacy": values[0], "candidate": values[1],
            "agreement": _hash(values[0]) == _hash(values[1])}


async def before_commit(pool: Any, run: Any, dossier: dict, result: dict) -> None:
    """En ombre l'ancien reste seul juge ; en canari une divergence arrête l'acceptation."""
    # Les scripts antérieurs et leurs contrats n'ont pas de génération. Les
    # vrais claims, eux, la relisent depuis la capture durable.
    generation = run.get("engine_generation")
    if generation is None:
        return
    try:
        mode = await pool.fetchval("SELECT mode FROM core_rollout_config WHERE singleton")
        if generation == "legacy" and mode == "legacy":
            return
        if generation == core_rollout.GENERATION and mode == "active":
            return
        compared = compare_final(dossier, result)
        stored = await core_rollout.record_comparison(
            pool, message_id=str(run["message_id"]), dossier=dossier,
            proposed_response=result.get("raw_response", result),
            legacy=compared["legacy"], candidate=compared["candidate"], source="shadow",
        )
        if not stored or not compared["agreement"]:
            raise CoreComparisonError("comparaison absente ou divergente")
    except Exception as exc:
        _log("core.comparison_failed", run_id=run["id"], error_type=type(exc).__name__)
        if generation == core_rollout.GENERATION:
            raise CoreComparisonError("comparaison avant acceptation impossible") from exc


async def before_model(pool: Any, run: Any, dossier: dict, deep: dict, settings: Any) -> None:
    """Compare règles complètes, compaction et prompt sur le même dossier réel."""
    generation = run.get("engine_generation")
    if generation is None:
        return
    try:
        mode = await pool.fetchval("SELECT mode FROM core_rollout_config WHERE singleton")
        if generation == "legacy" and mode == "legacy":
            return
        if generation == core_rollout.GENERATION and mode == "active":
            return
        values = []
        for prepare, make_prompt in (
            (reference()._prepare_for_judgment, reference()._prompt),
            (dossier_core._prepare_for_judgment, prompt._prompt),
        ):
            prepared = _attempt(prepare, dossier, deep, settings)
            value = {"prepared": _hash(prepared)}
            if prepared["status"] == "ok":
                value["prompt"] = _hash(_attempt(make_prompt, prepared["value"]))
            values.append(value)
        stored = await core_rollout.record_comparison(
            pool, message_id=str(run["message_id"]),
            dossier={"stage": "before_model", "dossier": dossier, "deep": deep,
                     "confidence": settings.auto_delivery_confidence},
            proposed_response={"stage": "before_model"},
            legacy=values[0], candidate=values[1], source="shadow",
        )
        if not stored or not stored["agreement"]:
            raise CoreComparisonError("préparation absente ou divergente")
    except Exception as exc:
        _log("core.preparation_comparison_failed", run_id=run["id"], error_type=type(exc).__name__)
        if generation == core_rollout.GENERATION:
            raise CoreComparisonError("comparaison avant modèle impossible") from exc


async def run_legacy(pool: Any, client: Any, settings: Any, conversations: Any, run: Any) -> bool:
    """Les dossiers déjà ouverts terminent sur leur version, sous le claim commun."""
    old = reference()
    if not getattr(old, "_comparison_installed", False):
        persist = old._complete
        build = old._build_dossier

        async def complete(*args: Any, **kwargs: Any):
            await before_commit(args[0], args[1], args[2], args[3])
            return await persist(*args, **kwargs)

        async def build_dossier(*args: Any, **kwargs: Any):
            dossier = await build(*args, **kwargs)
            current = _legacy_run.get()
            if current is not None:
                await before_model(args[0], current, dossier, args[2], kwargs["settings"])
            return dossier

        old._complete = complete
        old._build_dossier = build_dossier
        # Le moteur figé conserve ses décisions ; cette frontière de reprise
        # applique seulement l'invariant qui interdit de rouvrir un accepté.
        old._unadapted_mark_error = old._mark_error
        old._mark_error = commit._mark_error
        old._comparison_installed = True
    token = _legacy_run.set(run)
    try:
        return await old._process_run(pool, client, settings, conversations, run)
    finally:
        _legacy_run.reset(token)
