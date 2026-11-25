"""Compare le cœur sur des cas fictifs ou des raisonnements conservés.

Le rejeu des dossiers conservés s'exécute sur le serveur Linux qui les détient.
Les sorties et les tables de comparaison ne reçoivent que des comptes et des
empreintes, jamais les textes utilisés pour le calcul.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import copy
import hashlib
import json
import logging
import re
import sys
from collections import Counter
from collections.abc import AsyncIterable, Iterable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from sentimail_v3.supervision import core_rollout

_SCHEMA = "sentinel-verdict-dossier-v3-trial-roles"
_SAFE_SETTINGS = {"auto_delivery_confidence": 0.9, "decision_mode": True}


def _object(value: Any) -> dict:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


def _clue(code: str, article: str, direction: str = "adverse", **fields: Any) -> dict:
    return {"id": 1, "clue_code": code, "article_code": article,
            "direction": direction, "strength": 60, "confidence": 1.0,
            "statement": "Constat fictif pour vérifier le contrat existant.",
            "facts": {}, **fields}


def _response(classification="legitimate", decision="deliver", confidence=0.98, **fields) -> str:
    return json.dumps({"unfavorable": {"clue_codes": [], "arguments": []},
        "favorable": {"clue_codes": [], "arguments": []},
        "final_verdict": {"classification": classification, "delivery_decision": decision,
            "confidence": confidence, "rationale": "Motivation fictive fondée sur le dossier.",
            "doubt": classification != "legitimate", "doubt_reasons": [], **fields}},
        ensure_ascii=False, sort_keys=True)


def _codes(article: dict) -> list[str]:
    parameters = _object(article.get("parameters"))
    values = [*(article.get("clue_codes") or []), parameters.get("clue_code")]
    return sorted({value for value in values if isinstance(value, str) and value})


def benchmark_cases(active_articles: list[dict]) -> list[dict]:
    """Fabrique les entrées, sans nouveau critère ni dépendance à un courrier."""
    articles = [copy.deepcopy(dict(article)) for article in active_articles]
    material = next((a for a in articles
        if _object(a.get("parameters")).get("delivery_barrier") == "material_danger" and _codes(a)), None)
    if material is None:
        raise ValueError("le corpus actif ne décrit aucun indice de barrière matérielle")
    material_code = _codes(material)[0]
    danger = _clue(material_code, material["article_code"], strength=95)
    auth = _clue("AUTH_DMARC_PASS", "AUTH-001", "favorable")
    fail = _clue("AUTH_DMARC_FAIL", "AUTH-002")
    conflict = _clue("CORRELATION_UNVERIFIED_IDENTITY_DESTINATION", "CORR-019")
    blocked = _clue("ATTACHMENT_ANALYSIS_BLOCKED", "ATT-019", "neutral", strength=0)
    cases: list[dict] = []

    def add(identifier: str, coverage=(), *, clues=(), deep=None, message=None,
            response_text=None, classification="legitimate", decision="deliver", confidence=0.98,
            code_articles=None, **extra):
        cited = {clue["article_code"] for clue in clues}
        dossier = {"schema": _SCHEMA,
            "privacy": {"raw_eml_included": False, "html_included": False},
            "message": {"investigation_status": "complete", "body_text": "Texte fictif.", **(message or {})},
            "clues": copy.deepcopy(list(clues)),
            "code_articles": copy.deepcopy([a for a in articles if a["article_code"] in cited]
                                           if code_articles is None else code_articles),
            "code_index": [{"article_code": a["article_code"], "title": a.get("title", "")} for a in articles],
            "entities": [], "selected_headers": [], **extra}
        cases.append({"id": identifier, "coverage": list(coverage), "dossier": dossier,
            "deep": {"complete": True, "attachments_complete": True, **(deep or {})},
            "settings": dict(_SAFE_SETTINGS),
            "response_text": response_text if response_text is not None else _response(classification, decision, confidence)})

    add("legitimate", ["legitimate"], clues=[auth])
    add("spam", ["spam"], clues=[fail], classification="spam", decision="junk")
    add("suspect", ["suspect"], clues=[fail], classification="suspect", decision="ask_user")
    add("dangerous", ["dangerous"], clues=[danger], classification="dangerous", decision="junk")
    add("undetermined", ["undetermined"], clues=[blocked], deep={"attachments_complete": False},
        classification="undetermined", decision="ask_user")
    add("material_danger", ["material_danger"], clues=[danger])
    add("authenticated_hold", ["authenticated_hold"], clues=[auth], deep={"history": {"persistent_hold": True}})
    add("static_incomplete", ["static_incomplete"], clues=[fail], message={"investigation_status": "partial"})
    add("deep_incomplete", ["deep_incomplete"], clues=[fail], deep={"complete": False})
    add("identity_destination_conflict", ["identity_destination_conflict"], clues=[conflict])
    add("otp", ["otp"], clues=[auth,
        _clue("CONTENT_EXPECTED_ONE_TIME_CODE_INPUT", "CONTENT-010", "neutral", strength=0)],
        message={"body_text": "Votre code de connexion est 482913. Il expire dans cinq minutes."},
        express_inputs={"sender_apex": "example.org", "destinations": ["example.org"],
                        "organisations": {}, "established": True, "code_visible": True})
    add("policy_b", ["policy_b"], clues=[auth], deep={"history": {"persistent_hold": True}},
        schema="sentimail-authenticated-sender-policy-v1",
        analysis_not_requested_reason="authenticated_sender_policy",
        classification="undetermined", decision="ask_user")
    add("real_doubt", ["real_doubt"], clues=[blocked], deep={"attachments_complete": False,
        "history": {"ask_only_on_real_doubt": True}}, classification="suspect", decision="ask_user")
    add("retry", ["retry"], clues=[auth], classification="legitimate", decision="ask_user",
        retry_inputs={"attempts": 1, "transient": False})
    add("invalid_response", ["invalid_response"], clues=[auth], response_text="Réponse sans objet JSON.")
    add("invalid_reference", ["invalid_reference"], clues=[auth],
        response_text=_response(rationale="AUTH_UNAVAILABLE_999 serait une preuve absente."))
    add("low_confidence", ["low_confidence"], clues=[auth], confidence=0.5)
    add("without_real_doubt", clues=[auth], deep={"complete": False,
        "history": {"ask_only_on_real_doubt": True}}, classification="suspect", decision="ask_user", confidence=0.5)
    add("parameters_json_text", clues=[danger], code_articles=[
        {**material, "parameters": json.dumps(_object(material.get("parameters")))}])

    # Chaque article passe au moins dans la lecture du dossier. Un code d'indice
    # absent du corpus et des constats conservés n'est jamais fabriqué ici.
    for article in articles:
        clues = [_clue(code, article["article_code"], article.get("default_direction", "neutral"))
                 for code in _codes(article)]
        add("article_"+article["article_code"], ["article:"+article["article_code"]],
            clues=clues, code_articles=[article], response_text=_response("suspect", "ask_user",
                rationale="Exercice fictif de l'article "+article["article_code"]+"."))

    many = [_clue("AUTH_DMARC_PASS", "AUTH-001", "favorable", id=i+1,
                  statement="Description fictive. "*300, facts={"ordinal": i}) for i in range(65)]
    many.append({**danger, "id": 66})
    add("saturation_material_beyond_40", clues=many,
        message={"body_text": "Contenu fictif. "*15000},
        reference_knowledge={"passages": [{"nature": "adversarial", "text": "Norme fictive. "*1000}]},
        entities=[{"entity_type": "url", "value_normalized": "https://example.test/"+"a"*2000} for _ in range(75)])
    # La transformation de profil porte sur les indices complets même lorsque
    # l'affichage destiné au juge est réduit.
    add("material_spam_compaction", clues=[fail,
        _clue("HISTORY_FIRST_OBSERVATION", "HIST-002", "neutral", strength=0),
        _clue("NATURE_UNSOLICITED_BULK_FIRST_CONTACT", "NATURE-002"), *many],
        material_spam_profile=True, classification="suspect", decision="ask_user")
    add("retry_transient", clues=[auth], retry_inputs={"attempts": 3, "transient": True})
    add("retry_exhausted", clues=[auth], retry_inputs={"attempts": 10, "transient": False})
    return cases


def _envelope(case: dict) -> dict:
    if case.get("comparison_scope") == "stored_validation_execution":
        return {"dossier": case["dossier"], "comparison_scope": case["comparison_scope"]}
    return {"dossier": case["dossier"], "deep": case["deep"],
            "settings": {key: case.get("settings", {}).get(key, default)
                         for key, default in _SAFE_SETTINGS.items()}}


async def _iterate(cases: Iterable[dict] | AsyncIterable[dict]):
    if isinstance(cases, AsyncIterable):
        async for case in cases:
            yield case
    else:
        for case in cases:
            yield case


async def compare_cases(
    pool: Any, cases: Iterable[dict] | AsyncIterable[dict], *, publish: bool = True,
) -> dict:
    from sentimail_v3.judgment.core_compare import (
        ORACLE_SHA256, compare_case, compare_express, compare_final, compare_retry,
    )

    counts: Counter = Counter()
    scopes: Counter = Counter()
    exclusions: Counter = Counter()
    coverage: set[str] = set()
    pairs: dict[tuple, list[dict]] = {}
    required = set(core_rollout.REQUIRED_COVERAGE)
    case_count = 0
    digest = hashlib.sha256(b"[")
    async for case in _iterate(cases):
        envelope = _envelope(case)
        if case_count:
            digest.update(b",")
        digest.update(json.dumps({"inputs": envelope, "response": case["response_text"]},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode())
        case_count += 1
        scopes[case.get("comparison_scope", "full_fixture")] += 1
        if case.get("exclusion_reason"):
            exclusions[case["exclusion_reason"]] += 1
        required.update("article:"+article["article_code"]
                        for article in case["dossier"].get("code_index", []))
        try:
            if case.get("exclusion_reason"):
                compared = {"legacy": {}, "candidate": {}, "agreement": False}
            elif case.get("comparison_scope") == "stored_validation_execution":
                compared = compare_final(case["dossier"], case["stored_result"])
            else:
                compared = compare_case(case["dossier"], case["deep"], SimpleNamespace(**envelope["settings"]), case["response_text"])
            if "otp" in case.get("coverage", ()):
                express = await compare_express(_ExpressPool(case), "00000000-0000-0000-0000-000000000001")
                if any(not express[side].get("result") for side in ("legacy", "candidate")):
                    raise ValueError("la fixture OTP doit ouvrir les deux voies rapides")
                for side in ("legacy", "candidate"):
                    compared[side]["express"] = express[side]
            retry = case["dossier"].get("retry_inputs")
            if retry:
                planned = await compare_retry(**retry)
                if any("plan" not in planned[side] for side in ("legacy", "candidate")):
                    raise ValueError("la fixture de reprise doit produire deux plans")
                for side in ("legacy", "candidate"):
                    compared[side]["retry"] = planned[side]
        except Exception as exc:
            compared = {"legacy": {}, "candidate": {}, "agreement": False, "error_type": type(exc).__name__}
        stored = await core_rollout.record_comparison(pool, dossier=envelope,
            proposed_response=case["response_text"], legacy=compared["legacy"], candidate=compared["candidate"],
            source="offline", message_id=case.get("message_id"), coverage=case.get("coverage", ()),
            error_type=compared.get("error_type"), exclusion_reason=case.get("exclusion_reason"))
        status = stored["status"] if stored else "record_error"
        counts[status] += 1
        if status == "complete":
            counts["agreements" if stored["agreement"] else "mismatches"] += 1
        key = (core_rollout._hash(envelope), core_rollout._hash(case["response_text"]))
        pair = pairs.setdefault(key, [{"status": "complete", "agreement": True, "coverage": set()}])[0]
        if status != "complete":
            pair["status"] = status
        pair["agreement"] = pair["agreement"] and bool(stored and stored["agreement"])
        pair["coverage"].update(case.get("coverage", []))
    digest.update(b"]")
    coverage.update(core_rollout._independent_coverage(pairs, required=required))
    report = {"cases": case_count, "distinct_pairs": len(pairs), "counts": dict(counts),
        "scopes": dict(scopes), "exclusions": dict(exclusions),
        "coverage": sorted(coverage), "oracle_sha256": ORACLE_SHA256,
        "case_set_sha256": digest.hexdigest()}
    if publish and required <= coverage and not any(
        counts[key] for key in ("error", "record_error", "mismatches")
    ):
        qualified = await core_rollout.publish_qualification(pool, case_set_sha256=report["case_set_sha256"])
        report["qualification"] = {key: qualified[key] for key in
            ("status", "cases", "errors", "mismatches", "excluded", "coverage", "comparison_set_sha256")}
    return report


def stored_case(row: dict) -> dict:
    """Exige les règles conservées sans reconstruire le dossier qui les a produites."""
    dossier, response = _object(row.get("input_snapshot")), _object(row.get("response"))
    deep = _object(dossier.get("deep_analysis"))
    result = _object(response.get("verdict"))
    rules = _object(dossier.get("judgment_rules"))
    reason = None
    needed_rules = {"confidence_required", "deep_execution_complete", "static_investigation_complete",
                    "material_danger_evidence", "authenticated_sender_policy"}
    if (not isinstance(dossier.get("clues"), list) or not needed_rules <= rules.keys()
        or not (rules.get("verdict_is_final") or rules.get("judge_is_final"))):
        reason = "IncompleteStoredDossier"
    elif (result.get("classification") not in {"legitimate", "spam", "suspect", "dangerous", "undetermined"}
        or result.get("delivery_decision") not in {"deliver", "junk", "ask_user", "suppress"}
        or not isinstance(result.get("confidence"), (int, float))):
        reason = "MissingStoredResponse"
    return {"id": str(row["id"]), "message_id": str(row["message_id"]), "dossier": dossier,
        "deep": deep, "settings": {}, "response_text": json.dumps(result, ensure_ascii=False),
        "comparison_scope": "stored_validation_execution", "stored_result": result,
        "coverage": [], **({"exclusion_reason": reason} if reason else {})}


class _ExpressPool:
    """Lecteur en mémoire des seuls constats nécessaires à la voie OTP réelle."""

    def __init__(self, case: dict):
        self.dossier = case["dossier"]
        self.inputs = self.dossier["express_inputs"]

    async def fetch(self, query: str, *args):
        return self.dossier["clues"] if "FROM clues" in query else []

    async def fetchrow(self, query: str, *args):
        if "body_text" in query:
            return {"subject": "", "body_html": "", "body_text": self.dossier["message"]["body_text"]}
        return None

    async def fetchval(self, query: str, *args):
        if "hook_runs" in query:
            return {"actionable_apexes": self.inputs["destinations"]}
        if "delivery_status='delivered'" in query:
            return self.inputs["established"]
        if "split_part(from_header" in query:
            return self.inputs["sender_apex"]
        return None


def _static_associations() -> dict[str, set[str]]:
    """Relit les associations littérales déjà écrites dans le code d'observation."""
    associations: dict[str, set[str]] = {}
    package = Path(__file__).resolve().parents[1]
    article_pattern = re.compile(r"[A-Z][A-Z0-9]*-\d{3}")
    clue_pattern = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")

    def collect(values):
        strings = [node.value for node in values if isinstance(node, ast.Constant) and isinstance(node.value, str)]
        articles = [value for value in strings if article_pattern.fullmatch(value)]
        clues = [value for value in strings if clue_pattern.fullmatch(value)]
        if len(articles) == len(clues) == 1:
            associations.setdefault(articles[0], set()).add(clues[0])

    for directory in ("code", "observation"):
        for path in sorted((package/directory).rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, (ast.Tuple, ast.List)):
                    collect(node.elts)
                elif isinstance(node, ast.Call):
                    collect([*node.args, *(keyword.value for keyword in node.keywords)])
                elif isinstance(node, ast.Dict):
                    for key, value in zip(node.keys, node.values):
                        if isinstance(value, (ast.Tuple, ast.List)):
                            collect([key, *value.elts])
    return associations


async def _active_articles(pool: Any) -> list[dict]:
    rows = await pool.fetch("""SELECT a.article_code,a.title,a.principle,a.default_direction,
      a.default_strength,a.severity,a.limitations,a.parameters,
      ARRAY(SELECT DISTINCT c.clue_code FROM clues c WHERE c.article_id=a.id ORDER BY c.clue_code) AS clue_codes
      FROM code_articles a JOIN code_editions e ON e.id=a.edition_id
      WHERE a.enabled AND e.status='active' ORDER BY a.article_code""")
    articles = [dict(row) for row in rows]
    declared = _static_associations()
    for article in articles:
        article["clue_codes"] = sorted(set(_codes(article)) | declared.get(article["article_code"], set()))
    return articles


async def _run(args: argparse.Namespace) -> dict:
    import asyncpg
    from sentimail_v3.config import load_settings

    if args.stored and sys.platform != "linux":
        raise ValueError("le rejeu des dossiers conservés exige le serveur Linux")
    settings = load_settings()
    async with asyncpg.create_pool(settings.database_url, min_size=1, max_size=2) as pool:
        if args.fixtures:
            articles = await _active_articles(pool)
            report = await compare_cases(pool, benchmark_cases(articles))
            report["active_articles"] = len(articles)
            report["articles_with_known_clue_codes"] = sum(bool(_codes(article)) for article in articles)
            report["known_clue_codes"] = len({code for article in articles for code in _codes(article)})
            report["articles_without_known_clue_codes"] = len(articles)-report["articles_with_known_clue_codes"]
            return report
        return await compare_cases(pool, _stored_cases(pool, args.limit), publish=False)


async def _stored_cases(pool: Any, limit: int):
    """Le curseur garde au plus un lot de textes, jamais l'historique entier."""
    async with pool.acquire() as connection, connection.transaction(readonly=True):
        async for row in connection.cursor("""SELECT r.id,i.message_id,r.input_snapshot,r.response
          FROM verdict_runs r JOIN investigations i ON i.id=r.investigation_id
          WHERE r.status='complete' ORDER BY r.completed_at DESC,r.id LIMIT $1""", limit, prefetch=50):
            yield stored_case(dict(row))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fixtures", action="store_true", help="comparer les scénarios fictifs au corpus actif")
    group.add_argument("--stored", action="store_true", help="comparer validation et exécution conservées sur leur serveur")
    parser.add_argument("--limit", type=int, default=1000, help="nombre maximal de dossiers conservés lus")
    args = parser.parse_args()
    if not 1 <= args.limit <= 10000:
        parser.error("la limite doit être comprise entre 1 et 10000")
    previous_logging = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        report = asyncio.run(_run(args))
    except Exception as exc:
        print(json.dumps({"status": "error", "error_type": type(exc).__name__}))
        raise SystemExit(1) from None
    finally:
        logging.disable(previous_logging)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    if any(report["counts"].get(key) for key in ("error", "record_error", "mismatches")):
        raise SystemExit(1)
    if args.fixtures and report.get("qualification", {}).get("status") != "complete":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
