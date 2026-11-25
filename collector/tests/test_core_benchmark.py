"""Le banc exerce des contrats distincts et n'annonce pas de qualité métier."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import tracemalloc
from types import SimpleNamespace
from urllib.parse import urlsplit
from unittest.mock import AsyncMock, patch
import uuid

import pytest

from sentimail_v3.judgment.core_compare import compare_case, compare_express, compare_retry, reference
from sentimail_v3.judgment.dossier import _prepare_for_judgment
from sentimail_v3.judgment.response import JudgmentContradiction, _parse_final_response
from sentimail_v3.supervision import core_benchmark as bank, core_rollout


ARTICLES = [
    {"article_code": "AUTH-001", "title": "Authentification", "default_direction": "favorable",
     "parameters": {}, "clue_codes": ["AUTH_DMARC_PASS"]},
    {"article_code": "AUTH-002", "title": "Échec", "default_direction": "adverse",
     "parameters": {}, "clue_codes": ["AUTH_DMARC_FAIL"]},
    {"article_code": "ATT-001", "title": "Exécutable", "default_direction": "adverse",
     "parameters": {"delivery_barrier": "material_danger", "material_kind": "executable_attachment"},
     "clue_codes": ["ATTACHMENT_EXECUTABLE"]},
    {"article_code": "CONTENT-010", "title": "Code fourni", "default_direction": "neutral",
     "parameters": {}, "clue_codes": ["CONTENT_EXPECTED_ONE_TIME_CODE_INPUT"]},
    {"article_code": "ATT-019", "title": "Inspection incomplète", "default_direction": "neutral",
     "parameters": {"clue_code": "ATTACHMENT_ANALYSIS_BLOCKED"}},
    {"article_code": "CORR-019", "title": "Destination contradictoire", "default_direction": "adverse",
     "parameters": {"clue_code": "CORRELATION_UNVERIFIED_IDENTITY_DESTINATION"}},
]


def cases() -> dict:
    return {case["id"]: case for case in bank.benchmark_cases(ARTICLES)}


def required() -> set[str]:
    return core_rollout.REQUIRED_COVERAGE | {"article:"+article["article_code"] for article in ARTICLES}


@pytest.fixture
def anyio_backend():
    return "asyncio"


def prepared(case: dict) -> dict:
    return _prepare_for_judgment(copy.deepcopy(case["dossier"]), case["deep"], SimpleNamespace(**case["settings"]))


def test_chaque_couverture_a_une_paire_distincte() -> None:
    original = copy.deepcopy(ARTICLES)
    fixtures = bank.benchmark_cases(ARTICLES)
    pairs = {}
    for case in fixtures:
        key = (core_rollout._hash(bank._envelope(case)), core_rollout._hash(case["response_text"]))
        pairs.setdefault(key, []).append({"status": "complete", "agreement": True, "coverage": case["coverage"]})
    assert set(core_rollout._independent_coverage(pairs, required=required())) == required()
    assert len(pairs) == len(fixtures)
    assert ARTICLES == original


def test_tous_les_articles_et_indices_declares_passent_dans_le_dossier() -> None:
    fixtures = cases()
    for article in ARTICLES:
        case = fixtures["article_"+article["article_code"]]
        assert case["dossier"]["code_articles"] == [article]
        assert {c["clue_code"] for c in case["dossier"]["clues"]} == set(bank._codes(article))


@pytest.mark.parametrize("identifier,reason", [
    ("material_danger", "material_danger_unresolved"),
    ("authenticated_hold", "authenticated_hold_ignored"),
    ("static_incomplete", "static_investigation_incomplete"),
    ("deep_incomplete", "deep_execution_incomplete"),
    ("identity_destination_conflict", "identity_destination_conflict_unresolved"),
])
def test_chaque_fixture_de_barriere_exerce_son_rejet(identifier: str, reason: str) -> None:
    case = cases()[identifier]
    for prepare, parse in ((_prepare_for_judgment, _parse_final_response),
                           (reference()._prepare_for_judgment, reference()._parse_final_response)):
        dossier = prepare(copy.deepcopy(case["dossier"]), case["deep"], SimpleNamespace(**case["settings"]))
        result, contradictions = parse(case["response_text"], dossier)
        assert reason in contradictions
        assert result["delivery_decision"] == "ask_user"


@pytest.mark.parametrize("identifier", ["retry", "low_confidence"])
def test_les_fixtures_rejouables_ne_simulent_pas_un_verdict_valide(identifier: str) -> None:
    case = cases()[identifier]
    with pytest.raises(JudgmentContradiction) as caught:
        _parse_final_response(case["response_text"], prepared(case))
    assert not caught.value.structural


def test_la_saturation_conserve_la_barriere_cachee_hors_des_40_indices() -> None:
    case = cases()["saturation_material_beyond_40"]
    assert len(case["dossier"]["clues"]) > 40
    dossier = prepared(case)
    assert dossier["llm_budget"]["truncated_for_llm"]
    assert len(dossier["clues"]) == 40
    assert not any(c["clue_code"] == "ATTACHMENT_EXECUTABLE" for c in dossier["clues"])
    assert dossier["judgment_rules"]["material_danger_evidence"]


def test_les_calculs_complets_sont_equivalents_a_la_reference_independante() -> None:
    for case in cases().values():
        result = compare_case(case["dossier"], case["deep"], SimpleNamespace(**case["settings"]), case["response_text"])
        assert result["agreement"], case["id"]


@pytest.mark.parametrize("classification", ["legitimate", "spam", "suspect", "dangerous", "undetermined"])
def test_les_cinq_classifications_sont_reellement_parsees(classification: str) -> None:
    case = cases()[classification]
    result, contradictions = _parse_final_response(case["response_text"], prepared(case))
    assert result["classification"] == classification
    assert not contradictions


def test_la_fixture_b_exerce_la_suppression_authentifiee_reelle() -> None:
    case = cases()["policy_b"]
    result = compare_case(case["dossier"], case["deep"], SimpleNamespace(**case["settings"]), case["response_text"])
    assert all(result[side]["policy_b"]["value"]["delivery_decision"] == "suppress"
               for side in ("legacy", "candidate"))


@pytest.mark.parametrize("identifier", ["invalid_response", "invalid_reference"])
def test_les_reponses_invalides_sont_reellement_rejetees_des_deux_cotes(identifier: str) -> None:
    case = cases()[identifier]
    for parse in (_parse_final_response, reference()._parse_final_response):
        with pytest.raises(ValueError):
            parse(case["response_text"], prepared(case))


@pytest.mark.anyio
async def test_la_fixture_otp_ouvre_la_vraie_voie_et_le_tiers_la_ferme() -> None:
    case = cases()["otp"]
    compared = await compare_express(bank._ExpressPool(case), "synthetic")
    assert compared["agreement"]
    assert all(compared[side]["result"]["delivery_decision"] == "deliver" for side in ("legacy", "candidate"))
    case["dossier"]["express_inputs"]["destinations"] = ["unrelated.invalid"]
    blocked = await compare_express(bank._ExpressPool(case), "synthetic")
    assert blocked["agreement"]
    assert blocked["candidate"]["result"] is None


@pytest.mark.anyio
async def test_les_fixtures_de_reprise_comparent_des_plans_reels() -> None:
    for identifier in ("retry", "retry_transient", "retry_exhausted"):
        result = await compare_retry(**cases()[identifier]["dossier"]["retry_inputs"])
        assert result["agreement"]
        assert result["candidate"]["plan"]
        assert result["candidate"]["state"]["status"] == "error"


def _stored_row() -> dict:
    case = cases()["legitimate"]
    dossier = prepared(case)
    result, _ = _parse_final_response(case["response_text"], dossier)
    return {"id": "00000000-0000-0000-0000-000000000001", "message_id": "00000000-0000-0000-0000-000000000002",
            "input_snapshot": dossier, "response": {"verdict": result}}


def test_une_vue_reduite_ne_prouve_que_validation_et_execution() -> None:
    row = _stored_row()
    row["input_snapshot"].update({"schema": "sentimail-v3-training-view-1", "deep_analysis": {}})
    row["input_snapshot"].pop("message")
    case = bank.stored_case(row)
    assert "exclusion_reason" not in case
    assert case["comparison_scope"] == "stored_validation_execution"
    assert "settings" not in bank._envelope(case)


@pytest.mark.parametrize("field,reason", [("input_snapshot", "IncompleteStoredDossier"), ("response", "MissingStoredResponse")])
def test_un_historique_incomplet_est_explicitement_exclu(field: str, reason: str) -> None:
    row = _stored_row()
    row[field] = {}
    assert bank.stored_case(row)["exclusion_reason"] == reason


@pytest.mark.anyio
async def test_un_historique_exclu_n_est_jamais_reconstruit() -> None:
    case = bank.stored_case({"id": "a", "message_id": "b", "input_snapshot": {}, "response": {}})
    with patch("sentimail_v3.judgment.core_compare.compare_case", side_effect=AssertionError("pas de reconstruction")), \
         patch.object(core_rollout, "record_comparison", new=AsyncMock(return_value={"status": "excluded", "agreement": False})) as record:
        report = await bank.compare_cases(object(), [case], publish=False)
    assert report["counts"] == {"excluded": 1}
    assert record.await_args.kwargs["exclusion_reason"] == "IncompleteStoredDossier"
    assert report["coverage"] == []


def test_les_associations_statiques_sont_des_constantes_du_code_existant() -> None:
    mapping = bank._static_associations()
    assert "AUTH_DMARC_PASS" in mapping["AUTH-001"]
    assert "HISTORY_FIRST_OBSERVATION" in mapping["HIST-002"]
    assert "CONTENT_EXPECTED_ONE_TIME_CODE_INPUT" in mapping["CONTENT-010"]


@pytest.mark.anyio
async def test_le_rapport_ne_divulgue_aucun_texte_et_qualifie_la_couverture_complete() -> None:
    async def store(pool, **kwargs):
        excluded = kwargs.get("exclusion_reason")
        error = kwargs.get("error_type")
        return {"status": "excluded" if excluded else "error" if error else "complete",
                "agreement": kwargs["legacy"] == kwargs["candidate"] and not error and not excluded}
    published = {"status": "complete", "cases": len(cases()), "errors": 0, "mismatches": 0,
                 "excluded": 0, "coverage": sorted(required()), "comparison_set_sha256": "a"*64}
    with patch.object(core_rollout, "record_comparison", new=store), \
         patch.object(core_rollout, "publish_qualification", new=AsyncMock(return_value=published)) as publish:
        report = await bank.compare_cases(object(), list(cases().values()))
    publish.assert_awaited_once()
    assert report["coverage"] == sorted(required())
    assert report["counts"]["agreements"] == len(cases())
    assert "Texte fictif" not in json.dumps(report)
    assert "482913" not in json.dumps(report)


@pytest.fixture
async def postgres_pool():
    import asyncpg

    dsn = os.environ.get("CORE_ROLLOUT_TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("PostgreSQL jetable requis")
    target = urlsplit(dsn)
    assert target.hostname == "127.0.0.1" and target.path.endswith("_test")
    schema = "core_benchmark_"+uuid.uuid4().hex
    connection = await asyncpg.connect(dsn)
    await connection.execute(f"CREATE SCHEMA {schema}")

    async def initialize(conn):
        await conn.execute(f"SET search_path={schema},public")

    pool = await asyncpg.create_pool(dsn, min_size=1, max_size=2, setup=initialize)
    try:
        await pool.execute("""CREATE TABLE messages (LIKE public.messages INCLUDING ALL);
          ALTER TABLE messages DROP COLUMN IF EXISTS engine_generation;
          ALTER TABLE messages DROP COLUMN IF EXISTS engine_generation_assigned_at;
          CREATE TABLE verdict_runs (LIKE public.verdict_runs INCLUDING ALL);
          ALTER TABLE verdict_runs DROP COLUMN IF EXISTS engine_generation;
          ALTER TABLE verdict_runs DROP COLUMN IF EXISTS analysis_plan;
          CREATE TABLE code_articles AS SELECT * FROM public.code_articles;
          CREATE TABLE code_editions AS SELECT * FROM public.code_editions;
          CREATE TABLE audit_log (LIKE public.audit_log INCLUDING ALL);""")
        await pool.execute((Path(__file__).parents[2]/"database/init/109_core_rollout.sql").read_text())
        yield pool
    finally:
        await pool.close()
        await connection.execute(f"DROP SCHEMA {schema} CASCADE")
        await connection.close()


@pytest.mark.anyio
async def test_postgres_enregistre_les_paires_et_qualifie_sans_conserver_leur_contenu(postgres_pool) -> None:
    pool = postgres_pool
    with patch.object(core_rollout, "package_fingerprint", return_value="a"*64):
        articles = await bank._active_articles(pool)
        report = await bank.compare_cases(pool, bank.benchmark_cases(articles))
    assert report["qualification"]["status"] == "complete"
    assert report["qualification"]["coverage"] == sorted(await core_rollout.required_coverage(pool))
    assert report["qualification"]["errors"] == report["qualification"]["mismatches"] == 0
    assert await pool.fetchval("SELECT bool_and(agreement AND status='complete') FROM core_rollout_comparisons")
    columns = await pool.fetch("""SELECT column_name FROM information_schema.columns
      WHERE table_schema=current_schema() AND table_name='core_rollout_comparisons'""")
    assert not {"dossier", "response", "raw_response", "input_snapshot"} & {row["column_name"] for row in columns}


@pytest.mark.anyio
async def test_l_empreinte_incrementale_reste_identique_a_celle_du_jeu_complet() -> None:
    fixtures = list(cases().values())[:3]

    async def stream():
        for case in fixtures:
            yield case

    with patch.object(core_rollout, "record_comparison", new=AsyncMock(return_value={"status": "complete", "agreement": True})):
        report = await bank.compare_cases(object(), stream(), publish=False)
    expected = core_rollout._hash([{"inputs": bank._envelope(case), "response": case["response_text"]} for case in fixtures])
    assert report["case_set_sha256"] == expected
    assert report["cases"] == len(fixtures)


@pytest.mark.anyio
async def test_postgres_rejoue_3000_runs_par_curseur_sans_garder_leurs_textes(postgres_pool) -> None:
    pool = postgres_pool
    row = _stored_row()
    row["input_snapshot"]["message"]["body_text"] = "Texte entièrement fictif. "*2000
    identifier = row["message_id"]
    await pool.execute("""INSERT INTO messages (
      id,ingest_key,envelope_from,envelope_recipients,raw_sha256,raw_size_bytes,
      headers_size_bytes,body_size_bytes,line_count,max_line_length,contains_8bit,
      contains_nul,line_ending,root_content_type,parser_version)
      VALUES($1::uuid,'fixture','sender@example.org',ARRAY['recipient@example.net'],
        repeat('a',64),0,0,0,0,0,false,false,'crlf','text/plain','fixture')""", identifier)
    await pool.execute("""DROP TABLE verdict_runs;
      CREATE TABLE verdict_runs (id uuid,investigation_id uuid,input_snapshot jsonb,
        response jsonb,status text,completed_at timestamptz);
      CREATE TABLE investigations (id uuid PRIMARY KEY,message_id uuid);""")
    investigation = str(uuid.uuid4())
    await pool.execute("INSERT INTO investigations VALUES($1::uuid,$2::uuid)", investigation, identifier)
    await pool.execute("""INSERT INTO verdict_runs
      SELECT gen_random_uuid(),$1::uuid,$2::jsonb,$3::jsonb,'complete',now()
      FROM generate_series(1,3000)""", investigation, json.dumps(row["input_snapshot"]), json.dumps(row["response"]))

    class ReaderGuard:
        def acquire(self):
            return pool.acquire()

        async def fetch(self, query, *args):
            assert "FROM verdict_runs" not in query
            return await pool.fetch(query, *args)

        async def fetchval(self, query, *args):
            return await pool.fetchval(query, *args)

        async def execute(self, query, *args):
            return await pool.execute(query, *args)

    tracemalloc.start()
    try:
        with patch.object(core_rollout, "package_fingerprint", return_value="a"*64):
            guarded = ReaderGuard()
            report = await bank.compare_cases(guarded, bank._stored_cases(guarded, 3000), publish=False)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert report["cases"] == report["counts"]["agreements"] == 3000
    assert report["distinct_pairs"] == 1
    assert peak < 32*1024*1024
    assert await pool.fetchval("SELECT count(*) FROM core_rollout_comparisons") == 3000


@pytest.mark.anyio
async def test_mode_active_core_v1_court_circuite_before_model_et_before_commit() -> None:
    from sentimail_v3.judgment import core_compare

    pool = SimpleNamespace(fetchval=AsyncMock(return_value="active"))
    run = {"id": "run-1", "message_id": "msg-1", "engine_generation": core_rollout.GENERATION}
    with patch.object(core_compare, "reference", side_effect=AssertionError("oracle figé interdit en mode active")), \
         patch.object(core_rollout, "record_comparison", new=AsyncMock(side_effect=AssertionError("aucune écriture"))):
        await core_compare.before_model(pool, run, {}, {}, SimpleNamespace(auto_delivery_confidence=0.9))
        await core_compare.before_commit(pool, run, {}, {"delivery_decision": "deliver"})


@pytest.mark.anyio
async def test_mode_canary_core_v1_maintient_la_comparaison_et_bloque_sur_divergence() -> None:
    from sentimail_v3.judgment import core_compare

    pool = SimpleNamespace(fetchval=AsyncMock(return_value="canary"))
    run = {"id": "run-2", "message_id": "msg-2", "engine_generation": core_rollout.GENERATION}
    with patch.object(core_compare, "compare_final", return_value={"legacy": {"a": 1}, "candidate": {"a": 2}, "agreement": False}), \
         patch.object(core_rollout, "record_comparison", new=AsyncMock(return_value={"agreement": False})):
        with pytest.raises(core_compare.CoreComparisonError):
            await core_compare.before_commit(pool, run, {}, {"delivery_decision": "deliver"})


@pytest.mark.anyio
async def test_mode_shadow_legacy_maintient_la_comparaison_sans_bloquer() -> None:
    from sentimail_v3.judgment import core_compare

    pool = SimpleNamespace(fetchval=AsyncMock(return_value="shadow"))
    run = {"id": "run-3", "message_id": "msg-3", "engine_generation": "legacy"}
    record = AsyncMock(return_value={"agreement": False})
    with patch.object(core_compare, "compare_final", return_value={"legacy": {"a": 1}, "candidate": {"a": 2}, "agreement": False}), \
         patch.object(core_rollout, "record_comparison", new=record):
        await core_compare.before_commit(pool, run, {}, {"delivery_decision": "deliver"})
    record.assert_awaited_once()
