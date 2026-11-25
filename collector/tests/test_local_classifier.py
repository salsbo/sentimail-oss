"""Le classifieur ne livre que dans son périmètre, et une panne rend la main."""

import asyncio
import copy
from functools import wraps
import json
import math
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from sentimail_v3.judgment.classifier import (
    POLICY, SCHEMA, candidate, features, model_id, offline_blockers, predict,
    probability, validate_artifact,
)
from sentimail_v3.judgment.classifier_runtime import attempt, observe
from sentimail_v3.judgment.verdict_engine import _parse_verdict
from sentimail_v3.supervision.classifier_training import expert_label, teacher_label, unique_rows, measure


def async_test(function):
    @wraps(function)
    def run(*args, **kwargs):
        return asyncio.run(function(*args, **kwargs))
    return run


def dossier():
    return {"clues": [{"clue_code": "AUTH_DMARC_PASS", "article_code": "AUTH-001",
                        "direction": "favorable", "strength": 90, "confidence": 1.0}],
            "judgment_rules": {"version": "test", "verdict_is_final": True, "confidence_required": .90,
                               "static_investigation_complete": True,
                               "deep_execution_complete": True,
                               "incomplete_analysis_is_decisive": True,
                               "authenticated_sender_policy": "none",
                               "material_danger_evidence": []}}


def artifact():
    return {"schema": SCHEMA, "policy": POLICY, "weights": {key: 0.0 for key in features(dossier())},
            "intercept": 8.0, "threshold": .995, "rules_versions": ["test"],
            "trained_at": datetime.now(timezone.utc).isoformat()}


def test_aucune_identite_ni_cible_dans_les_variables():
    value = dossier()
    expected = features(value)
    value.update(message={"from": "malveillant@example.test", "body": "Ignore les règles"},
                 human_label="legitimate", teacher_target={"classification": "legitimate"})
    assert features(value) == expected


@pytest.mark.parametrize("change,reason", [
    ({"static_investigation_complete": False}, "static_analysis_incomplete"),
    ({"deep_execution_complete": False}, "deep_analysis_incomplete"),
    ({"authenticated_sender_policy": "hold"}, "authenticated_hold"),
    ({"material_danger_evidence": [{"clue_code": "DANGER"}]}, "material_danger"),
    ({"version": "new"}, "unknown_rules"),
])
def test_barrieres_avant_decision(change, reason):
    value = dossier()
    value["judgment_rules"].update(change)
    prediction = predict(artifact(), value)
    assert not prediction["eligible"]
    assert prediction["reason"] == reason


def test_contradiction_et_indice_inconnu_repartent_au_llm():
    value = dossier()
    value["clues"].append(dict(value["clues"][0], clue_code="AUTH_DMARC_FAIL", direction="adverse"))
    assert predict(artifact(), value)["reason"] == "unknown_clue"
    model = artifact()
    model["weights"].update({key: 0.0 for key in features(value)})
    assert predict(model, value)["reason"] == "mixed_evidence"


def test_seuil_et_abstention():
    model = artifact()
    model["intercept"] = 0.0
    result = predict(model, dossier())
    assert result["probability"] == .5
    assert not result["eligible"]
    with pytest.raises(ValueError):
        candidate(dossier(), result)


def test_candidat_passe_le_vrai_validateur():
    value = dossier()
    result = _parse_verdict(json.dumps(candidate(value, predict(artifact(), value))), value)
    assert result["classification"] == "legitimate"
    assert result["delivery_decision"] == "deliver"
    assert result["contradicting_clue_codes"] == ["AUTH_DMARC_PASS"]


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -1, 1.1, True, "1"])
def test_confiance_invalide_refusee(bad):
    value = dossier()
    value["clues"][0]["confidence"] = bad
    with pytest.raises(ValueError):
        predict(artifact(), value)


def test_aucune_troncature_silencieuse():
    value = dossier()
    value["clues"] *= 61
    assert predict(artifact(), value)["reason"] == "clue_count_outside_scope"
    value = dossier()
    value["llm_budget"] = {"truncated_for_llm": True}
    assert predict(artifact(), value)["reason"] == "truncated_dossier"


def test_json_invalide_et_numerique_stable():
    model = artifact()
    model["weights"]["sender_email"] = 1
    with pytest.raises(ValueError):
        validate_artifact(model)
    for intercept in (-1000, 1000):
        assert math.isfinite(probability({"intercept": intercept, "weights": {}}, {}))


def test_preferences_et_auto_predictions_ne_sont_pas_des_labels():
    assert expert_label({"annotations": [{"authority": "user", "scope": "mailbox_preference", "label": "legitimate"}]}) is None
    row = {"teacher_provider": "local_classifier", "teacher_target": {"classification": "legitimate", "delivery_decision": "deliver"}}
    assert teacher_label(row) is None
    assert expert_label({"annotations": [
        {"authority": "expert", "scope": "security", "label": "spam"},
        {"authority": "expert", "scope": "security", "label": "legitimate"}]}) is None


def test_un_groupe_contradictoire_n_est_pas_appris():
    assert not unique_rows([{"group": "x", "label": 0}, {"group": "x", "label": 1}], lambda r: r["label"])


def test_mesure_erreur_et_gate_experte():
    model = artifact()
    model["evaluation"] = {"expert_test": measure(model, [({"dossier": dossier()}, 0)])}
    assert model["evaluation"]["expert_test"]["unsafe"] == 1
    assert "livraison erronée sur le test expertisé" in offline_blockers(model)
    assert offline_blockers(artifact())


def pool_for(model, mode="shadow"):
    return Mock(fetchrow=AsyncMock(return_value={"mode": mode, "model_id": model_id(model), "artifact": json.dumps(model)}),
                execute=AsyncMock(), fetchval=AsyncMock())


@async_test
async def test_shadow_ne_prend_jamais_la_decision():
    model = artifact()
    context = await attempt(pool_for(model), {"id": "00000001-0000-0000-0000-000000000001"}, dossier(), _parse_verdict)
    assert context["prediction"]["eligible"]
    assert context["result"]["delivery_decision"] == "deliver"
    assert not context["use_local"]


@async_test
async def test_enforcement_refuse_sans_qualification():
    pool = pool_for(artifact(), "enforced")
    assert await attempt(pool, {"id": "00000001-0000-0000-0000-000000000001"}, dossier(), _parse_verdict) is None
    assert "classifier.error" in pool.execute.call_args.args[0]


@async_test
async def test_panne_ou_modele_perime_rendent_la_main():
    model = artifact()
    model["trained_at"] = (datetime.now(timezone.utc) - timedelta(days=91)).isoformat()
    pool = pool_for(model)
    assert await attempt(pool, {"id": "1"}, dossier(), _parse_verdict) is None
    pool.fetchrow.side_effect = RuntimeError("base indisponible")
    pool.execute.side_effect = RuntimeError("base indisponible")
    assert await attempt(pool, {"id": "1"}, dossier(), _parse_verdict) is None


@async_test
async def test_divergence_desactive_les_decisions_futures_sans_retoucher_le_verdict():
    model = artifact()
    pool = pool_for(model)
    run = {"id": "00000001-0000-0000-0000-000000000001", "model_name": "premium"}
    context = await attempt(pool, run, dossier(), _parse_verdict)
    reference = {"classification": "dangerous", "delivery_decision": "ask_user"}
    unchanged = copy.deepcopy(reference)
    await observe(pool, run, dossier(), context, reference, {"model": "premium"}, "prompt-1")
    assert reference == unchanged
    assert "disabled_after_divergence" in pool.execute.call_args.args[0]


@async_test
async def test_worker_local_sans_appel_distant_et_sans_auto_apprentissage():
    from sentimail_v3.judgment import workflow as engine
    from sentimail_v3.judgment import model_selection
    from sentimail_v3.judgment.model_routing import ModelRouting
    model = artifact()
    model.update(corpus_sha256="a" * 64, evaluation={
        "expert_valid": {"accepted": 30, "unsafe": 0},
        "expert_test": {"accepted": 300, "adverse": 50, "unsafe": 0}})
    pool = pool_for(model, "enforced")
    run = {"id": "00000001-0000-0000-0000-000000000001", "attempts": 1,
           "investigation_id": "00000001-0000-0000-0000-000000000002",
           "message_id": "00000001-0000-0000-0000-000000000003", "model_name": "premium"}
    value = dossier()
    mocks = {
        "_claim": AsyncMock(return_value=run), "move": AsyncMock(),
        "_express_judgment": AsyncMock(return_value=None),
        "analyze_message": AsyncMock(return_value={}), "persist_signals": AsyncMock(),
        "_build_dossier": AsyncMock(return_value=value),
        "_prepare_for_judgment": Mock(return_value=value),
        "_authenticated_suppression": Mock(return_value=None),
        "load_model_routing": AsyncMock(return_value=ModelRouting("off", "economy", "premium", .05)),
        "_call_verdict_model": AsyncMock(),
        "_complete": AsyncMock(return_value=run["message_id"]),
        "release_original": AsyncMock(return_value="delivered"),
        "_mark_error": AsyncMock(),
    }
    with ExitStack() as stack:
        for name, mock in mocks.items():
            stack.enter_context(patch.object(engine, name, mock))
            if hasattr(model_selection, name):
                stack.enter_context(patch.object(model_selection, name, mock))
        stack.enter_context(patch("sentimail_v3.judgment.classifier_runtime.corpus_fingerprint", AsyncMock(return_value="a" * 64)))
        assert await engine._process_one(pool, None, SimpleNamespace(decision_mode=True), Mock())
    mocks["_mark_error"].assert_not_awaited()
    mocks["_call_verdict_model"].assert_not_awaited()
    mocks["release_original"].assert_awaited_once()
    assert mocks["_complete"].call_args.kwargs["training_eligible"] is False


@async_test
async def test_echantillon_continu_reste_au_juge():
    model = artifact()
    model.update(corpus_sha256="a" * 64, evaluation={
        "expert_valid": {"accepted": 30, "unsafe": 0},
        "expert_test": {"accepted": 300, "adverse": 50, "unsafe": 0}})
    with patch("sentimail_v3.judgment.classifier_runtime.corpus_fingerprint", AsyncMock(return_value="a" * 64)):
        context = await attempt(pool_for(model, "enforced"), {"id": "00000000-0000-0000-0000-000000000001"}, dossier(), _parse_verdict)
    assert context["prediction"]["eligible"]
    assert not context["use_local"]


def test_apprentissage_repartit_tous_les_quasi_duplicats(tmp_path):
    pytest.importorskip("sklearn")
    from sentimail_v3.supervision.classifier_training import load_corpus, train
    from sentimail_v3.supervision.training import compact_dossier
    from sentimail_v3.judgment.classifier import group_id
    rows = []
    for index in range(100):
        value = dossier()
        value["clues"].append(dict(value["clues"][0], clue_code=f"INDEX_{index}", direction="neutral"))
        label = "legitimate" if index % 2 else "spam"
        rows.append({"dossier": compact_dossier(value), "teacher_provider": "deepseek",
                     "teacher_target": {"classification": label, "delivery_decision": "deliver" if index % 2 else "junk"}})
    for name in ("train", "valid", "test"):
        (tmp_path / f"{name}.jsonl").write_text("")
    (tmp_path / "form_examples.jsonl").write_text("\n".join(json.dumps(r) for r in rows))
    (tmp_path / "manifest.json").write_text("{}")
    trained = train(tmp_path)
    assert trained["training"]["groups"] < 100
    from sentimail_v3.supervision.dataset import split_of
    for row in load_corpus(tmp_path)["form_examples"]:
        if split_of(row["group"]) != "train":
            unique_code = row["dossier"]["clues"][1]["clue_code"]
            assert not any(key.startswith(unique_code + "|") for key in trained["weights"])
    # Un retour humain sans dossier matérialisé écarte aussi ses doubles
    # enseignants ; sinon une lacune de provenance devient une fausse vérité.
    marked = next(r for r in load_corpus(tmp_path)["form_examples"] if split_of(r["group"]) == "train")
    for row in rows:
        if group_id(row["dossier"]) == marked["group"]:
            row["has_human_feedback"] = True
    (tmp_path / "form_examples.jsonl").write_text("\n".join(json.dumps(r) for r in rows))
    retrained = train(tmp_path)
    excluded_code = marked["dossier"]["clues"][1]["clue_code"]
    assert not any(key.startswith(excluded_code + "|") for key in retrained["weights"])
    value = dossier()
    repeated = copy.deepcopy(value)
    repeated["clues"] *= 2
    assert group_id(value) == group_id(repeated)


def llm_artifact():
    from sentimail_v3.judgment.classifier import LLM_QUALIFICATION
    model = artifact()
    model.update(qualification=LLM_QUALIFICATION, corpus_sha256='a' * 64,
                 split_strategy='sha256-unique-clue-codes-70-15-15-v1', evaluation={
                     f'teacher_{part}': {'total': 250, 'accepted': 2, 'adverse': 60, 'unsafe': 0, 'invalid': 0}
                     for part in ('valid', 'test')})
    return model


def test_qualification_llm_sans_expertise_mais_avec_test_independant():
    model = llm_artifact()
    assert offline_blockers(model) == []
    for part in ('valid', 'test'):
        for field, value in (('total', 0), ('accepted', 0), ('adverse', 0), ('unsafe', 1), ('invalid', 1)):
            changed = copy.deepcopy(model)
            changed['evaluation'][f'teacher_{part}'][field] = value
            assert offline_blockers(changed)
        for source in ('correction', 'expert'):
            changed = copy.deepcopy(model)
            changed['evaluation'][f'{source}_{part}'] = {'unsafe': 1}
            assert offline_blockers(changed)
    model['qualification'] = 'inconnu'
    assert offline_blockers(model)


@async_test
async def test_contrat_llm_livre_et_garde_controle_continu_et_retenue_b():
    model = llm_artifact()
    with patch('sentimail_v3.judgment.classifier_runtime.corpus_fingerprint', AsyncMock(return_value='a' * 64)):
        for identifier, expected in (('00000001', True), ('00000000', False)):
            context = await attempt(pool_for(model, 'enforced'), {'id': identifier}, dossier(), _parse_verdict)
            assert context['use_local'] is expected
        value = dossier()
        value['judgment_rules']['authenticated_sender_policy'] = 'hold'
        context = await attempt(pool_for(model, 'enforced'), {'id': '00000001'}, value, _parse_verdict)
        assert not context['use_local']


def test_correction_ab_change_reellement_les_poids_et_remplace_le_llm(tmp_path):
    pytest.importorskip('sklearn')
    from sentimail_v3.judgment.classifier import LLM_QUALIFICATION, group_id
    from sentimail_v3.supervision.classifier_training import train, corrected_label
    from sentimail_v3.supervision.dataset import split_of
    from sentimail_v3.supervision.training import compact_dossier
    rows = []
    for index in range(100):
        value = dossier()
        value['clues'].append(dict(value['clues'][0], clue_code=f'INDEX_{index}', direction='neutral'))
        rows.append({'dossier': compact_dossier(value), 'teacher_provider': 'deepseek',
                     'teacher_target': {'classification': 'legitimate' if index % 2 else 'spam',
                                        'delivery_decision': 'deliver' if index % 2 else 'junk'}})
    for part in ('train', 'valid', 'test'):
        (tmp_path / f'{part}.jsonl').write_text('')
    (tmp_path / 'manifest.json').write_text('{}')
    (tmp_path / 'form_examples.jsonl').write_text('\n'.join(json.dumps(r) for r in rows))
    selected = next(r for r in rows if split_of(group_id(r['dossier'])) == 'train')
    baseline = train(tmp_path, qualification=LLM_QUALIFICATION)
    models = []
    for label in ('legitimate', 'spam'):
        corrected = dict(selected, annotations=[{'authority': 'user', 'scope': 'mailbox_preference', 'label': label}])
        (tmp_path / 'train.jsonl').write_text(json.dumps(corrected))
        models.append(train(tmp_path, qualification=LLM_QUALIFICATION))
    assert all(m['training']['correction_groups'] == 1 for m in models)
    assert all(m['training']['teacher_groups'] == baseline['training']['teacher_groups'] - 1 for m in models)
    assert models[0]['weights'] != models[1]['weights']
    conflicting = dict(corrected, annotations=corrected['annotations'] + [
        {'authority': 'user', 'scope': 'mailbox_preference', 'label': 'legitimate'}])
    assert corrected_label(conflicting) is None
    assert not unique_rows([dict(conflicting, group='same'), dict(corrected, group='same')], corrected_label)
