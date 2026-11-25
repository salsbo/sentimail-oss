"""Le cycle ne transforme ni un arrêt ni une attente de preuves en activation."""

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, patch

from sentimail_v3.supervision.classifier_cycle import advance, run_once


def qualified():
    return {"corpus_sha256": "a" * 64, "evaluation": {
        "expert_valid": {"accepted": 30, "unsafe": 0},
        "expert_test": {"accepted": 300, "adverse": 50, "unsafe": 0}}}


class CorpusCycleTests(IsolatedAsyncioTestCase):
    async def test_changement_du_code_declenche_export_sans_attendre_24_heures(self):
        for candidate_corpus in ("ancien", None, "actuel"):
            with self.subTest(candidate_corpus=candidate_corpus):
                config = {"enabled": True, "auto_activate": True,
                          "report": {"feedback_revision": "labels-inchanges"},
                          "last_completed_at": datetime.now(timezone.utc),
                          "candidate_model_id": "candidat"}
                lock = SimpleNamespace(fetchval=AsyncMock(return_value=True), execute=AsyncMock())
                acquisition = MagicMock()
                acquisition.__aenter__.return_value = lock
                pool = SimpleNamespace(
                    acquire=MagicMock(return_value=acquisition),
                    fetchrow=AsyncMock(return_value=config), execute=AsyncMock(),
                    fetchval=AsyncMock(side_effect=["labels-inchanges", candidate_corpus, "{}"]))
                export = AsyncMock(side_effect=RuntimeError("export atteint"))
                promote = AsyncMock()
                with patch("sentimail_v3.supervision.classifier_cycle.apply_reviews", AsyncMock(return_value=0)), \
                        patch("sentimail_v3.supervision.classifier_cycle.corpus_fingerprint", AsyncMock(return_value="actuel")), \
                        patch("sentimail_v3.supervision.classifier_cycle.export", export), \
                        patch("sentimail_v3.supervision.classifier_cycle.advance", promote):
                    if candidate_corpus == "actuel":
                        self.assertEqual(await run_once(pool), {"status": "not_due"})
                        export.assert_not_awaited()
                        promote.assert_awaited_once()
                    else:
                        with self.assertRaisesRegex(RuntimeError, "export atteint"):
                            await run_once(pool)
                        export.assert_awaited_once()
                        promote.assert_not_awaited()
                lock.execute.assert_awaited_once()


class QualificationTests(IsolatedAsyncioTestCase):
    async def invoke(self, state, candidate=None, active=None, auto=True):
        pool = SimpleNamespace(fetchval=AsyncMock(return_value=json.dumps(active or qualified())))
        configure = AsyncMock(return_value={"mode": "enforced"})
        with patch("sentimail_v3.supervision.classifier_cycle.report", AsyncMock(return_value=state)), \
                patch("sentimail_v3.supervision.classifier_cycle.configure", configure):
            result = await advance(pool, candidate or qualified(), auto_activate=auto)
        return result, configure

    async def test_arret_operateur_et_mode_actif_preserves(self):
        for mode in ("off", "enforced"):
            with self.subTest(mode=mode):
                state = {"mode": mode, "model_id": "a", "enforcement_blockers": []}
                result, configure = await self.invoke(state)
                self.assertEqual(result, state)
                configure.assert_not_awaited()

    async def test_auto_activation_desactivee(self):
        _, configure = await self.invoke({"mode": "shadow", "enforcement_blockers": []}, auto=False)
        configure.assert_not_awaited()

    async def test_activation_utilise_la_transaction_de_qualification_et_l_etat_attendu(self):
        _, configure = await self.invoke({"mode": "shadow", "model_id": "a", "enforcement_blockers": []})
        self.assertEqual(configure.call_args.kwargs, {"mode": "enforced", "automated": True,
                                                      "expected": ("a", "shadow")})

    async def test_nouveau_candidat_ne_remet_pas_a_zero_l_observation_qualifiee(self):
        _, configure = await self.invoke({"mode": "shadow", "model_id": "a", "enforcement_blockers": ["300 groupes manquants"]})
        configure.assert_not_awaited()

    async def test_candidat_incomplet_ne_remplace_pas_le_modele(self):
        _, configure = await self.invoke({"mode": "shadow", "model_id": "a", "enforcement_blockers": ["expertise manquante"]},
                                         candidate={"evaluation": {}}, active={"evaluation": {}})
        configure.assert_not_awaited()

    async def test_candidat_qualifie_commence_par_observation(self):
        model = qualified()
        _, configure = await self.invoke({"mode": "shadow", "model_id": "a", "enforcement_blockers": ["expertise manquante"]},
                                         candidate=model, active={"evaluation": {}})
        self.assertEqual(configure.call_args.kwargs["artifact"], model)
        self.assertNotIn("mode", configure.call_args.kwargs)

    async def test_modele_perime_ne_bloque_pas_un_nouveau_cycle_d_observation(self):
        _, configure = await self.invoke({"mode": "shadow", "model_id": "a", "enforcement_blockers": ["modèle périmé"]})
        self.assertIn("artifact", configure.call_args.kwargs)
        self.assertNotIn("mode", configure.call_args.kwargs)

    async def test_candidat_llm_corrige_remplace_modele_actif_apres_garde(self):
        from test_local_classifier import llm_artifact
        from sentimail_v3.judgment.classifier import model_id
        candidate = llm_artifact()
        pool = SimpleNamespace()
        configure = AsyncMock(side_effect=[{'model_id': model_id(candidate), 'mode': 'shadow', 'enforcement_blockers': []},
                                          {'model_id': model_id(candidate), 'mode': 'enforced'}])
        with patch('sentimail_v3.supervision.classifier_cycle.report', AsyncMock(return_value={
                'mode': 'enforced', 'model_id': 'old', 'enforcement_blockers': []})), \
                patch('sentimail_v3.supervision.classifier_cycle.configure', configure):
            result = await advance(pool, candidate, auto_activate=True)
        self.assertEqual(result['mode'], 'enforced')
        self.assertEqual(configure.await_args_list[0].kwargs['expected'], ('old', 'enforced'))
        self.assertEqual(configure.await_args_list[1].kwargs['expected'], (model_id(candidate), 'shadow'))
