from __future__ import annotations

import unittest
from typing import Any
from unittest.mock import patch

from sentimail_v3.supervision import caretaker
from sentimail_v3.supervision.caretaker import SAFE_ACTIONS, execute, worth_reporting


class ReparationDesRetenuesTests(unittest.IsolatedAsyncioTestCase):
    """La réparation d'une retenue orpheline reçoit la file des avis.

    Depuis que `reconcile_one_review_hold` exige la file qui remet l'avis en
    route, le caretaker l'appelait sans elle : TypeError à chaque passage,
    « caretaker.error » au journal, rien de réparé (prod des 9 et 10
    septembre 2026). Le worker de verdict faisait le travail à sa place.
    """

    async def test_la_reparation_recoit_la_file_d_invitations(self) -> None:
        from types import SimpleNamespace
        from unittest.mock import AsyncMock

        file = SimpleNamespace(queue_invitation=AsyncMock(return_value=True))
        reparer = AsyncMock(side_effect=[True, False])
        with (
            patch.object(caretaker, "_invitation_queue", AsyncMock(return_value=file)),
            patch.object(caretaker, "reconcile_one_review_hold", reparer),
        ):
            outcome = await execute(None, None, ["reconcile_review_holds"])
        self.assertEqual({"reconcile_review_holds": 1}, outcome)
        reparer.assert_awaited_with(None, None, file)

    def test_la_signature_reelle_accepte_ce_que_le_caretaker_envoie(self) -> None:
        # Le doublon de sécurité : si la signature change encore, ce test
        # tombe avant la production.
        import inspect

        from sentimail_v3.execution.review_guard import reconcile_one_review_hold

        inspect.signature(reconcile_one_review_hold).bind(None, None, None)


class GardeFousTests(unittest.IsolatedAsyncioTestCase):
    async def test_une_action_inconnue_n_est_jamais_executee(self) -> None:
        # Le modèle peut recommander n'importe quoi : seul ce que le code
        # connaît s'exécute, le reste est rapporté.
        outcome = await execute(
            None, None, ["drop_database", "restart_host", "unknown"]
        )
        self.assertEqual(outcome, {})

    async def test_le_diagnostic_filtre_les_recommandations(self) -> None:
        async def modele(pool: Any, client: Any, settings: Any, **kwargs: Any):
            return (
                '{"diagnosis":"d","suspected_causes":[],"recommended_actions":'
                '["replay_errored_verdicts","effacer_les_logs"],'
                '"needs_operator":false,"operator_note":null}',
                {},
            )

        original = caretaker.provider_chat_json
        caretaker.provider_chat_json = modele
        try:
            from dataclasses import replace

            from sentimail_v3.config import load_settings

            with patch.dict(
                "os.environ",
                {"DATABASE_URL": "postgresql://test:test@127.0.0.1:9/test"},
            ):
                settings = replace(
                    load_settings(), provider_secrets_dir="/nonexistent"
                )
            verdict = await caretaker.diagnose(None, None, settings, {})
        finally:
            caretaker.provider_chat_json = original
        self.assertEqual(verdict["recommended_actions"], ["replay_errored_verdicts"])
        self.assertEqual(verdict["ignored_recommendations"], ["effacer_les_logs"])

    async def test_un_modele_muet_ne_bloque_pas_le_rapport(self) -> None:
        async def panne(pool: Any, client: Any, settings: Any, **kwargs: Any):
            from sentimail_v3.llm import LlmError

            raise LlmError("panne")

        original = caretaker.provider_chat_json
        caretaker.provider_chat_json = panne
        try:
            from dataclasses import replace

            from sentimail_v3.config import load_settings

            with patch.dict(
                "os.environ",
                {"DATABASE_URL": "postgresql://test:test@127.0.0.1:9/test"},
            ):
                settings = replace(
                    load_settings(), provider_secrets_dir="/nonexistent"
                )
            verdict = await caretaker.diagnose(None, None, settings, {})
        finally:
            caretaker.provider_chat_json = original
        self.assertTrue(verdict["needs_operator"])
        self.assertEqual(verdict["recommended_actions"], [])

    def test_un_etat_sain_ne_derange_personne(self) -> None:
        self.assertFalse(
            worth_reporting(
                {
                    "verdicts_en_erreur_24h": 0,
                    "livraisons_differees": 0,
                    "dossiers_coinces": 0,
                    "retenues_sans_avis": 0,
                    "desaccords_humain_modele_7j": [],
                }
            )
        )
        self.assertTrue(worth_reporting({"verdicts_en_erreur_24h": 1}))

    def test_la_liste_des_actions_est_fermee_et_courte(self) -> None:
        self.assertLessEqual(len(SAFE_ACTIONS), 6)
        for action in SAFE_ACTIONS:
            self.assertNotIn("delete", action)
            self.assertNotIn("drop", action)


if __name__ == "__main__":
    unittest.main()
