from __future__ import annotations

import unittest

from sentimail_v3.observation.deep_hooks import (
    DEEP_HOOKS,
    DeepHook,
    DeepHookResult,
    run_deep_hooks,
)


class _Contexte:
    def __init__(self) -> None:
        self.pool = None
        self.client = None
        self.settings = None
        self.message_id = "message-id"
        self.clue_codes: set[str] = set()
        self.sender_apex = "exemple.fr"
        self.subject = "Objet"
        self.body = "Corps"


class _HookQuiRepond(DeepHook):
    name = "repond"
    version = "1.0.0"

    async def observe(self, context):  # type: ignore[no-untyped-def]
        return [{"clue_code": "UN_INDICE", "article_code": "X-001"}], {"vu": True}


class _HookQuiPasse(DeepHook):
    name = "passe"
    version = "1.0.0"

    async def observe(self, context):  # type: ignore[no-untyped-def]
        return [], {"raison": "rien à faire ici"}


class _HookQuiCasse(DeepHook):
    name = "casse"
    version = "1.0.0"

    async def observe(self, context):  # type: ignore[no-untyped-def]
        raise RuntimeError("le modèle est injoignable")


class RunDeepHooksTests(unittest.IsolatedAsyncioTestCase):
    async def test_chaque_hook_rend_compte_de_son_passage(self) -> None:
        """La garantie d'exécution vaut ce que vaut sa trace."""
        results = await run_deep_hooks(
            [_HookQuiRepond(), _HookQuiPasse()], _Contexte()
        )
        self.assertEqual([r.hook_name for r in results], ["repond", "passe"])
        self.assertEqual([r.status for r in results], ["ok", "skip"])

    async def test_une_panne_n_arrete_pas_les_suivants(self) -> None:
        results = await run_deep_hooks(
            [_HookQuiCasse(), _HookQuiRepond()], _Contexte()
        )
        self.assertEqual(results[0].status, "error")
        self.assertEqual(results[0].error_type, "RuntimeError")
        # Le suivant a bien tourné : un hook qui tombe n'emporte pas l'enquête.
        self.assertEqual(results[1].status, "ok")

    async def test_une_panne_ne_produit_aucun_indice(self) -> None:
        """Ne pas savoir n'accuse pas : c'est la règle tenue partout ailleurs."""
        results = await run_deep_hooks([_HookQuiCasse()], _Contexte())
        self.assertEqual(results[0].clues, [])

    async def test_la_duree_est_mesuree(self) -> None:
        results = await run_deep_hooks([_HookQuiRepond()], _Contexte())
        self.assertGreaterEqual(results[0].duration_ms, 0)


class RegistryTests(unittest.TestCase):
    def test_le_registre_est_la_source_unique(self) -> None:
        noms = [hook.name for hook in DEEP_HOOKS]
        self.assertIn("sender_relation", noms)
        self.assertEqual(len(noms), len(set(noms)), "deux hooks de même nom")

    def test_chaque_hook_porte_une_version(self) -> None:
        for hook in DEEP_HOOKS:
            self.assertTrue(hook.version)


if __name__ == "__main__":
    unittest.main()


class TracageTests(unittest.IsolatedAsyncioTestCase):
    """Sans trace en base, la garantie d'exécution n'est pas vérifiable."""

    async def test_chaque_passage_est_inscrit_dans_hook_runs(self) -> None:
        from sentimail_v3.observation.deep_analysis import persist_deep_hook_runs

        class _Pool:
            def __init__(self):
                self.ecrits = []

            async def execute(self, query, *args):
                self.ecrits.append((query, args))
                return "INSERT 1"

        pool = _Pool()
        resultats = [
            DeepHookResult("sender_relation", "1.0.0", "ok", 12.0,
                           clues=[], facts={"asked": True}),
            DeepHookResult("autre", "1.0.0", "error", 3.0,
                           error_type="TimeoutError", error_detail="trop long"),
        ]

        await persist_deep_hook_runs(pool, "11111111-1111-1111-1111-111111111111", resultats)  # type: ignore[arg-type]

        inscrits = [a for q, a in pool.ecrits if "hook_runs" in q]
        self.assertEqual(len(inscrits), 2)
        noms = {v for args in inscrits for v in args if isinstance(v, str)}
        self.assertIn("sender_relation", noms)
        self.assertIn("TimeoutError", noms)


class RequestedActionHookTests(unittest.IsolatedAsyncioTestCase):
    """L'acte réclamé se juge, comme la cohérence de métier."""

    def test_le_hook_est_au_registre(self) -> None:
        self.assertIn("requested_action", [h.name for h in DEEP_HOOKS])

    async def test_un_message_sans_corps_ne_pose_pas_la_question(self) -> None:
        from sentimail_v3.observation.deep_hooks import RequestedActionHook

        contexte = _Contexte()
        contexte.body = ""
        contexte.subject = ""
        clues, facts = await RequestedActionHook().observe(contexte)
        self.assertEqual(clues, [])
        self.assertFalse(facts.get("asked"))

    async def test_un_code_fourni_ne_devient_pas_une_demande_de_le_communiquer(self) -> None:
        from unittest.mock import AsyncMock, patch

        from sentimail_v3.observation.deep_hooks import RequestedActionHook

        contexte = _Contexte()
        contexte.subject = "Voici le code que vous avez demandé"
        contexte.body = (
            "Le code de vérification de votre nouvel appareil est le suivant : "
            "123456. Ce code expirera dans 15 minutes. Vérifier cet appareil."
        )
        reponse = '{"actions": ["mfa_code_disclosure"], "explication": "x"}'
        with patch(
            "sentimail_v3.llm.provider_chat_json",
            new=AsyncMock(return_value=(reponse, {})),
        ):
            clues, facts = await RequestedActionHook().observe(contexte)
        self.assertEqual(clues, [])
        self.assertTrue(facts["mfa_code_disclosure_unconfirmed"])
