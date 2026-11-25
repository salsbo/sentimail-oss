"""Le trajet complet : deux recherches, puis le modèle qui juge le rapport.

Ce test tient l'enchaînement, là où `test_identity_relation` tient chacune de
ses pièces. Trois chemins comptent : le domaine reconnu comme celui de
l'organisation ferme la question sans appeler personne ; une absence de rapport
jugée sur pièces devient un indice ; un modèle en panne, muet ou hors format
n'accuse pas.
"""

from __future__ import annotations

import json
import unittest
from typing import Any
from unittest.mock import patch

from sentimail_v3.observation import deep_analysis


class _Settings:
    search_api_key = "cle"
    search_base_url = "https://api.exemple.test"


NOM = "DISNEY+ RECOVERY"
DOMAINE = "careerwiseenglish.com.au"
SUR_LE_NOM = [
    {"title": "Disney+ streaming", "url": "https://disneyplus.com/", "content": "Films et séries."}
]
SUR_LE_DOMAINE = [
    {
        "title": "CareerWise English",
        "url": "https://careerwiseenglish.com.au/",
        "content": "English school for international students in Sydney.",
    }
]


class TrajetCompletTests(unittest.IsolatedAsyncioTestCase):
    async def _juger(
        self,
        reponse: object,
        *,
        apexes: list[str],
        from_apex: str = DOMAINE,
        panne: bool = False,
    ):
        async def _about_name(*_: Any, **__: Any):
            return SUR_LE_NOM, apexes

        async def _about_domain(*_: Any, **__: Any):
            return SUR_LE_DOMAINE

        async def _chat(*_: Any, **__: Any):
            if panne:
                raise RuntimeError("fournisseur indisponible")
            return json.dumps(reponse), {}

        with patch.object(deep_analysis, "_log", lambda *a, **k: None), patch.object(
            deep_analysis, "provider_chat_json", _chat
        ), patch(
            "sentimail_v3.observation.organisation_search.about_name", _about_name
        ), patch(
            "sentimail_v3.observation.organisation_search.about_domain", _about_domain
        ):
            return await deep_analysis._identity_relation(
                None, None, _Settings(), display_name=NOM, from_apex=from_apex
            )

    async def test_l_absence_de_rapport_jugee_sur_pieces_devient_un_indice(self) -> None:
        clue, facts = await self._juger(
            {
                "rapport": False,
                "organisation": "Disney+",
                "explication": "Le domaine est celui d’une école de langue.",
            },
            apexes=["disneyplus.com", "disney.com"],
        )
        self.assertIsNotNone(clue)
        self.assertEqual(clue["article_code"], "DEEP-022")
        self.assertEqual(clue["direction"], "adverse")
        self.assertEqual(facts["results_on_domain"], 1)

    async def test_un_domaine_reconnu_ferme_la_question_sans_modele(self) -> None:
        clue, facts = await self._juger(
            {"rapport": False, "organisation": "Synology", "explication": "x"},
            apexes=["careerwiseenglish.com.au"],
        )
        self.assertIsNone(clue)
        self.assertTrue(facts["cleared"])

    async def test_un_rapport_reconnu_ne_produit_rien(self) -> None:
        clue, _ = await self._juger(
            {"rapport": True, "organisation": "Disney+", "explication": "x"},
            apexes=["disneyplus.com"],
        )
        self.assertIsNone(clue)

    async def test_un_doute_ne_produit_rien(self) -> None:
        clue, _ = await self._juger(
            {"rapport": None, "organisation": "", "explication": ""},
            apexes=["disneyplus.com"],
        )
        self.assertIsNone(clue)

    async def test_le_rapport_lu_est_ecrit_dans_les_faits(self) -> None:
        """L'enquêteur sender_relation distingue « rapport reconnu », « non
        tranché » et « démenti » sur ce fait : sans lui, une organisation
        trouvée au rapport non tranché passait pour un vide."""
        _, facts = await self._juger({"rapport": None}, apexes=["disneyplus.com"])
        self.assertIn("rapport", facts)
        self.assertIsNone(facts["rapport"])
        _, facts = await self._juger({"rapport": True}, apexes=["disneyplus.com"])
        self.assertTrue(facts["rapport"])

    async def test_une_panne_du_modele_n_accuse_pas(self) -> None:
        clue, facts = await self._juger({}, apexes=["disneyplus.com"], panne=True)
        self.assertIsNone(clue)
        self.assertTrue(facts["error"])


class JournalisationTests(unittest.TestCase):
    """Les chemins fail-soft doivent pouvoir écrire au journal.

    `_log` était appelé trois fois dans l'analyse profonde sans y être défini :
    chaque panne de modèle levait une `NameError` à l'endroit même où elle
    devait rester bénigne.
    """

    def test_l_analyse_profonde_sait_journaliser(self) -> None:
        self.assertTrue(callable(getattr(deep_analysis, "_log", None)))


class MemoireDesRecherchesTests(unittest.TestCase):
    """Une même question ne se pose qu'une fois par mois.

    Sept jours de courrier réel : 311 confrontations, mais 115 noms et 96
    domaines distincts. Sans mémoire, 622 recherches partent là où 211
    suffisent.
    """

    def test_les_deux_recherches_passent_par_la_memoire(self) -> None:
        import inspect

        from sentimail_v3.observation import organisation_search

        for fonction in (organisation_search.about_name, organisation_search.about_domain):
            with self.subTest(fonction=fonction.__name__):
                self.assertIn("_remembered_search", inspect.getsource(fonction))

    def test_une_recherche_muette_ne_se_garde_pas(self) -> None:
        # Sinon la panne d'aujourd'hui passerait pour l'absence de réponse de
        # tout le mois.
        import inspect

        from sentimail_v3.observation import organisation_search

        source = inspect.getsource(organisation_search._remembered_search)
        self.assertIn("if not results:", source)
        self.assertLess(source.index("if not results:"), source.index("INSERT INTO search_lookups"))


class CeQuiSortDeLaMachineTests(unittest.TestCase):
    """La recherche ne doit emporter que le nom affiché et le domaine."""

    def test_le_client_n_envoie_ni_message_ni_destinataire(self) -> None:
        import inspect

        from sentimail_v3.observation import organisation_search

        source = inspect.getsource(organisation_search)
        for interdit in ("subject", "body", "recipient", "envelope"):
            self.assertNotIn(interdit, source)


if __name__ == "__main__":
    unittest.main()


class FaitDeProprieteAvantAccusationTests(unittest.IsolatedAsyncioTestCase):
    """Le hook reçoit les signatures d'organisation et s'en sert avant d'accuser."""

    async def test_un_fait_de_propriete_ferme_la_question_sans_modele(self) -> None:
        appels: list[str] = []

        async def _about_name(*_: Any, **__: Any):
            return SUR_LE_NOM, ["ca-paris.com", "credit-agricole.fr"]

        async def _about_domain(*_: Any, **__: Any):
            appels.append("about_domain")
            return SUR_LE_DOMAINE

        async def _chat(*_: Any, **__: Any):
            appels.append("modele")
            return json.dumps({"rapport": False}), {}

        with patch.object(deep_analysis, "_log", lambda *a, **k: None), patch.object(
            deep_analysis, "provider_chat_json", _chat
        ), patch(
            "sentimail_v3.observation.organisation_search.about_name", _about_name
        ), patch(
            "sentimail_v3.observation.organisation_search.about_domain", _about_domain
        ):
            clue, facts = await deep_analysis._identity_relation(
                None,
                None,
                _Settings(),
                display_name="Crédit Agricole d'Ile-de-France",
                from_apex="e-ca-paris.fr",
                organisations={"e-ca-paris.fr": {"ns:credit-agricole.fr"}},
            )
        self.assertIsNone(clue)
        self.assertTrue(facts.get("cleared"))
        self.assertEqual(facts.get("owned_via"), "credit-agricole.fr")
        self.assertEqual(appels, [])

    async def test_sans_fait_de_propriete_le_constat_mecanique_reste(self) -> None:
        async def _about_name(*_: Any, **__: Any):
            return SUR_LE_NOM, ["ca-paris.com", "credit-agricole.fr"]

        with patch.object(deep_analysis, "_log", lambda *a, **k: None), patch(
            "sentimail_v3.observation.organisation_search.about_name", _about_name
        ):
            clue, _ = await deep_analysis._identity_relation(
                None,
                None,
                _Settings(),
                display_name="Crédit Agricole d'Ile-de-France",
                from_apex="e-ca-paris.fr",
                organisations={"e-ca-paris.fr": {"ns:hebergeur-mutualise.example"}},
            )
        self.assertIsNotNone(clue)
        self.assertEqual(clue["strength"], 65)

    def test_le_hook_transmet_les_signatures_du_contexte(self) -> None:
        import inspect

        from sentimail_v3.observation import deep_hooks

        source = inspect.getsource(deep_hooks.SenderRelationHook._constat)
        self.assertIn("organisations", source)


class AutorisationVisibleDuHookTests(unittest.TestCase):
    """Les indices d'historique naissent après les hooks : ils doivent leur être
    montrés quand même, sinon un expéditeur explicitement autorisé est vérifié
    comme un inconnu."""

    def test_l_autorisation_explicite_est_visible_avant_les_hooks(self) -> None:
        codes = deep_analysis._history_clue_codes({"persistent_allow": True}, None)
        self.assertIn("AUTHENTICATED_SENDER_ALLOW", codes)

    def test_un_expediteur_confirme_est_visible_avant_les_hooks(self) -> None:
        codes = deep_analysis._history_clue_codes(
            {"ground_truth_labels": {"legitimate": 5}}, None
        )
        self.assertIn("HISTORY_CONFIRMED_LEGITIMATE_SENDER", codes)

    def test_sans_historique_aucune_autorisation(self) -> None:
        codes = deep_analysis._history_clue_codes({}, None)
        self.assertNotIn("AUTHENTICATED_SENDER_ALLOW", codes)
        self.assertNotIn("HISTORY_CONFIRMED_LEGITIMATE_SENDER", codes)
