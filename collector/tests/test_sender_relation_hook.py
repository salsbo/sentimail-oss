"""L'enquêteur qui confronte toujours le domaine réel à ce que le message dit.

Il remplace `identity_claim` et `activity_coherence`, dont les conditions de
saut étaient la faille : nom qui ne désigne rien, site muet, expéditeur connu,
et rien n'entrait au dossier. Ici, quoi qu'il arrive, un constat sort.
"""

from __future__ import annotations

import json
import unittest
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from sentimail_v3.observation import deep_analysis, deep_hooks
from sentimail_v3.observation.deep_hooks import DEEP_HOOKS, SenderRelationHook, SenderActivityHook

TEXTE_PRIME = (
    "prime CONFIRMÉ Votre paiement a été accepté Bonjour MARTIN ALICE "
    "Montant 69,90 € Prime Famille — Abonnement annuel activé "
    "Gérer mon abonnement Annulation possible sous 14 jours."
)
SITE_ECOLE = "English school for international students in Sydney, Australia."


def _contexte(**surcharges: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "pool": None,
        "client": None,
        "settings": SimpleNamespace(search_api_key="cle"),
        "message_id": "m",
        "clue_codes": set(),
        "sender_apex": "mozn.space",
        "from_domain": "mozn.space",
        "subject": "ALICE, Achat confirmé, votre abonnement a été renouvelé",
        "body": TEXTE_PRIME,
        "display_name": "Annuel-Famille",
        "sender_site": None,
        "organisations": {},
        "sender_attested": False,
        "message_purpose": "financial_transfer",
    }
    base.update(surcharges)
    return SimpleNamespace(**base)


class _Scenario:
    """Ce que le monde extérieur répond, et ce qu'on lui a demandé."""

    def __init__(
        self,
        *,
        claim: str | None = "",
        relation: tuple[dict[str, object] | None, dict[str, object]] = (None, {}),
        coherence: dict[str, object] | None = None,
        domain_results: list[dict[str, object]] | None = None,
        panne: bool = False,
    ) -> None:
        self.claim = claim
        self.relation = relation
        self.coherence = coherence
        self.domain_results = domain_results or []
        self.panne = panne
        self.appels: list[str] = []

    async def _claimed(self, *_: Any, **__: Any) -> tuple[str, dict[str, object]]:
        self.appels.append("claim")
        if self.panne:
            raise RuntimeError("modèle injoignable")
        return self.claim or "", {"asked": True}

    async def _relation(self, *_: Any, **kwargs: Any):
        self.appels.append("relation:" + str(kwargs.get("display_name")))
        return self.relation

    async def _coherence(self, *_: Any, **__: Any):
        self.appels.append("coherence")
        if self.panne:
            return None
        return self.coherence

    async def _about_domain(self, *_: Any, **__: Any):
        self.appels.append("about_domain")
        return self.domain_results

    async def run(self, contexte: SimpleNamespace, *, activity: bool = False) -> list[dict[str, object]]:
        with patch.object(deep_analysis, "_claimed_organisation", self._claimed), patch.object(
            deep_analysis, "_identity_relation", self._relation
        ), patch.object(deep_analysis, "_activity_coherence", self._coherence), patch(
            "sentimail_v3.observation.organisation_search.about_domain", self._about_domain
        ):
            clues, facts = await (SenderActivityHook() if activity else SenderRelationHook()).observe(contexte)  # type: ignore[arg-type]
        self.facts = facts
        return clues


REFUTE = {
    "clue_code": "IDENTITY_CLAIMED_ORGANISATION_REFUTED",
    "article_code": "DEEP-022",
    "direction": "adverse",
    "strength": 50,
    "confidence": 0.75,
    "statement": "Le message se présente au nom de Prime Famille, mais il est envoyé depuis un domaine qui ne lui appartient pas.",
    "facts": {"official_apexes": ["primevideo.com"]},
}


class RegistreTests(unittest.TestCase):
    def test_l_enqueteur_remplace_les_deux_anciens(self) -> None:
        noms = [hook.name for hook in DEEP_HOOKS]
        self.assertIn("sender_relation", noms)
        self.assertNotIn("identity_claim", noms)
        self.assertNotIn("activity_coherence", noms)

    def test_aucun_enqueteur_ne_va_chercher_le_site_lui_meme(self) -> None:
        import inspect

        self.assertNotIn("_sender_site(", inspect.getsource(deep_hooks))


class ToujoursUnConstatTests(unittest.IsolatedAsyncioTestCase):
    async def test_la_marque_ecrite_dans_le_corps_est_confrontee_au_domaine(self) -> None:
        """M-a9e895 : « Prime Famille » dans le corps, « Annuel-Famille » en nom
        affiché. La confrontation part du corps et rend le démenti."""
        scenario = _Scenario(claim="Prime Famille", relation=(dict(REFUTE), {"searched": True}))
        clues = await scenario.run(_contexte())
        self.assertEqual([c["clue_code"] for c in clues], ["IDENTITY_CLAIMED_ORGANISATION_REFUTED"])
        self.assertIn("relation:Prime Famille", scenario.appels)
        self.assertEqual(scenario.facts["claimed_organisation"], "Prime Famille")
        self.assertEqual(scenario.facts["claim_source"], "content")

    async def test_une_organisation_que_le_message_n_ecrit_pas_est_ignoree(self) -> None:
        # Le modèle lit « Amazon Prime » là où seul « prime » est écrit : Amazon
        # est sa lecture, pas une revendication. On retombe sur le nom affiché.
        scenario = _Scenario(claim="Amazon Prime", relation=(None, {"searched": True, "results_on_name": 0, "results_on_domain": 0, "official_apexes": []}))
        clues = await scenario.run(_contexte())
        self.assertNotIn("relation:Amazon Prime", scenario.appels)
        self.assertIn("relation:Annuel-Famille", scenario.appels)
        self.assertEqual(clues[0]["clue_code"], "SENDER_WITHOUT_PUBLIC_FOOTPRINT")

    async def test_sans_repondant_le_vide_est_ecrit(self) -> None:
        """Nom générique, aucune organisation dans le corps, site muet, recherche
        vide : le silence d'hier devient un fait neutre."""
        scenario = _Scenario(
            claim=None,
            relation=(None, {"searched": True, "results_on_name": 0, "results_on_domain": 0, "official_apexes": []}),
        )
        clues = await scenario.run(_contexte(body="Bonjour, votre abonnement est renouvelé."))
        self.assertEqual(len(clues), 1)
        self.assertEqual(clues[0]["clue_code"], "SENDER_WITHOUT_PUBLIC_FOOTPRINT")
        self.assertEqual(clues[0]["direction"], "neutral")
        self.assertEqual(scenario.facts["outcome"], "SENDER_WITHOUT_PUBLIC_FOOTPRINT")

    async def test_un_nom_qui_reprend_le_domaine_concorde_sans_recherche(self) -> None:
        scenario = _Scenario(claim="Synology")
        clues = await scenario.run(
            _contexte(sender_apex="synology.com", display_name="Synology News", body="Nouveautés DSM 8.")
        )
        self.assertEqual(clues[0]["clue_code"], "SENDER_RELATION_CONSISTENT")
        self.assertNotIn("relation:Synology", scenario.appels)

    async def test_un_domaine_attribue_par_la_recherche_concorde(self) -> None:
        scenario = _Scenario(claim="Doctolib", relation=(None, {"searched": True, "cleared": True, "official_apexes": ["doctolib.fr"]}))
        clues = await scenario.run(
            _contexte(sender_apex="doctolib-mail.fr", display_name="Doctolib", body="Votre rendez-vous demain.")
        )
        self.assertEqual(clues[0]["clue_code"], "SENDER_RELATION_CONSISTENT")
        self.assertEqual(clues[0]["facts"]["how"], "search")

    async def test_une_organisation_trouvee_au_rapport_non_tranche_n_est_pas_un_vide(self) -> None:
        """La recherche a rendu les domaines de l'organisation, le modèle n'a pas
        su dire le rapport : « non vérifié », jamais « sans répondant », qui
        dirait au dossier que le nom ne désigne personne et nourrirait CORR-014."""
        scenario = _Scenario(
            claim="Banque Populaire",
            relation=(None, {"searched": True, "official_apexes": ["banquepopulaire.fr"], "rapport": None}),
        )
        clues = await scenario.run(
            _contexte(sender_apex="routeur-emailing.fr", body="Groupe Banque Populaire : votre relevé.")
        )
        self.assertEqual(clues[0]["clue_code"], "SENDER_RELATION_UNVERIFIED")
        self.assertEqual(clues[0]["facts"]["reason"], "relation_undetermined")

    async def test_un_rapport_reconnu_par_le_modele_concorde(self) -> None:
        scenario = _Scenario(
            claim="Banque Populaire",
            relation=(None, {"searched": True, "official_apexes": ["banquepopulaire.fr"], "rapport": True}),
        )
        clues = await scenario.run(
            _contexte(sender_apex="routeur-emailing.fr", body="Groupe Banque Populaire : votre relevé.")
        )
        self.assertEqual(clues[0]["clue_code"], "SENDER_RELATION_CONSISTENT")
        self.assertEqual(clues[0]["facts"]["how"], "model")

    async def test_le_nom_du_destinataire_n_est_jamais_une_organisation(self) -> None:
        # « Bonjour MARTIN ALICE » : un modèle qui prendrait le destinataire
        # pour une organisation enverrait son nom au moteur de recherche.
        scenario = _Scenario(claim="MARTIN ALICE", relation=(None, {"searched": True, "official_apexes": []}))
        clues = await scenario.run(_contexte(recipient="amartin@example.org"))
        self.assertNotIn("relation:MARTIN ALICE", scenario.appels)
        self.assertEqual(scenario.facts["claim_source"], "display_name")
        self.assertEqual(len(clues), 1)

    async def test_un_site_lisible_confronte_le_propos_au_metier(self) -> None:
        incoherent = {
            "clue_code": "SENDER_ACTIVITY_INCOHERENT",
            "article_code": "DEEP-019",
            "direction": "adverse",
            "strength": 55,
            "confidence": 0.75,
            "statement": "Une école de langue n'annonce pas de reçu Prime.",
            "facts": {},
        }
        scenario = _Scenario(claim=None, coherence=incoherent)
        clues = await scenario.run(
            _contexte(
                sender_apex="careerwiseenglish.com.au",
                display_name="Info",
                sender_site={"apex": "careerwiseenglish.com.au", "text": SITE_ECOLE},
            ),
            activity=True,
        )
        self.assertEqual(clues[0]["clue_code"], "SENDER_ACTIVITY_INCOHERENT")
        self.assertIn("coherence", scenario.appels)
        self.assertEqual(scenario.facts["activity_source"], "site")

    async def test_sans_site_la_recherche_sur_le_domaine_dit_le_metier(self) -> None:
        coherent = {
            "clue_code": "SENDER_ACTIVITY_COHERENT",
            "article_code": "DEEP-018",
            "direction": "favorable",
            "strength": 20,
            "confidence": 0.75,
            "statement": "Une école qui parle de cours.",
            "facts": {},
        }
        scenario = _Scenario(
            claim=None,
            coherence=coherent,
            domain_results=[{"title": "CareerWise English", "content": SITE_ECOLE, "url": "https://careerwiseenglish.com.au/"}],
        )
        clues = await scenario.run(
            _contexte(sender_apex="careerwiseenglish.com.au", display_name="Info", body="Vos cours reprennent lundi."),
            activity=True,
        )
        self.assertEqual(clues[0]["clue_code"], "SENDER_ACTIVITY_COHERENT")
        self.assertEqual(scenario.facts["activity_source"], "search")

    async def test_un_expediteur_connu_est_regarde_quand_meme(self) -> None:
        """Le serveur compromis : tout est authentique sauf le propos. C'est
        pour lui que le contrôle existe, et il le sautait."""
        scenario = _Scenario(claim=None, coherence=None, domain_results=[])
        clues = await scenario.run(
            _contexte(
                clue_codes={"HISTORY_CONFIRMED_LEGITIMATE_SENDER", "HISTORY_APEX_ESTABLISHED_LOCALLY"},
                sender_site={"apex": "mozn.space", "text": SITE_ECOLE},
            ),
            activity=True,
        )
        self.assertNotIn("claim", scenario.appels)
        self.assertIn("coherence", scenario.appels)
        self.assertEqual(len(clues), 1)

    async def test_une_panne_generale_rend_non_verifie_jamais_rien(self) -> None:
        scenario = _Scenario(panne=True)
        clues = await scenario.run(_contexte())
        self.assertEqual(len(clues), 1)
        self.assertEqual(clues[0]["clue_code"], "SENDER_RELATION_UNVERIFIED")
        self.assertEqual(clues[0]["direction"], "neutral")

    async def test_un_modele_muet_sur_le_metier_rend_non_verifie(self) -> None:
        # Site lisible, mais le modèle ne répond pas : ni charge ni décharge,
        # et surtout pas « sans répondant », qui nourrirait une convergence.
        scenario = _Scenario(claim=None, coherence=None)
        clues = await scenario.run(
            _contexte(display_name="Info", sender_site={"apex": "mozn.space", "text": SITE_ECOLE}),
            activity=True,
        )
        self.assertEqual(clues[0]["clue_code"], "SENDER_ACTIVITY_UNVERIFIED")

    async def test_l_attestation_locale_est_transmise(self) -> None:
        recu: dict[str, object] = {}

        async def _relation(*_: Any, **kwargs: Any):
            recu.update(kwargs)
            return None, {"searched": True, "cleared": True, "official_apexes": ["nintendo.com"]}

        scenario = _Scenario(claim="Nintendo")
        with patch.object(deep_analysis, "_identity_relation", _relation):
            with patch.object(deep_analysis, "_claimed_organisation", scenario._claimed), patch(
                "sentimail_v3.observation.organisation_search.about_domain", scenario._about_domain
            ):
                await SenderRelationHook().observe(  # type: ignore[arg-type]
                    _contexte(sender_apex="nintendo-europe.com", display_name="Nintendo", body="Nintendo Switch", sender_attested=True)
                )
        self.assertTrue(recu.get("attested_locally"))
        self.assertEqual(recu.get("from_domain"), "mozn.space")

    async def test_le_hook_ne_rend_jamais_une_liste_vide(self) -> None:
        scenarios = [
            _Scenario(),
            _Scenario(claim=None),
            _Scenario(claim="Prime Famille"),
            _Scenario(panne=True),
            _Scenario(claim=None, domain_results=[{"title": "x", "content": "y"}]),
        ]
        for scenario in scenarios:
            clues = await scenario.run(_contexte())
            with self.subTest(appels=scenario.appels):
                self.assertEqual(len(clues), 1)


if __name__ == "__main__":
    unittest.main()
