"""Une recherche en panne n'est pas une recherche vide.

Le 15 septembre 2026 vers 08 h UTC, le moteur de recherche s'est mis à refuser
la clé de production (401). Pendant deux jours, chaque question posée dehors a
rendu une liste vide, que rien ne distinguait d'une absence de réponse :
« Amazon » n'avait plus de domaine officiel (M-373976, faux reçu Prime Video
depuis un installateur de portes de garage : DEEP-022 jamais posé, juge en
doute au lieu de rejeter), et six expéditeurs, dont des newsletters connues,
ont reçu « personne ne répond publiquement de ce domaine », le fait qui
nourrit CORR-014. Le superviseur n'a rien vu : il compte le crédit du juge,
pas le moteur de recherche.

Ces tests tiennent les quatre couches : le moteur dit la panne, le rapport
l'écrit, l'enquêteur la note sans accuser, le superviseur la compte.
"""

from __future__ import annotations

import json
import unittest
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import httpx

from sentimail_v3.observation import deep_analysis, organisation_search
from sentimail_v3.observation.deep_hooks import SenderRelationHook, SenderActivityHook
from sentimail_v3.observation.organisation_search import SearchUnavailable
from sentimail_v3.supervision import watchdog
from sentimail_v3.supervision.watchdog_letter import lettre
from tests.test_watchdog import _SnapshotPool, _snapshot_settings

_URL = "https://api.exemple.test/search"


class _Settings:
    search_api_key = "cle"
    search_base_url = "https://api.exemple.test"


class _Client:
    """Un client HTTP qui répond ce qu'on lui dit, ou qui tombe."""

    def __init__(self, status: int | None = None, payload: object = None, exc: Exception | None = None) -> None:
        self.status = status
        self.payload = payload
        self.exc = exc

    async def post(self, url: str, **_: Any) -> httpx.Response:
        if self.exc is not None:
            raise self.exc
        return httpx.Response(
            int(self.status or 200),
            json=self.payload,
            request=httpx.Request("POST", url),
        )


class _Pool:
    """Une mémoire de recherche vide : chaque question part dehors."""

    def __init__(self) -> None:
        self.ecrit: list[tuple[object, ...]] = []

    async def fetchrow(self, *_: object) -> None:
        return None

    async def execute(self, *args: object) -> None:
        self.ecrit.append(args)


class LeMoteurDitLaPanneTests(unittest.IsolatedAsyncioTestCase):
    async def test_une_cle_refusee_est_une_panne_durable(self) -> None:
        for statut in (401, 403, 432):
            with self.subTest(statut=statut):
                with self.assertRaises(SearchUnavailable) as trouve:
                    await organisation_search._search(_Client(statut, {"detail": "no"}), _Settings(), "Amazon")
                self.assertEqual(trouve.exception.kind, "rejected")

    async def test_une_erreur_passagere_est_une_panne_passagere(self) -> None:
        cas = {
            "5xx": _Client(503, {}),
            "delai": _Client(exc=httpx.ReadTimeout("trop long")),
            "reseau": _Client(exc=httpx.ConnectError("injoignable")),
        }
        for nom, client in cas.items():
            with self.subTest(cas=nom):
                with self.assertRaises(SearchUnavailable) as trouve:
                    await organisation_search._search(client, _Settings(), "Amazon")
                self.assertEqual(trouve.exception.kind, "error")

    async def test_une_reponse_vide_reste_une_absence_de_reponse(self) -> None:
        # C'est le silence légitime : le moteur a répondu, il n'a rien à dire.
        resultats = await organisation_search._search(_Client(200, {"results": []}), _Settings(), "Grange Immobilier")
        self.assertEqual(resultats, [])

    async def test_sans_cle_configuree_rien_ne_part_et_rien_ne_tombe(self) -> None:
        # Le cas « pas de clé » est déjà écrit par l'enquêteur comme non
        # vérifié ; il ne doit pas devenir une panne comptée comme un refus.
        resultats = await organisation_search._search(
            _Client(exc=AssertionError("ne doit pas appeler")),
            SimpleNamespace(search_api_key="", search_base_url=_Settings.search_base_url),
            "Amazon",
        )
        self.assertEqual(resultats, [])

    async def test_la_panne_traverse_la_memoire_et_ne_s_y_inscrit_pas(self) -> None:
        pool = _Pool()
        with self.assertRaises(SearchUnavailable):
            await organisation_search.about_name(pool, _Client(401, {}), _Settings(), "Amazon")  # type: ignore[arg-type]
        with self.assertRaises(SearchUnavailable):
            await organisation_search.about_domain(pool, _Client(401, {}), _Settings(), "thegaragedoorcompany.ltd.uk")  # type: ignore[arg-type]
        self.assertEqual(pool.ecrit, [], "une panne ne se garde pas un mois comme une absence de réponse")


class LeRapportEcritLaPanneTests(unittest.IsolatedAsyncioTestCase):
    async def _rapport(self, *, nom_tombe: bool, domaine_tombe: bool):
        async def _about_name(*_: Any, **__: Any):
            if nom_tombe:
                raise SearchUnavailable("rejected", "HTTP 401")
            return [{"title": "Amazon", "url": "https://amazon.fr/", "content": "Boutique."}], ["amazon.fr"]

        async def _about_domain(*_: Any, **__: Any):
            if domaine_tombe:
                raise SearchUnavailable("rejected", "HTTP 401")
            return []

        async def _chat(*_: Any, **__: Any):
            raise AssertionError("le modèle ne doit pas être interrogé sur du vide")

        with patch.object(deep_analysis, "_log", lambda *a, **k: None), patch.object(
            deep_analysis, "provider_chat_json", _chat
        ), patch("sentimail_v3.observation.organisation_search.about_name", _about_name), patch(
            "sentimail_v3.observation.organisation_search.about_domain", _about_domain
        ):
            return await deep_analysis._identity_relation(
                None, None, _Settings(), display_name="Amazon", from_apex="thegaragedoorcompany.ltd.uk"
            )

    async def test_le_nom_introuvable_par_panne_n_est_pas_cherche(self) -> None:
        clue, facts = await self._rapport(nom_tombe=True, domaine_tombe=True)
        self.assertIsNone(clue)
        self.assertFalse(facts["searched"])
        self.assertEqual(facts["search_unavailable"], "rejected")

    async def test_le_domaine_introuvable_par_panne_n_est_pas_juge(self) -> None:
        # Le nom sortait de la mémoire, le domaine devait partir dehors : la
        # question au modèle n'a pas de matière, elle ne se pose pas.
        clue, facts = await self._rapport(nom_tombe=False, domaine_tombe=True)
        self.assertIsNone(clue)
        self.assertFalse(facts["searched"])
        self.assertEqual(facts["search_unavailable"], "rejected")
        self.assertEqual(facts["official_apexes"], ["amazon.fr"])


TEXTE_PRIME = (
    "prime Confirmation de commande Votre abonnement à Prime Video a été "
    "renouvelé Gérer votre abonnement Vendu par : Amazon Digital Services LLC "
    "Total facturé 69,90 EUR"
)


def _contexte(**surcharges: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "pool": None,
        "client": None,
        "settings": SimpleNamespace(search_api_key="cle"),
        "message_id": "m",
        "clue_codes": set(),
        "sender_apex": "thegaragedoorcompany.ltd.uk",
        "from_domain": "thegaragedoorcompany.ltd.uk",
        "subject": "MARTIN Merci pour votre renouvellement",
        "body": TEXTE_PRIME,
        "display_name": "Formule Annuelle",
        "recipient": "amartin@example.org",
        "sender_site": None,
        "organisations": {},
        "sender_attested": False,
        "message_purpose": "payment",
    }
    base.update(surcharges)
    return SimpleNamespace(**base)


class _Monde:
    """Ce que l'extérieur répond à l'enquêteur pendant la panne."""

    def __init__(self, *, relation: dict[str, object], domaine_tombe: str | None, coherence: dict[str, object] | None = None) -> None:
        self.relation = relation
        self.domaine_tombe = domaine_tombe
        self.coherence = coherence
        self.appels: list[str] = []

    async def _claimed(self, *_: Any, **__: Any):
        return "Amazon", {"asked": True, "read": "Amazon"}

    async def _relation(self, *_: Any, **__: Any):
        self.appels.append("relation")
        return None, dict(self.relation)

    async def _about_domain(self, *_: Any, **__: Any):
        self.appels.append("about_domain")
        if self.domaine_tombe:
            raise SearchUnavailable(self.domaine_tombe, "HTTP 401")
        return []

    async def _coherence(self, *_: Any, **__: Any):
        self.appels.append("coherence")
        return self.coherence

    async def run(self, contexte: SimpleNamespace):
        with patch.object(deep_analysis, "_claimed_organisation", self._claimed), patch.object(
            deep_analysis, "_identity_relation", self._relation
        ), patch.object(deep_analysis, "_activity_coherence", self._coherence), patch(
            "sentimail_v3.observation.organisation_search.about_domain", self._about_domain
        ):
            clues, facts = await SenderRelationHook().observe(contexte)  # type: ignore[arg-type]
            if contexte.sender_site:
                activity, _ = await SenderActivityHook().observe(contexte)
                clues.extend(activity)
        self.facts = facts
        return clues


PANNE = {"searched": False, "error": True, "search_unavailable": "rejected"}
INCOHERENT = {
    "clue_code": "SENDER_ACTIVITY_INCOHERENT",
    "article_code": "DEEP-019",
    "direction": "adverse",
    "strength": 55,
    "confidence": 0.75,
    "statement": "Le propos de ce message est étranger à l’activité que son expéditeur publie.",
    "facts": {},
}


class LEnqueteurNoteSansAccuserTests(unittest.IsolatedAsyncioTestCase):
    async def test_la_panne_s_ecrit_non_verifiee_jamais_sans_repondant(self) -> None:
        """M-373976 sans site lisible : le vide n'est pas un vide, c'est une
        panne. « Sans répondant » nourrirait CORR-014 sur une clé morte."""
        monde = _Monde(relation=PANNE, domaine_tombe="rejected")
        clues = await monde.run(_contexte())
        self.assertEqual([c["clue_code"] for c in clues], ["SENDER_RELATION_UNVERIFIED"])
        self.assertEqual(clues[0]["direction"], "neutral")
        self.assertIn("search_rejected", clues[0]["facts"]["reason"])
        self.assertEqual(monde.facts["search_unavailable"], "rejected")
        self.assertEqual(monde.facts["outcome"], "SENDER_RELATION_UNVERIFIED")

    async def test_une_panne_connue_ne_repart_pas_dehors(self) -> None:
        # Le rapport a déjà constaté le refus : l'enquêteur ne rappelle pas le
        # moteur pour le domaine, il tomberait pareil.
        monde = _Monde(relation=PANNE, domaine_tombe="rejected")
        await monde.run(_contexte())
        self.assertNotIn("about_domain", monde.appels)

    async def test_le_site_lu_directement_confronte_encore_le_metier(self) -> None:
        """Ce qui a marché sur M-373976 doit continuer de marcher : la page
        d'accueil n'a pas besoin du moteur, DEEP-019 se pose, et la panne
        reste inscrite aux faits pour le superviseur."""
        monde = _Monde(relation=PANNE, domaine_tombe="rejected", coherence=dict(INCOHERENT))
        clues = await monde.run(
            _contexte(sender_site={"apex": "thegaragedoorcompany.ltd.uk", "text": "The Garage Door Company | Best Garage Doors Near Me | UK. Supply and fit garage doors across the country."})
        )
        self.assertEqual([c["clue_code"] for c in clues], ["SENDER_RELATION_UNVERIFIED", "SENDER_ACTIVITY_INCOHERENT"])
        self.assertEqual(monde.facts["search_unavailable"], "rejected")

    async def test_une_panne_passagere_s_ecrit_aussi(self) -> None:
        monde = _Monde(relation={"searched": False, "error": True, "search_unavailable": "error"}, domaine_tombe="error")
        clues = await monde.run(_contexte())
        self.assertEqual(clues[0]["clue_code"], "SENDER_RELATION_UNVERIFIED")
        self.assertEqual(monde.facts["search_unavailable"], "error")

    async def test_une_panne_sur_le_seul_domaine_s_ecrit_aussi(self) -> None:
        # Sans organisation revendiquée, seule la recherche sur le domaine part :
        # si elle tombe, le constat est « non vérifié », pas « sans répondant ».
        async def _rien(*_: Any, **__: Any):
            return "", {"asked": True}

        monde = _Monde(relation=PANNE, domaine_tombe="rejected")
        monde._claimed = _rien  # type: ignore[method-assign]
        clues = await monde.run(_contexte(display_name="", body="Bonjour, votre abonnement est renouvelé."))
        self.assertEqual(clues[0]["clue_code"], "SENDER_RELATION_UNVERIFIED")
        self.assertEqual(monde.facts["search_unavailable"], "rejected")

    async def test_une_recherche_vide_reste_un_vide(self) -> None:
        # Le moteur a répondu qu'il ne savait rien : c'est le constat neutre
        # d'hier, inchangé.
        monde = _Monde(
            relation={"searched": True, "results_on_name": 0, "results_on_domain": 0, "official_apexes": [], "rapport": None},
            domaine_tombe=None,
        )
        clues = await monde.run(_contexte())
        self.assertEqual(clues[0]["clue_code"], "SENDER_WITHOUT_PUBLIC_FOOTPRINT")
        self.assertNotIn("search_unavailable", monde.facts)


class LeSuperviseurCompteTests(unittest.IsolatedAsyncioTestCase):
    async def test_une_cle_refusee_sonne_au_premier_refus(self) -> None:
        pool = _SnapshotPool(organisation_search_rejected=1)
        snapshot = await watchdog._snapshot(
            pool,  # type: ignore[arg-type]
            _snapshot_settings(),
            previously_observed=frozenset({"organisation_search_rejected"}),
        )
        self.assertEqual(snapshot["details"]["organisation_search_rejected"], 1)
        self.assertIn("organisation_search_rejected", snapshot["details"]["reasons"])
        self.assertEqual(snapshot["status"], "degraded")

    async def test_une_panne_qui_dure_ne_reveille_pas_l_alerte_a_chaque_nom(self) -> None:
        """Le signal est un état : quatre refus depuis le dernier succès valent
        1, et le nombre reste au détail. Un compteur qui grimpe à chaque nom
        cherché relancerait l'alerte tant que la clé est morte."""
        pool = _SnapshotPool(organisation_search_rejected=4)
        snapshot = await watchdog._snapshot(pool, _snapshot_settings())  # type: ignore[arg-type]
        self.assertEqual(snapshot["details"]["organisation_search_rejected"], 1)
        self.assertEqual(snapshot["details"]["organisation_search_rejections"], 4)
        self.assertNotIn("organisation_search_rejected", watchdog.SOFT_FAILURE_COUNTERS)
        self.assertIn("organisation_search_errors_last_hour", watchdog.SOFT_FAILURE_COUNTERS)

    async def test_les_erreurs_passageres_sonnent_a_trois(self) -> None:
        for valeur, attendu in ((2, False), (3, True)):
            with self.subTest(valeur=valeur):
                pool = _SnapshotPool(organisation_search_errors_last_hour=valeur)
                snapshot = await watchdog._snapshot(
                    pool,  # type: ignore[arg-type]
                    _snapshot_settings(),
                    previously_observed=frozenset({"organisation_search_errors_last_hour"}),
                )
                self.assertEqual(
                    "organisation_search_errors_last_hour" in snapshot["details"]["reasons"], attendu
                )

    async def test_sans_panne_rien_ne_sonne(self) -> None:
        snapshot = await watchdog._snapshot(_SnapshotPool(), _snapshot_settings())  # type: ignore[arg-type]
        self.assertEqual(snapshot["details"]["organisation_search_rejected"], 0)
        self.assertEqual(snapshot["details"]["organisation_search_errors_last_hour"], 0)
        self.assertNotIn("organisation_search_rejected", snapshot["details"]["reasons"])

    def test_le_refus_se_lit_apres_le_dernier_succes(self) -> None:
        """Un état, pas un compteur : il retombe seul à la première recherche
        qui rend au moins un résultat (seule celle-là s'inscrit dans la
        mémoire) et ne clignote pas quand une heure passe sans recherche
        neuve."""
        import inspect

        source = inspect.getsource(watchdog._snapshot)
        self.assertIn("organisation_search_rejected", source)
        self.assertIn("search_lookups", source)


class LaLettreDitQuoiFaireTests(unittest.TestCase):
    def test_la_cle_refusee_se_dit_en_mots_simples_avec_le_geste(self) -> None:
        details = {"reasons": ["organisation_search_rejected"], "organisation_search_rejected": 4}
        texte = lettre("degraded", details).text
        self.assertNotIn("le signal «", texte)
        self.assertIn("moteur de recherche", texte)
        self.assertIn("search_api_key", texte)
        self.assertIn("verdict", texte)

    def test_les_erreurs_passageres_se_disent_aussi(self) -> None:
        details = {"reasons": ["organisation_search_errors_last_hour"], "organisation_search_errors_last_hour": 3}
        texte = lettre("degraded", details).text
        self.assertNotIn("le signal «", texte)
        self.assertIn("moteur de recherche", texte)


if __name__ == "__main__":
    unittest.main()
