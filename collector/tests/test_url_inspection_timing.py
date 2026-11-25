from __future__ import annotations

import asyncio
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

from sentimail_v3.observation import deep_analysis


class _Pool:
    """Retient les insertions plutôt que de les écrire."""

    def __init__(self) -> None:
        self.insertions: list[tuple[Any, ...]] = []

    async def execute(self, query: str, *args: Any) -> str:
        self.insertions.append((query, *args))
        return "INSERT 1"


class DureeMesureeTests(unittest.IsolatedAsyncioTestCase):
    """La durée d'une inspection n'était jamais mesurée.

    Les colonnes existaient et étaient remplies - avec la même valeur, posée à
    l'écriture. Sur 3704 inspections, 63 avaient une durée exploitable. C'est
    ce qui a rendu invisible une fermeture TLS de trente secondes par URL :
    aucune trace d'erreur, et aucune durée pour la contredire.
    """

    async def test_le_debut_reel_est_enregistre_et_non_l_heure_d_ecriture(self) -> None:
        pool = _Pool()
        debut = datetime.now(timezone.utc) - timedelta(seconds=12)
        await deep_analysis._save_analysis(
            pool,  # type: ignore[arg-type]
            "11111111-1111-1111-1111-111111111111",
            "url",
            "cle",
            "url-sandbox",
            "ok",
            {"initial_url": "https://exemple.fr/"},
            started_at=debut,
        )
        self.assertTrue(pool.insertions)
        arguments = pool.insertions[0]
        self.assertIn(debut, arguments, "le début réel n'est pas transmis")

    async def test_sans_debut_fourni_l_insertion_reste_possible(self) -> None:
        # Les chemins qui ne mesurent rien - une URL sautée - ne doivent pas
        # échouer pour autant.
        pool = _Pool()
        await deep_analysis._save_analysis(
            pool,  # type: ignore[arg-type]
            "11111111-1111-1111-1111-111111111111",
            "url",
            "cle",
            "url-sandbox",
            "skipped",
            {"analysis_skipped": True},
        )
        self.assertTrue(pool.insertions)

    async def test_la_requete_ecrit_les_deux_bornes(self) -> None:
        pool = _Pool()
        await deep_analysis._save_analysis(
            pool,  # type: ignore[arg-type]
            "11111111-1111-1111-1111-111111111111",
            "url",
            "cle",
            "url-sandbox",
            "ok",
            {},
            started_at=datetime.now(timezone.utc),
        )
        requete = str(pool.insertions[0][0])
        self.assertIn("started_at", requete)
        self.assertIn("completed_at", requete)


class ChronoDeLInspectionSeuleTests(unittest.IsolatedAsyncioTestCase):
    """La durée enregistrée est celle d'une tentative, jamais celle de la file.

    Le 9 novembre, un message portait vingt liens d'un même apex. Ils passent
    un par un, et le chrono démarrait avant l'attente : treize liens ont
    dépassé 45 s alors que le plus long n'avait travaillé que 12,6 s. Le
    superviseur est resté dégradé une heure sans aucune panne.
    """

    MESSAGE = "11111111-1111-1111-1111-111111111111"

    @staticmethod
    def _candidats(nombre: int) -> list[dict[str, str]]:
        return [
            {"url": f"https://exemple.fr/{rang}", "role": "html_link",
             "link_context": "primary", "visible_text": f"Document {rang}"}
            for rang in range(nombre)
        ]

    async def _analyser(
        self, candidats: list[dict[str, str]], faux_fetch: Any, *, budget: float = 5.0,
    ) -> list[tuple[str, datetime | None, datetime]]:
        enregistrements: list[tuple[str, datetime | None, datetime]] = []

        async def enregistrer(pool, message, kind, key, source, status, data,
                              failure=None, started_at=None):
            enregistrements.append((status, started_at, datetime.now(timezone.utc)))

        pool = SimpleNamespace(fetchrow=AsyncMock(return_value=None), execute=AsyncMock())
        reglages = SimpleNamespace(url_analysis_concurrency=2, url_analysis_deadline_seconds=budget)
        with patch.object(deep_analysis, "_message_url_candidates", return_value=(candidats, 0)), patch.object(
            deep_analysis, "_select_url_candidates", return_value=(candidats, {})
        ), patch.object(
            deep_analysis, "_message_is_dmarc_aligned", AsyncMock(return_value=False)
        ), patch.object(deep_analysis, "_fetch_url_analysis", faux_fetch), patch.object(
            deep_analysis, "_save_analysis", enregistrer
        ), patch.object(deep_analysis, "should_compare_profiles", return_value=False):
            await deep_analysis._analyze_urls(pool, None, reglages, self.MESSAGE, b"raw")  # type: ignore[arg-type]
        return enregistrements

    async def test_l_attente_de_la_file_n_entre_pas_dans_la_duree(self) -> None:
        async def faux_fetch(client, settings, url, key):
            await asyncio.sleep(0.05)
            return {"initial_url": url, "initial_apex": "exemple.fr"}, "ok", None

        lignes = await self._analyser(self._candidats(5), faux_fetch)

        durees = [(fin - debut).total_seconds() for _, debut, fin in lignes if debut]
        self.assertEqual(len(durees), 5)
        # Cinq liens en série : le dernier attend 0,20 s avant de travailler 0,05 s.
        self.assertLess(max(durees), 0.15, "l'attente de la file est comptée")

    async def test_un_rejeu_n_additionne_pas_ses_deux_tentatives(self) -> None:
        appels = 0

        async def faux_fetch(client, settings, url, key):
            nonlocal appels
            appels += 1
            if appels == 1:
                await asyncio.sleep(0.2)
                return {"initial_url": url, "initial_apex": "exemple.fr", "error": "hop_timeout"}, "ok", None
            return {"initial_url": url, "initial_apex": "exemple.fr"}, "ok", None

        lignes = await self._analyser(self._candidats(1), faux_fetch)

        self.assertEqual(appels, 2)
        _, debut, fin = lignes[0]
        self.assertIsNotNone(debut)
        self.assertLess((fin - debut).total_seconds(), 0.1, "les deux tentatives sont additionnées")

    async def test_un_blocage_du_bac_a_sable_reste_visible_si_le_rejeu_reussit(self) -> None:
        # Le délai de 45 s du client signifie que le plafond n'a pas tenu. C'est
        # le cas que le compteur existe pour voir : le rejeu ne doit pas l'effacer.
        appels = 0

        async def faux_fetch(client, settings, url, key):
            nonlocal appels
            appels += 1
            if appels == 1:
                await asyncio.sleep(0.2)
                return {"initial_url": url, "initial_apex": "exemple.fr",
                        "analysis_incomplete": True, "error": "sandbox_request:ReadTimeout"}, "error", TimeoutError()
            return {"initial_url": url, "initial_apex": "exemple.fr"}, "ok", None

        lignes = await self._analyser(self._candidats(1), faux_fetch)

        self.assertEqual(appels, 2)
        _, debut, fin = lignes[0]
        self.assertIsNotNone(debut)
        self.assertGreaterEqual((fin - debut).total_seconds(), 0.2, "le blocage du bac à sable a disparu")

    async def test_un_lien_jamais_inspecte_n_a_pas_de_duree(self) -> None:
        # Le budget expire pendant l'attente : ce lien n'a rien coûté au bac à
        # sable, il ne doit pas passer pour une inspection de plusieurs dizaines
        # de secondes. Son absence reste visible par son statut d'erreur.
        async def faux_fetch(client, settings, url, key):
            await asyncio.Event().wait()

        lignes = await self._analyser(self._candidats(3), faux_fetch, budget=0.05)

        self.assertEqual([statut for statut, _, _ in lignes], ["error"] * 3)
        self.assertEqual(sum(debut is None for _, debut, _ in lignes), 2,
                         "un lien resté dans la file a reçu une durée")
        self.assertEqual(sum(debut is not None for _, debut, _ in lignes), 1,
                         "le lien coupé en plein travail doit garder sa durée")


class RejeuQuiNeSObstinePasTests(unittest.IsolatedAsyncioTestCase):
    """Rejouer un apex qui vient de se taire double le coût pour rien.

    Le rejeu existe parce qu'un aléa réseau est souvent passager. Mais quand le
    même apex vient déjà de rendre un délai, ce n'est plus un aléa : c'est un
    domaine durablement muet. Le 18 août, seize URL d'un même apex ont été
    inspectées deux fois chacune, sans jamais rien rapporter.
    """

    async def test_un_apex_deja_muet_n_est_pas_rejoue(self) -> None:
        appels: list[str] = []

        async def faux_fetch(client, settings, url, key):
            appels.append(url)
            return ({"initial_apex": "muet.fr", "error": "hop_timeout"}, "ok", None)

        original = deep_analysis._fetch_url_analysis
        deep_analysis._fetch_url_analysis = faux_fetch  # type: ignore[assignment]
        try:
            muets: set[str] = set()
            await deep_analysis.fetch_url_analysis_with_retry(
                None, None, "https://muet.fr/a", "k1", apex_deja_muets=muets  # type: ignore[arg-type]
            )
            premier = len(appels)
            await deep_analysis.fetch_url_analysis_with_retry(
                None, None, "https://muet.fr/b", "k2", apex_deja_muets=muets  # type: ignore[arg-type]
            )
            second = len(appels) - premier
        finally:
            deep_analysis._fetch_url_analysis = original  # type: ignore[assignment]

        self.assertEqual(premier, 2, "le premier délai mérite encore un rejeu")
        self.assertEqual(second, 1, "le second ne doit plus être rejoué")
        self.assertIn("muet.fr", muets)

    async def test_un_premier_delai_isole_reste_rejoue(self) -> None:
        appels: list[str] = []

        async def faux_fetch(client, settings, url, key):
            appels.append(url)
            return ({"initial_apex": "ponctuel.fr", "error": "hop_timeout"}, "ok", None)

        original = deep_analysis._fetch_url_analysis
        deep_analysis._fetch_url_analysis = faux_fetch  # type: ignore[assignment]
        try:
            await deep_analysis.fetch_url_analysis_with_retry(
                None, None, "https://ponctuel.fr/a", "k", apex_deja_muets=set()  # type: ignore[arg-type]
            )
        finally:
            deep_analysis._fetch_url_analysis = original  # type: ignore[assignment]
        self.assertEqual(len(appels), 2)

    async def test_un_succes_ne_declenche_aucun_rejeu(self) -> None:
        appels: list[str] = []

        async def faux_fetch(client, settings, url, key):
            appels.append(url)
            return ({"initial_apex": "vivant.fr", "final_host": "vivant.fr"}, "ok", None)

        original = deep_analysis._fetch_url_analysis
        deep_analysis._fetch_url_analysis = faux_fetch  # type: ignore[assignment]
        try:
            muets: set[str] = set()
            await deep_analysis.fetch_url_analysis_with_retry(
                None, None, "https://vivant.fr/a", "k", apex_deja_muets=muets  # type: ignore[arg-type]
            )
        finally:
            deep_analysis._fetch_url_analysis = original  # type: ignore[assignment]
        self.assertEqual(len(appels), 1)
        self.assertEqual(muets, set())

    async def test_sans_memoire_d_apex_le_comportement_reste_l_ancien(self) -> None:
        # Les appelants qui ne passent pas la mémoire gardent le rejeu simple.
        appels: list[str] = []

        async def faux_fetch(client, settings, url, key):
            appels.append(url)
            return ({"initial_apex": "muet.fr", "error": "hop_timeout"}, "ok", None)

        original = deep_analysis._fetch_url_analysis
        deep_analysis._fetch_url_analysis = faux_fetch  # type: ignore[assignment]
        try:
            await deep_analysis.fetch_url_analysis_with_retry(
                None, None, "https://muet.fr/a", "k"  # type: ignore[arg-type]
            )
        finally:
            deep_analysis._fetch_url_analysis = original  # type: ignore[assignment]
        self.assertEqual(len(appels), 2)


if __name__ == "__main__":
    unittest.main()
