from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from typing import Any

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
