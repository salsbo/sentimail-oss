from __future__ import annotations

import json
import unittest
from typing import Any

from sentimail_v3.supervision import evaluation_report as report
from sentimail_v3.supervision.evaluation import ASK, DELIVER, JUNK


class _Pool:
    """Retient la requête et rend les lignes qu'on lui donne."""

    def __init__(self, rows: list[dict[str, Any]] | None = None) -> None:
        self.rows = rows or []
        self.queries: list[str] = []
        self.written: list[tuple[Any, ...]] = []

    async def fetch(self, query: str, *args: Any) -> list[dict[str, Any]]:
        self.queries.append(query)
        return self.rows

    async def execute(self, query: str, *args: Any) -> str:
        self.queries.append(query)
        self.written.append(args)
        return "INSERT 1"


class RequeteTests(unittest.IsolatedAsyncioTestCase):
    """L'issue se reconstruit depuis les événements, jamais depuis l'état.

    `delivery_cases.original_delivery_allowed` est mis à jour APRÈS la réponse
    de l'utilisateur : il raconte l'état final, pas la décision du moment. Une
    mesure bâtie dessus dirait qu'un message retenu puis libéré avait été livré
    d'emblée, et le taux de sollicitation tomberait à zéro. Seuls les
    événements de livraison sont immuables.
    """

    async def test_la_requete_lit_les_evenements_de_livraison(self) -> None:
        pool = _Pool()
        await report.collect(pool, days=30)  # type: ignore[arg-type]
        sql = pool.queries[0]
        self.assertIn("delivery_events", sql)
        self.assertIn("review_notice_delivered", sql)
        self.assertIn("original_filed_as_junk", sql)

    async def test_la_requete_n_utilise_pas_l_etat_mutable(self) -> None:
        pool = _Pool()
        await report.collect(pool, days=30)  # type: ignore[arg-type]
        sql = pool.queries[0]
        self.assertNotIn("original_delivery_allowed", sql)

    async def test_seule_la_verite_humaine_est_retenue(self) -> None:
        # Un jugement de modèle n'établit rien : le mesurer contre lui-même
        # produirait un accord parfait et vide de sens.
        pool = _Pool()
        await report.collect(pool, days=30)  # type: ignore[arg-type]
        sql = pool.queries[0]
        self.assertIn("is_ground_truth", sql)

    async def test_la_fenetre_est_un_parametre_lie(self) -> None:
        pool = _Pool()
        await report.collect(pool, days=7)  # type: ignore[arg-type]
        self.assertIn("$1", pool.queries[0])


class AssemblageTests(unittest.IsolatedAsyncioTestCase):
    """Le rapport porte ses conditions de validité, pas seulement ses taux."""

    async def _rapport(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        return await report.collect(_Pool(rows), days=30)  # type: ignore[arg-type]

    async def test_le_rapport_porte_la_couverture_avant_les_taux(self) -> None:
        rapport = await self._rapport(
            [{"outcome": DELIVER, "truth": None}] * 100
            + [{"outcome": ASK, "truth": "spam"}] * 3
        )
        self.assertIn("coverage", rapport)
        self.assertAlmostEqual(rapport["coverage"][DELIVER]["rate"], 0.0)

    async def test_le_rapport_contient_la_matrice_et_l_utilite(self) -> None:
        rapport = await self._rapport([{"outcome": JUNK, "truth": "spam"}] * 5)
        self.assertIn("matrix", rapport)
        self.assertIn("utility", rapport)
        self.assertIn("weights", rapport["utility"])

    async def test_le_risque_est_declare_comme_borne_basse(self) -> None:
        # Aucun sondage aléatoire n'existe encore : le rapport doit le dire.
        rapport = await self._rapport([{"outcome": DELIVER, "truth": "spam"}])
        self.assertTrue(rapport["generalized_risk"]["lower_bound_only"])

    async def test_un_corpus_vide_ne_fabrique_aucun_chiffre(self) -> None:
        rapport = await self._rapport([])
        self.assertEqual(rapport["matrix"]["total"], 0)
        self.assertIsNone(rapport["hold_precision"]["value"])
        self.assertIsNone(rapport["utility"]["normalised"])

    async def test_la_fenetre_est_rappelee_dans_le_rapport(self) -> None:
        rapport = await self._rapport([])
        self.assertEqual(rapport["window_days"], 30)


class PublicationTests(unittest.IsolatedAsyncioTestCase):
    """La mesure se publie là où l'état opérationnel se lit déjà."""

    async def test_le_rapport_est_publie_sous_son_propre_composant(self) -> None:
        pool = _Pool([{"outcome": DELIVER, "truth": "legitimate"}])
        await report.publish(pool, days=30)  # type: ignore[arg-type]
        self.assertIn("operational_status", " ".join(pool.queries))
        # Le nom du composant est un paramètre lié, pas du texte dans la
        # requête : c'est ce qui garantit qu'aucune valeur n'entre dans le SQL.
        self.assertIn(report.COMPONENT, [str(a) for args in pool.written for a in args])

    async def test_le_composant_ne_masque_pas_l_etat_general(self) -> None:
        # Écrire sous « sentimail-v3 » écraserait l'état du superviseur.
        self.assertNotEqual(report.COMPONENT, "sentimail-v3")

    async def test_la_mesure_n_est_jamais_un_etat_degrade(self) -> None:
        # Un taux d'erreur n'est pas une panne : le publier en « degraded »
        # ferait sonner l'alerte du superviseur pour une information de qualité.
        pool = _Pool([{"outcome": DELIVER, "truth": "spam"}] * 50)
        await report.publish(pool, days=30)  # type: ignore[arg-type]
        valeurs = [str(a) for args in pool.written for a in args]
        self.assertNotIn("degraded", valeurs)
        self.assertNotIn("down", valeurs)

    async def test_le_detail_publie_est_du_json_lisible(self) -> None:
        pool = _Pool([{"outcome": ASK, "truth": "spam"}])
        await report.publish(pool, days=30)  # type: ignore[arg-type]
        charge = next(
            (a for args in pool.written for a in args if isinstance(a, str) and "{" in a),
            None,
        )
        self.assertIsNotNone(charge)
        decode = json.loads(str(charge))
        self.assertIn("matrix", decode)
        self.assertIn("coverage", decode)



class BranchementTests(unittest.IsolatedAsyncioTestCase):
    """La mesure doit tourner d'elle-même, sinon elle n'existe pas.

    Le caretaker est déjà le service d'auto-évaluation : il tourne à intervalle
    long, il lit déjà les désaccords humain/modèle. La mesure y a sa place,
    plutôt que dans le superviseur qui passe toutes les minutes pour surveiller
    l'intégrité du flux.
    """

    def test_le_caretaker_publie_la_mesure_a_chaque_cycle(self) -> None:
        import inspect

        from sentimail_v3.supervision import caretaker

        source = inspect.getsource(caretaker.main)
        self.assertIn("publish_evaluation", source)

    def test_un_echec_de_mesure_n_arrete_pas_l_entretien(self) -> None:
        # Mesurer n'est jamais critique : une erreur ici ne doit pas empêcher
        # le rejeu des verdicts en erreur ni la relance des livraisons.
        import inspect

        from sentimail_v3.supervision import caretaker

        source = inspect.getsource(caretaker.main)
        bloc = source.split("publish_evaluation")[0]
        self.assertIn("try:", bloc)

if __name__ == "__main__":
    unittest.main()
