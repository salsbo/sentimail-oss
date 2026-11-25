from __future__ import annotations

import pathlib
import re
import unittest

from sentimail_v3.code.families import (
    FAMILIES,
    CROSS_CUTTING,
    family_of,
    family_coverage,
    converging_families,
)


def _clue(article: str, direction: str = "adverse", strength: int = 60) -> dict[str, object]:
    return {
        "clue_code": "X_" + article.replace("-", "_"),
        "article_code": article,
        "direction": direction,
        "strength": strength,
    }


class FamilyOfTests(unittest.TestCase):
    def test_l_authentification_est_une_famille_d_identite(self) -> None:
        self.assertEqual(family_of("AUTH-001"), "identite")
        self.assertEqual(family_of("IDENTITY-003"), "identite")

    def test_un_article_profond_va_dans_sa_vraie_famille_pas_dans_deep(self) -> None:
        """DEEP- n'est pas une famille : c'est l'étage qui a produit le constat.

        Les mêmes 19 articles couvrent la navigation, les pièces jointes et la
        cohérence du métier. Les ranger ensemble ferait croire à une
        convergence là où un seul sujet est observé.
        """
        self.assertEqual(family_of("DEEP-001"), "liens")
        self.assertEqual(family_of("DEEP-004"), "pieces_jointes")
        self.assertEqual(family_of("DEEP-005"), "pieces_jointes")
        self.assertEqual(family_of("DEEP-019"), "coherence_metier")

    def test_les_actes_reclames_relevent_du_contenu(self) -> None:
        self.assertEqual(family_of("ACT-001"), "contenu")
        self.assertEqual(family_of("CONTENT-002"), "contenu")

    def test_une_convergence_n_est_pas_une_famille(self) -> None:
        # Une corrélation relie des familles ; la compter comme une famille de
        # plus ferait passer un seul faisceau pour deux preuves.
        self.assertEqual(family_of("CORR-001"), CROSS_CUTTING)
        # Le soupçon du filtre sans authentification reste une heuristique :
        # ni famille de preuve, ni barrière.
        self.assertEqual(family_of("CORR-018"), CROSS_CUTTING)

    def test_le_nom_deguise_et_le_domaine_sosie_sont_des_preuves_d_identite(self) -> None:
        # Rangé par défaut dans « liens », le nom déguisé pouvait faire
        # compter une seconde famille forte à côté d'une organisation démentie.
        self.assertEqual(family_of("DEEP-026"), "identite")
        self.assertEqual(family_of("IDENTITY-010"), "identite")

    def test_un_article_inconnu_ne_fait_pas_tomber_le_jugement(self) -> None:
        self.assertEqual(family_of("ZZZ-999"), "autre")
        self.assertEqual(family_of(""), "autre")
        self.assertEqual(family_of(None), "autre")


class CouvertureTests(unittest.TestCase):
    def test_une_famille_sans_indice_est_muette(self) -> None:
        coverage = family_coverage([_clue("AUTH-001")])
        par_nom = {f["family"]: f for f in coverage}
        self.assertFalse(par_nom["identite"]["silent"])
        self.assertTrue(par_nom["pieces_jointes"]["silent"])

    def test_le_silence_n_est_pas_une_decharge(self) -> None:
        # Le piège central : « aucune pièce jointe » ne plaide pas en faveur du
        # message, ça ne dit rien. Une famille muette ne porte aucune force.
        par_nom = {f["family"]: f for f in family_coverage([])}
        for famille in FAMILIES:
            self.assertTrue(par_nom[famille]["silent"])
            self.assertEqual(par_nom[famille]["favorable"]["count"], 0)
            self.assertEqual(par_nom[famille]["adverse"]["max_strength"], 0)

    def test_la_force_retenue_est_le_maximum_jamais_la_somme(self) -> None:
        # Cinq broutilles ne valent pas une preuve : additionner les forces
        # fabriquerait une charge que personne n'a observée.
        coverage = family_coverage([_clue("AUTH-001", strength=10) for _ in range(5)])
        identite = next(f for f in coverage if f["family"] == "identite")
        self.assertEqual(identite["adverse"]["max_strength"], 10)
        self.assertEqual(identite["adverse"]["count"], 5)

    def test_charge_et_decharge_coexistent_dans_une_meme_famille(self) -> None:
        coverage = family_coverage(
            [
                _clue("AUTH-001", direction="adverse", strength=40),
                _clue("AUTH-002", direction="favorable", strength=70),
            ]
        )
        identite = next(f for f in coverage if f["family"] == "identite")
        self.assertEqual(identite["adverse"]["count"], 1)
        self.assertEqual(identite["favorable"]["count"], 1)
        self.assertEqual(identite["favorable"]["max_strength"], 70)

    def test_chaque_famille_cite_ses_codes(self) -> None:
        coverage = family_coverage([_clue("ATT-010")])
        pj = next(f for f in coverage if f["family"] == "pieces_jointes")
        self.assertIn("X_ATT_010", pj["adverse"]["clue_codes"])

    def test_toutes_les_familles_sont_toujours_presentes(self) -> None:
        # Une famille absente du dossier serait invisible : le jugement doit
        # voir qu'elle n'a rien vu, pas ignorer qu'elle existe.
        noms = [f["family"] for f in family_coverage([_clue("AUTH-001")])]
        self.assertEqual(set(noms), set(FAMILIES))

    def test_un_dossier_illisible_ne_produit_pas_d_erreur(self) -> None:
        for valeur in (None, [], "texte", [None], ["x"], [{}]):
            with self.subTest(valeur=valeur):
                coverage = family_coverage(valeur)
                self.assertEqual(len(coverage), len(FAMILIES))


class ConvergenceTests(unittest.TestCase):
    """« Au moins deux familles fortes indépendantes » doit être mesuré."""

    def test_deux_familles_chargees_convergent(self) -> None:
        familles = converging_families(
            [_clue("AUTH-001", strength=70), _clue("ATT-010", strength=80)]
        )
        self.assertEqual(set(familles), {"identite", "pieces_jointes"})

    def test_une_famille_ne_converge_pas_avec_elle_meme(self) -> None:
        # Trois indices d'authentification décrivent le même sujet : c'est une
        # charge, pas une convergence.
        familles = converging_families(
            [
                _clue("AUTH-001", strength=70),
                _clue("AUTH-002", strength=75),
                _clue("IDENTITY-001", strength=80),
            ]
        )
        self.assertEqual(familles, ["identite"])

    def test_une_correlation_ne_cree_pas_une_famille_supplementaire(self) -> None:
        familles = converging_families(
            [_clue("AUTH-001", strength=70), _clue("CORR-001", strength=90)]
        )
        self.assertEqual(familles, ["identite"])

    def test_les_indices_faibles_ne_convergent_pas(self) -> None:
        familles = converging_families(
            [_clue("AUTH-001", strength=15), _clue("ATT-010", strength=10)]
        )
        self.assertEqual(familles, [])

    def test_une_decharge_ne_converge_pas(self) -> None:
        familles = converging_families(
            [_clue("AUTH-001", direction="favorable", strength=90)]
        )
        self.assertEqual(familles, [])


class CompletudeTests(unittest.TestCase):
    """La leçon des article_code : ce qui n'est pas rangé disparaît."""

    def test_chaque_article_du_code_a_une_famille(self) -> None:
        racine = pathlib.Path(__file__).resolve().parents[2] / "database" / "init"
        articles = set()
        for fichier in racine.glob("*.sql"):
            articles.update(
                re.findall(r"'([A-Z][A-Z0-9]*-[0-9]{3})'", fichier.read_text("utf-8"))
            )
        self.assertGreater(len(articles), 100, "articles introuvables : test aveugle")
        orphelins = sorted(a for a in articles if family_of(a) == "autre")
        self.assertEqual(orphelins, [], f"articles sans famille : {orphelins}")


if __name__ == "__main__":
    unittest.main()
