"""Aucune table de marques ne doit revenir.

Il y en a eu une : 108 noms écrits à la main, et l'ambition de dire quel nom
appartient à quelle organisation. Elle a coûté ce que coûte toute liste - elle
ignorait « CIC » puis « Disney » jusqu'à ce qu'on les y ajoute, et se trompait
sur ce qu'on y avait mal mis : « ca-paris.fr » accusé d'usurper le Crédit
Agricole, dont c'est pourtant un domaine, et « Amazon via LinkedIn » accusé
d'usurper Amazon.

Elle a été supprimée le 27 août. La confrontation du nom affiché à
l'organisation qu'il désigne se fait sur ce qu'une recherche rend du nom et du
domaine, jugée par le modèle sur ces pièces.

Ce test garde la décision : une liste réapparaît vite, un nom à la fois.
"""

from __future__ import annotations

import pathlib
import unittest


def _sources() -> list[pathlib.Path]:
    racine = pathlib.Path(__file__).resolve().parents[1] / "src" / "sentimail_v3"
    return sorted(racine.rglob("*.py"))


class AucunReferentielTests(unittest.TestCase):
    def test_le_module_des_marques_n_existe_plus(self) -> None:
        with self.assertRaises(ImportError):
            __import__("sentimail_v3.code.brands")

    def test_aucune_source_ne_le_rappelle(self) -> None:
        for fichier in _sources():
            with self.subTest(fichier=fichier.name):
                texte = fichier.read_text(encoding="utf-8")
                self.assertNotIn("BRAND_APEXES", texte)
                self.assertNotIn("code.brands", texte)

    def test_aucune_liste_de_marques_ne_se_reforme_ailleurs(self) -> None:
        """Une liste peut renaître sous un autre nom : on la reconnaît à ses
        membres, pas à son intitulé."""
        temoins = ("doctolib", "paypal", "netflix", "decathlon")
        for fichier in _sources():
            texte = fichier.read_text(encoding="utf-8").casefold()
            presents = [nom for nom in temoins if nom in texte]
            with self.subTest(fichier=fichier.name):
                self.assertLess(
                    len(presents),
                    3,
                    f"{fichier.name} recense des marques : {presents}",
                )


if __name__ == "__main__":
    unittest.main()
