"""Un article du Code doit avoir quelqu'un pour le produire.

L'inventaire du 27 août a montré 41 articles muets sur 142. La plupart dorment
par nature - aucune macro reçue, aucun exécutable joint - et c'est sain : une
détection qui ne sert pas est une détection qui n'a pas eu à servir.

Mais trois ne dormaient pas : leur producteur avait disparu, ou n'avait jamais
été branché. Ce test vérifie l'inverse du précédent : non plus que tout signal
sait se dire, mais que tout article écrit dans le code a bien un endroit qui
l'émet.
"""

from __future__ import annotations

import pathlib
import re
import unittest

RACINE = pathlib.Path(__file__).resolve().parents[1] / "src" / "sentimail_v3"
MIGRATIONS = pathlib.Path(__file__).resolve().parents[2] / "database" / "init"


def _sources() -> str:
    return "\n".join(
        fichier.read_text(encoding="utf-8") for fichier in RACINE.rglob("*.py")
    )


class ArticlesSansProducteurTests(unittest.TestCase):
    def test_les_articles_du_referentiel_supprime_sont_retires(self) -> None:
        """Leur producteur est parti avec la table des marques."""
        for code in ("IDENTITY-009", "IDENTITY-010", "DEEP-017"):
            porteurs = [
                fichier.name
                for fichier in RACINE.rglob("*.py")
                if f'"{code}"' in fichier.read_text(encoding="utf-8")
            ]
            with self.subTest(code=code):
                self.assertEqual(porteurs, [], f"{code} subsiste dans {porteurs}")

    def test_le_code_les_desactive_en_base(self) -> None:
        migration = (MIGRATIONS / "077_retire_orphan_articles.sql").read_text(
            encoding="utf-8"
        )
        self.assertIn("enabled = false", migration)
        for code in ("IDENTITY-009", "IDENTITY-010", "DEEP-017"):
            self.assertIn(code, migration)

    def test_chaque_article_cite_dans_le_code_est_ecrit_en_migration(self) -> None:
        """Sinon un indice s'insère sans article : ni force par défaut, ni
        famille, ni jurisprudence - et rien ne le signale."""
        source = _sources()
        cites = set(re.findall(r'"article_code": "([A-Z]+-\d+)"', source))
        cites |= set(re.findall(r'^\s*"([A-Z]+-\d+)":\s*\(', source, re.MULTILINE))
        ecrits = "\n".join(
            fichier.read_text(encoding="utf-8") for fichier in MIGRATIONS.glob("*.sql")
        )
        manquants = sorted(code for code in cites if f"'{code}'" not in ecrits)
        self.assertEqual(manquants, [], f"articles jamais écrits au Code : {manquants}")


if __name__ == "__main__":
    unittest.main()
