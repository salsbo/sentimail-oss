"""Tout courrier composé par SentiMail porte sa date.

La RFC 5322 n'impose que deux en-têtes, `From` et `Date`. Sans le second, un
client qui trie par date range le message hors de la liste que l'œil parcourt -
souvent tout en bas, parfois en 1970 - et il passe pour perdu alors qu'il est
arrivé. Les filtres anti-spam comptent aussi cette absence contre l'expéditeur.

Le contrôle porte sur le source : il vaut pour les composeurs d'aujourd'hui
comme pour celui que quelqu'un ajoutera demain.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "src" / "sentimail_v3"
# Ce qui suit la construction d'un message, jusqu'à son envoi ou sa fin.
_CONSTRUCTION = re.compile(r"=\s*EmailMessage\(\)(.{0,2000}?)(?:set_content|add_alternative)", re.S)


class DateDesCourriersTests(unittest.TestCase):
    def _compositions(self) -> list[tuple[Path, str]]:
        trouves = []
        for chemin in SOURCE.rglob("*.py"):
            texte = chemin.read_text(encoding="utf-8")
            for bloc in _CONSTRUCTION.findall(texte):
                trouves.append((chemin, bloc))
        return trouves

    def test_il_existe_bien_des_composeurs_a_controler(self) -> None:
        # Sans cette garde, un test vert ne prouverait rien.
        self.assertGreaterEqual(len(self._compositions()), 3)

    def test_chaque_courrier_compose_porte_sa_date(self) -> None:
        for chemin, bloc in self._compositions():
            with self.subTest(module=chemin.name):
                self.assertIn('["Date"]', bloc)
