"""La barrière matérielle se lit dans le Code, pas dans une liste recopiée."""

from __future__ import annotations

import inspect
import re
import unittest

from sentimail_v3.code import material_danger
from sentimail_v3.code.material_danger import has_material_danger


class _Pool:
    """Répond à la requête de la barrière, et à elle seule."""

    def __init__(self, exists: bool) -> None:
        self.exists = exists
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    async def fetchval(self, query: str, *args: object) -> object:
        self.calls.append((query, args))
        if "delivery_barrier" in query and "material_danger" in query:
            return self.exists
        raise AssertionError("requête inattendue")


class BarriereMaterielleTests(unittest.IsolatedAsyncioTestCase):
    async def test_la_requete_est_executable_seule(self) -> None:
        pool = _Pool(True)
        self.assertTrue(await has_material_danger(pool, "message-id"))
        self.assertEqual(pool.calls[0][1], ("message-id",))
        self.assertFalse(await has_material_danger(_Pool(False), "message-id"))

    async def test_seul_un_indice_defavorable_d_un_article_actif_compte(self) -> None:
        pool = _Pool(True)
        await has_material_danger(pool, "message-id")
        requete = pool.calls[0][0]
        self.assertIn("c.direction='adverse'", requete)
        self.assertIn("a.enabled=true", requete)

    def test_aucune_liste_d_articles_en_dur(self) -> None:
        source = inspect.getsource(material_danger)
        self.assertIn("delivery_barrier", source)
        self.assertIsNone(re.search(r"\b[A-Z]{3,}-\d{3}\b", source))


if __name__ == "__main__":
    unittest.main()
