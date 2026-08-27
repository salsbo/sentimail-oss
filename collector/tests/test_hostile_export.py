"""Le registre des sources hostiles devient un fichier que Postfix lit.

Le MX ne doit dépendre ni de la base ni d'un service au moment d'accepter une
connexion : le watchdog exporte périodiquement le registre en table cidr
(écriture atomique, inchangé = pas d'écriture). Les entrées automatiques
expirent à 30 jours glissants ; les entrées manuelles de l'admin restent
jusqu'à leur suppression.
"""

from __future__ import annotations

import pathlib
import tempfile
import unittest

from sentimail_v3.execution.hostile_export import export_hostile_cidr


class _Pool:
    def __init__(self, ips: list[str]) -> None:
        self._ips = ips
        self.queries: list[str] = []

    async def fetch(self, query, *args):
        assert "hostile_smtp_sources" in query
        self.queries.append(query)
        return [{"ip": ip} for ip in self._ips]


class ExportTests(unittest.IsolatedAsyncioTestCase):
    async def test_le_fichier_cidr_est_ecrit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "hostile.cidr"
            count = await export_hostile_cidr(_Pool(["93.184.216.99", "93.184.216.0/24"]), str(path))
            self.assertEqual(count, 2)
            contenu = path.read_text()
            self.assertIn("93.184.216.99/32\tREJECT", contenu)
            self.assertIn("93.184.216.0/24\tREJECT", contenu)

    async def test_un_registre_vide_donne_un_fichier_vide(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "hostile.cidr"
            count = await export_hostile_cidr(_Pool([]), str(path))
            self.assertEqual(count, 0)
            self.assertEqual(path.read_text(), "")

    async def test_un_contenu_inchange_ne_reecrit_pas(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "hostile.cidr"
            await export_hostile_cidr(_Pool(["93.184.216.99"]), str(path))
            avant = path.stat().st_mtime_ns
            await export_hostile_cidr(_Pool(["93.184.216.99"]), str(path))
            self.assertEqual(path.stat().st_mtime_ns, avant)

    async def test_le_blocage_exige_dix_occurrences(self) -> None:
        # Une occurrence isolée peut être un faux positif ou un serveur
        # partagé : on observe. Seule la récidive lourde (>= 10 messages)
        # ferme la porte - sauf décision manuelle, qui bloque toujours.
        pool = _Pool(["93.184.216.99"])
        with tempfile.TemporaryDirectory() as tmp:
            await export_hostile_cidr(pool, str(pathlib.Path(tmp) / "h.cidr"))
        query = pool.queries[0]
        self.assertIn("hits >= 10", query)
        self.assertIn("manual", query)

    async def test_une_ipv6_recoit_son_prefixe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "hostile.cidr"
            await export_hostile_cidr(_Pool(["2a01:4f8::1"]), str(path))
            self.assertIn("2a01:4f8::1/128\tREJECT", path.read_text())


if __name__ == "__main__":
    unittest.main()
