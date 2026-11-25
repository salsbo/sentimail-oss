"""L'état du superviseur, lisible par la sonde centrale.

`/sante/pipeline` ne passe en échec que si un message n'entre plus. Un juge
qui traîne, une file en retard, un avis non parti laissent la sonde de
supervision verte. Le 14 septembre, seule la lettre de MAIA portait l'alerte ; si le relais
de sortie tombe, personne ne la voit. Cette route rend le verdict du
superviseur sous la forme que la sonde `json_health` consomme : « ok » vaut
vert, tout le reste vaut rouge avec la cause.
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sentimail_admin.app import sante_superviseur


class _Pool:
    def __init__(self, row: dict | None) -> None:
        self.row = row

    async def fetchrow(self, sql: str, *args: object) -> dict | None:
        return self.row


def _requete(row: dict | None) -> SimpleNamespace:
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(pool=_Pool(row))))


def _corps(response) -> dict:
    return json.loads(response.body)


class SanteSuperviseurTests(unittest.IsolatedAsyncioTestCase):
    async def test_un_superviseur_serein_vaut_ok(self) -> None:
        row = {"status": "ok", "details": {"reasons": []}, "observed_at": datetime.now(timezone.utc)}
        response = await sante_superviseur(_requete(row))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(_corps(response)["status"], "ok")

    async def test_une_degradation_porte_ses_causes(self) -> None:
        row = {
            "status": "degraded",
            "details": {"reasons": ["accepted_without_terminal_outcome", "analysis_backlog"]},
            "observed_at": datetime.now(timezone.utc),
        }
        response = await sante_superviseur(_requete(row))
        # La sonde json_health lit le JSON seulement sous 400.
        self.assertEqual(response.status_code, 200)
        corps = _corps(response)
        self.assertEqual(corps["status"], "degraded")
        self.assertIn("analysis_backlog", corps["reasons"])

    async def test_un_superviseur_muet_vaut_panne(self) -> None:
        row = {
            "status": "ok",
            "details": {"reasons": []},
            "observed_at": datetime.now(timezone.utc) - timedelta(minutes=12),
        }
        corps = _corps(await sante_superviseur(_requete(row)))
        self.assertEqual(corps["status"], "down")
        self.assertIn("muet", corps["reasons"])

    async def test_aucun_releve_vaut_inconnu(self) -> None:
        corps = _corps(await sante_superviseur(_requete(None)))
        self.assertEqual(corps["status"], "unknown")
