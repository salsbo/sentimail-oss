"""« Jamais contourné » se garantit, il ne se promet pas.

Le registre est le seul chemin d'exécution ; le superviseur compte les
passages de `sender_relation` restés sans constat. Sans ce compteur, un hook
qui recommence à se taire disparaît en silence, exactement ce qui a livré le
faux reçu du 16 septembre 2026.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from sentimail_v3.supervision import watchdog
from sentimail_v3.supervision.watchdog import REQUIRED_DEEP_HOOKS
from sentimail_v3.supervision.watchdog_letter import lettre
from tests.test_watchdog import _SnapshotPool, _snapshot_settings


class RegistreExigeTests(unittest.TestCase):
    def test_la_sonde_exige_le_nouvel_enqueteur(self) -> None:
        self.assertIn("sender_relation", REQUIRED_DEEP_HOOKS)
        self.assertIn("sender_activity", REQUIRED_DEEP_HOOKS)
        self.assertIn("action_destination", REQUIRED_DEEP_HOOKS)
        self.assertNotIn("identity_claim", REQUIRED_DEEP_HOOKS)
        self.assertNotIn("activity_coherence", REQUIRED_DEEP_HOOKS)


class SilenceCompteTests(unittest.IsolatedAsyncioTestCase):
    async def test_une_erreur_de_coherence_degrade_le_superviseur(self) -> None:
        snapshot = await watchdog._snapshot(
            _SnapshotPool(coherence_hook_failures=1), _snapshot_settings(),
            previously_observed=frozenset({"coherence_hook_failures"}),
        )
        self.assertIn("coherence_hook_failures", snapshot["details"]["reasons"])

    async def test_un_passage_sans_constat_degrade_le_superviseur(self) -> None:
        pool = _SnapshotPool(sender_relation_silent=1)
        snapshot = await watchdog._snapshot(
            pool,  # type: ignore[arg-type]
            _snapshot_settings(),
            previously_observed=frozenset({"sender_relation_silent"}),
        )
        self.assertEqual(snapshot["details"]["sender_relation_silent"], 1)
        self.assertIn("sender_relation_silent", snapshot["details"]["reasons"])

    async def test_sans_silence_rien_ne_sonne(self) -> None:
        snapshot = await watchdog._snapshot(
            _SnapshotPool(),  # type: ignore[arg-type]
            _snapshot_settings(),
        )
        self.assertEqual(snapshot["details"]["sender_relation_silent"], 0)
        self.assertNotIn("sender_relation_silent", snapshot["details"]["reasons"])


class LettreTests(unittest.TestCase):
    def test_la_lettre_nomme_le_silence_en_mots_simples(self) -> None:
        details = {"reasons": ["sender_relation_silent"], "sender_relation_silent": 2}
        texte = lettre("degraded", details).text
        # Un code absent de la table est montré brut : « le signal « … » est
        # levé ». Celui-ci doit se dire en français.
        self.assertNotIn("le signal «", texte)
        self.assertIn("sans constat", texte)


if __name__ == "__main__":
    unittest.main()
