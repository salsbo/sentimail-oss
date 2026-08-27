from __future__ import annotations

import unittest

from sentimail_admin.config import identity_environment_defaults


class IdentityEnvironmentDefaultsTests(unittest.TestCase):
    """Les mêmes noms de variable et les mêmes défauts que le collector."""

    def test_les_defauts_correspondent_au_collector(self) -> None:
        valeurs = identity_environment_defaults({})
        self.assertEqual(valeurs["action_address"], "maia@sentinel.sentimail.example")
        self.assertEqual(
            valeurs["action_aliases"], ["kitt@sentinel.sentimail.example"]
        )
        self.assertEqual(
            valeurs["assistant_sender"], "MAIA - SentiMail <maia@sentimail.example>"
        )
        self.assertEqual(
            valeurs["probe_recipient"], "sentinel-probe@sentimail.example"
        )

    def test_les_variables_d_environnement_sont_prises_en_compte(self) -> None:
        environ = {
            "ACTION_ADDRESS": "maia@exemple.org",
            "ACTION_ALIASES": "kitt@exemple.org, autre@exemple.org",
            "ASSISTANT_SENDER": "MAIA <maia@exemple.org>",
            "PROBE_RECIPIENT": "sonde@exemple.org",
        }
        valeurs = identity_environment_defaults(environ)
        self.assertEqual(valeurs["action_address"], "maia@exemple.org")
        self.assertEqual(
            valeurs["action_aliases"], ["kitt@exemple.org", "autre@exemple.org"]
        )
        self.assertEqual(valeurs["assistant_sender"], "MAIA <maia@exemple.org>")
        self.assertEqual(valeurs["probe_recipient"], "sonde@exemple.org")

    def test_un_alias_vide_ne_produit_aucune_entree(self) -> None:
        valeurs = identity_environment_defaults({"ACTION_ALIASES": "  "})
        self.assertEqual(valeurs["action_aliases"], [])


if __name__ == "__main__":
    unittest.main()
