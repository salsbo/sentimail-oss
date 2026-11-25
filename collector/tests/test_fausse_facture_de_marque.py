"""CORR-017 : une facture au nom d'une marque, par quelqu'un qui n'est pas elle.

M-2a9365 (29 septembre 2026) : « Support AppIe » facture 99 € d'Apple TV depuis
un domaine tiers authentifié et publiquement connu. Ni CORR-014 (sans
répondant) ni CORR-016 (page vide) ne se posaient : c'est l'identité empruntée
qui porte ce faisceau.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from sentimail_v3.code import plain_words
from sentimail_v3.code.correlation import correlations

CODE = "CORRELATION_BRAND_TRANSACTION_LURE"
FAISCEAU = {
    "CONTENT_FINANCIAL_CONTEXT",
    "IDENTITY_DISPLAY_NAME_DISGUISED",
    "HISTORY_FIRST_OBSERVATION",
}


def _codes(observed: set[str]) -> dict[str, dict[str, object]]:
    return {value["clue_code"]: value for value in correlations(observed)}


class ConvergenceTests(unittest.TestCase):
    def test_les_trois_faits_reunis_convergent(self) -> None:
        clue = _codes(set(FAISCEAU))[CODE]
        self.assertEqual(clue["direction"], "adverse")
        self.assertEqual(clue["article_code"], "CORR-017")
        self.assertEqual(clue["facts"]["attack_technique"], "FAKE_TRANSACTION_LURE")
        self.assertEqual(int(clue["strength"]), 80)

    def test_le_dossier_de_m_2a9365_converge_malgre_l_authentification(self) -> None:
        dossier = set(FAISCEAU) | {
            "AUTH_DMARC_PASS",
            "AUTH_DKIM_PASS",
            "AUTH_SPF_PASS",
            "CORRELATION_BRAND_FIRST_CONTACT",
            "SENDER_ACTIVITY_INCOHERENT",
        }
        self.assertIn(CODE, _codes(dossier))

    def test_toute_identite_empruntee_suffit(self) -> None:
        for identite in (
            "IDENTITY_BRAND_MISMATCH",
            "IDENTITY_COUSIN_DOMAIN",
            "IDENTITY_CLAIMED_ORGANISATION_REFUTED",
        ):
            with self.subTest(identite=identite):
                observed = {"ACTION_PAYMENT_TRANSFER", identite, "HISTORY_FIRST_OBSERVATION"}
                self.assertIn(CODE, _codes(observed))

    def test_sans_identite_empruntee_rien_ne_converge(self) -> None:
        # Un vrai reçu d'un marchand inconnu : de l'argent, un premier
        # contact, mais aucun nom emprunté.
        self.assertNotIn(
            CODE, _codes({"CONTENT_FINANCIAL_CONTEXT", "HISTORY_FIRST_OBSERVATION"})
        )

    def test_sans_argent_rien_ne_converge(self) -> None:
        self.assertNotIn(
            CODE,
            _codes({"IDENTITY_DISPLAY_NAME_DISGUISED", "HISTORY_FIRST_OBSERVATION"}),
        )

    def test_un_expediteur_deja_vu_ne_converge_pas(self) -> None:
        self.assertNotIn(
            CODE,
            _codes({"CONTENT_FINANCIAL_CONTEXT", "IDENTITY_DISPLAY_NAME_DISGUISED"}),
        )

    def test_un_apex_etabli_ici_l_exclut(self) -> None:
        self.assertNotIn(
            CODE, _codes(set(FAISCEAU) | {"HISTORY_APEX_ESTABLISHED_LOCALLY"})
        )


class MotsSimplesTests(unittest.TestCase):
    def test_l_indice_a_ses_mots_sur_chaque_surface(self) -> None:
        self.assertIn(CODE, plain_words._PLAIN)
        self.assertIn(CODE, plain_words._SHORT)
        self.assertIn(CODE, plain_words._TELEGRAPHIQUE)


class MigrationTests(unittest.TestCase):
    def test_la_migration_declare_l_article_et_la_technique(self) -> None:
        racine = Path(__file__).resolve().parents[2] / "database" / "init"
        fichiers = sorted(racine.glob("092_*.sql"))
        self.assertEqual(len(fichiers), 1, "une migration 092 attendue")
        sql = fichiers[0].read_text(encoding="utf-8")
        for attendu in ("'CORR-017'", "'adverse', 80", CODE, "FAKE_TRANSACTION_LURE"):
            with self.subTest(attendu=attendu):
                self.assertIn(attendu, sql)
        # Un faisceau, pas une barrière matérielle.
        self.assertNotIn("material_danger", sql)


if __name__ == "__main__":
    unittest.main()
