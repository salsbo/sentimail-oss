"""Métier sans rapport : compte détourné si l'adresse est authentifiée, adresse empruntée sinon.

M-16ae76, 16 septembre 2026 : une boutique de vêtements annonçait un stockage
plein, DMARC en échec. CORR-007 écrivait « s'authentifie correctement » et le
juge lisait « compte peut-être détourné ».
"""

from __future__ import annotations

import unittest

from sentimail_v3.code.correlation import correlations
from sentimail_v3.code.plain_words import short_points

INCOHERENT_INCONNU = {"SENDER_ACTIVITY_INCOHERENT", "HISTORY_FIRST_OBSERVATION"}


def _codes(observed: set[str]) -> dict[str, dict[str, object]]:
    return {
        value["clue_code"]: value
        for value in correlations(
            observed,
            identity={"displayed_email": "support@mundololita.com"},
            evidence={"SENDER_ACTIVITY_INCOHERENT": {"sender_apex": "mundololita.com"}},
        )
    }


class AdresseEmprunteeTests(unittest.TestCase):
    def test_m_16ae76_est_une_adresse_empruntee(self) -> None:
        found = _codes(
            INCOHERENT_INCONNU
            | {"AUTH_DMARC_FAIL", "AUTH_DKIM_INCONCLUSIVE", "AUTH_SPF_INCONCLUSIVE"}
        )
        self.assertIn("CORRELATION_SPOOFED_UNRELATED_SENDER", found)
        self.assertNotIn("CORRELATION_COMPROMISED_SENDER", found)
        clue = found["CORRELATION_SPOOFED_UNRELATED_SENDER"]
        self.assertEqual(clue["article_code"], "CORR-015")
        self.assertEqual(clue["facts"]["attack_technique"], "SENDER_SPOOFING")
        self.assertNotIn("s’authentifie correctement", str(clue["statement"]))
        self.assertEqual(
            clue["facts"]["identity"]["displayed_email"], "support@mundololita.com"
        )
        self.assertEqual(clue["facts"]["activity"]["sender_apex"], "mundololita.com")

    def test_authentifie_reste_un_compte_detourne(self) -> None:
        found = _codes(INCOHERENT_INCONNU | {"AUTH_DMARC_PASS"})
        self.assertIn("CORRELATION_COMPROMISED_SENDER", found)
        self.assertNotIn("CORRELATION_SPOOFED_UNRELATED_SENDER", found)

    def test_un_defaut_a_cote_d_un_dmarc_valide_ne_pose_que_la_soeur(self) -> None:
        found = _codes(INCOHERENT_INCONNU | {"AUTH_DMARC_PASS", "AUTH_SPF_SOFTFAIL"})
        self.assertIn("CORRELATION_SPOOFED_UNRELATED_SENDER", found)
        self.assertNotIn("CORRELATION_COMPROMISED_SENDER", found)

    def test_sans_authentification_connue_aucune_des_deux(self) -> None:
        found = _codes(set(INCOHERENT_INCONNU))
        self.assertNotIn("CORRELATION_COMPROMISED_SENDER", found)
        self.assertNotIn("CORRELATION_SPOOFED_UNRELATED_SENDER", found)

    def test_un_correspondant_deja_vu_n_est_pas_accuse(self) -> None:
        # Sur 60 jours, trois légitimes réunissaient incohérence et défaut
        # d'authentification hors première observation.
        found = _codes({"SENDER_ACTIVITY_INCOHERENT", "AUTH_DMARC_FAIL"})
        self.assertNotIn("CORRELATION_SPOOFED_UNRELATED_SENDER", found)

    def test_un_apex_deja_livre_ici_n_est_pas_accuse(self) -> None:
        found = _codes(
            INCOHERENT_INCONNU | {"AUTH_DMARC_FAIL", "HISTORY_APEX_ESTABLISHED_LOCALLY"}
        )
        self.assertNotIn("CORRELATION_SPOOFED_UNRELATED_SENDER", found)


class AvisAdresseEmprunteeTests(unittest.TestCase):
    def test_l_avis_dit_l_usurpation_une_seule_fois(self) -> None:
        rows = [
            {"clue_code": "CORRELATION_SPOOFED_UNRELATED_SENDER", "statement": "x"},
            {"clue_code": "SENDER_ACTIVITY_INCOHERENT", "statement": "y"},
            {"clue_code": "AUTH_DMARC_FAIL", "statement": "z"},
        ]
        points = short_points(rows, 5)
        self.assertEqual(len(points), 1)
        self.assertIn("non authentifiée", points[0])

    def test_l_avis_telegraphique_a_son_libelle(self) -> None:
        rows = [
            {"clue_code": "CORRELATION_SPOOFED_UNRELATED_SENDER", "statement": "x"},
            {"clue_code": "URL_FAKE_HUMAN_VERIFICATION", "statement": "y"},
        ]
        points = short_points(rows, 5, telegraphique=True)
        self.assertIn("Identité : adresse empruntée, métier sans rapport", points)
        self.assertIn("Lien : fausse vérification anti-robot", points)


if __name__ == "__main__":
    unittest.main()
