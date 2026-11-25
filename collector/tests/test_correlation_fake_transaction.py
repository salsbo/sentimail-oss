"""Un acte financier annoncé par un expéditeur dont personne ne répond.

Le faux reçu du 16 septembre 2026 : un paiement « confirmé », un RIB, un
montant, un lien pour « gérer », depuis un domaine authentifié que personne ne
revendique et jamais vu. Aucun des trois faits ne suffit ; ensemble ils
décrivent le leurre de transaction fictive.
"""

from __future__ import annotations

import unittest

from sentimail_v3.code.correlation import CORRELATIONS, correlations


def _codes(observed: set[str]) -> dict[str, dict[str, object]]:
    return {value["clue_code"]: value for value in correlations(observed)}


FAISCEAU = {
    "CONTENT_FINANCIAL_CONTEXT",
    "SENDER_WITHOUT_PUBLIC_FOOTPRINT",
    "HISTORY_FIRST_OBSERVATION",
}


class FakeTransactionLureTests(unittest.TestCase):
    def test_les_trois_faits_reunis_convergent(self) -> None:
        found = _codes(set(FAISCEAU))
        self.assertIn("CORRELATION_FAKE_TRANSACTION_LURE", found)
        clue = found["CORRELATION_FAKE_TRANSACTION_LURE"]
        self.assertEqual(clue["direction"], "adverse")
        self.assertEqual(clue["article_code"], "CORR-014")
        self.assertEqual(clue["facts"]["attack_technique"], "FAKE_TRANSACTION_LURE")

    def test_un_paiement_demande_vaut_contexte_financier(self) -> None:
        found = _codes(
            {"ACTION_PAYMENT_TRANSFER", "SENDER_WITHOUT_PUBLIC_FOOTPRINT", "HISTORY_FIRST_OBSERVATION"}
        )
        self.assertIn("CORRELATION_FAKE_TRANSACTION_LURE", found)

    def test_sans_contexte_financier_rien_ne_converge(self) -> None:
        self.assertNotIn(
            "CORRELATION_FAKE_TRANSACTION_LURE",
            _codes({"SENDER_WITHOUT_PUBLIC_FOOTPRINT", "HISTORY_FIRST_OBSERVATION"}),
        )

    def test_un_expediteur_qui_a_un_repondant_ne_converge_pas(self) -> None:
        # Un reçu PayByPhone en première observation : le domaine répond de lui.
        self.assertNotIn(
            "CORRELATION_FAKE_TRANSACTION_LURE",
            _codes({"CONTENT_FINANCIAL_CONTEXT", "HISTORY_FIRST_OBSERVATION"}),
        )

    def test_une_verification_en_panne_n_accuse_personne(self) -> None:
        # Un moteur de recherche indisponible n'est pas une absence de répondant.
        self.assertNotIn(
            "CORRELATION_FAKE_TRANSACTION_LURE",
            _codes({"CONTENT_FINANCIAL_CONTEXT", "SENDER_RELATION_UNVERIFIED", "HISTORY_FIRST_OBSERVATION"}),
        )

    def test_un_apex_deja_livre_ici_ne_converge_pas(self) -> None:
        # Les envoyeurs mutualisés tirent une adresse au hasard : le premier
        # contact y est vrai à perpétuité, l'apex, lui, est connu.
        self.assertNotIn(
            "CORRELATION_FAKE_TRANSACTION_LURE",
            _codes(set(FAISCEAU) | {"HISTORY_APEX_ESTABLISHED_LOCALLY"}),
        )

    def test_la_convergence_est_inscrite_au_registre(self) -> None:
        codes = {rule.clue_code for rule in CORRELATIONS}
        self.assertIn("CORRELATION_FAKE_TRANSACTION_LURE", codes)


if __name__ == "__main__":
    unittest.main()
