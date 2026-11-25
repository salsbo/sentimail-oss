"""Un message qui parle d'argent le dit au dossier, même sans rien demander.

Le 16 septembre 2026, le hook contenu avait lu « paiement accepté », « RIB »,
« 69,90 € » et posé la finalité `financial_transfer` dans ses faits de travail.
Aucun indice n'en sortait : le juge, qui ne lit que les indices, a écrit
« aucun indice défavorable » sur un faux reçu. Le fait reste neutre ; il est
désormais écrit.
"""

from __future__ import annotations

import unittest

from sentimail_v3.observation.dossier.hooks.content import ContentHook
from sentimail_v3.observation.dossier.models import InvestigationContext
from sentimail_v3.observation.parser import parse_message


def _html_only(subject: str, html_body: str) -> bytes:
    return (
        "From: Annuel-Famille <noreply@exemple.test>\r\n"
        "To: amartin@mondomaine.example\r\n"
        f"Subject: {subject}\r\n"
        "Date: Wed, 16 Sep 2026 09:29:48 +0000\r\n"
        "Message-ID: <abc@exemple.test>\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        f"<html><body>{html_body}</body></html>\r\n"
    ).encode("utf-8")


def _clues(raw: bytes) -> dict[str, object]:
    import asyncio

    context = InvestigationContext(
        raw, parse_message(raw), "bounces@exemple.test", ["amartin@mondomaine.example"]
    )
    clues, _ = asyncio.run(ContentHook().observe(context))
    return {clue.clue_code: clue for clue in clues}


class FinancialContextTests(unittest.TestCase):
    def test_un_faux_recu_html_seul_porte_le_contexte_financier(self) -> None:
        codes = _clues(
            _html_only(
                "ALICE, Achat confirmé, votre abonnement a été renouvelé",
                "<p>Votre paiement a été accepté</p><p>RIB FR7630006000011234567890189</p>"  # audit-ok: IBAN d'exemple publié, ne désigne aucun compte
                "<p>Montant 69,90 €</p><a href='https://exemple.test/'>Gérer mon abonnement</a>",
            )
        )
        self.assertIn("CONTENT_FINANCIAL_CONTEXT", codes)
        clue = codes["CONTENT_FINANCIAL_CONTEXT"]
        self.assertEqual(clue.article_code, "CONTENT-015")
        self.assertEqual(clue.direction, "neutral")
        self.assertEqual(clue.strength, 0)
        self.assertEqual(clue.facts["purpose"], "payment")
        self.assertNotIn("transfer_money", clue.facts["action_types"])
        self.assertIn("bank_account", clue.facts["sensitive_categories_mentioned"])

    def test_un_recu_ordinaire_le_porte_aussi_sans_charge(self) -> None:
        # Un vrai reçu PayByPhone est un contexte financier : le fait est le
        # même, c'est la convergence avec le reste qui distingue.
        codes = _clues(
            _html_only("Reçu de stationnement", "<p>Votre paiement de 2,40 € a été enregistré.</p>")
        )
        self.assertIn("CONTENT_FINANCIAL_CONTEXT", codes)
        self.assertEqual(codes["CONTENT_FINANCIAL_CONTEXT"].facts["purpose"], "payment")

    def test_une_lettre_d_information_ne_le_porte_pas(self) -> None:
        codes = _clues(
            _html_only("Nos nouveautés de septembre", "<p>Découvrez la nouvelle collection.</p>")
        )
        self.assertNotIn("CONTENT_FINANCIAL_CONTEXT", codes)

    def test_le_fait_dit_ce_qui_a_ete_lu(self) -> None:
        codes = _clues(
            _html_only("Facture", "<p>Votre facture est disponible. Cliquez pour la consulter.</p>")
        )
        clue = codes["CONTENT_FINANCIAL_CONTEXT"]
        self.assertIn("pay", clue.facts["action_types"])
        self.assertEqual(clue.facts["sensitive_categories_requested"], [])


if __name__ == "__main__":
    unittest.main()
