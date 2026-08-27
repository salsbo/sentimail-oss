from __future__ import annotations

import unittest

from aiosmtplib.errors import (
    SMTPConnectError,
    SMTPRecipientRefused,
    SMTPRecipientsRefused,
    SMTPResponseException,
    SMTPServerDisconnected,
)

from sentimail_v3.execution.smtp_failure import is_permanent_rejection


class PermanentRejectionTests(unittest.TestCase):
    def test_un_destinataire_inconnu_est_definitif(self) -> None:
        refusal = SMTPRecipientsRefused(
            [
                SMTPRecipientRefused(
                    550,
                    "5.1.1 <millou@example.fr>: Recipient address rejected: "
                    "User unknown in virtual mailbox table",
                    "millou@example.fr",
                )
            ]
        )
        self.assertTrue(is_permanent_rejection(refusal))

    def test_un_rejet_temporaire_reste_a_reessayer(self) -> None:
        refusal = SMTPRecipientsRefused(
            [SMTPRecipientRefused(450, "4.2.0 Mailbox busy", "a@example.fr")]
        )
        self.assertFalse(is_permanent_rejection(refusal))

    def test_un_refus_definitif_du_relais_est_definitif(self) -> None:
        self.assertTrue(is_permanent_rejection(SMTPResponseException(554, "5.7.1")))

    def test_une_panne_de_connexion_reste_a_reessayer(self) -> None:
        self.assertFalse(is_permanent_rejection(SMTPConnectError("relais injoignable")))
        self.assertFalse(is_permanent_rejection(SMTPServerDisconnected("coupure")))
        self.assertFalse(is_permanent_rejection(TimeoutError()))

    def test_un_lot_partiellement_temporaire_reste_a_reessayer(self) -> None:
        """Un seul destinataire encore réessayable interdit d'abandonner le lot."""
        refusal = SMTPRecipientsRefused(
            [
                SMTPRecipientRefused(550, "5.1.1 unknown", "a@example.fr"),
                SMTPRecipientRefused(451, "4.3.0 try later", "b@example.fr"),
            ]
        )
        self.assertFalse(is_permanent_rejection(refusal))


if __name__ == "__main__":
    unittest.main()
