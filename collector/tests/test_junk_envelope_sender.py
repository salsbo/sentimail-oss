from __future__ import annotations

import unittest
from email import policy
from email.parser import BytesParser

from sentimail_v3.execution.delivery import build_junk_envelope

BRUT = (
    b"From: Health Science Desk <support@mash-japan.co.jp>\r\n"
    b"To: operateur@mondomaine.example\r\n"
    b"Reply-To: no-reply@mash-japan.co.jp\r\n"
    b"Subject: Tired during ordinary activity?\r\n"
    b"Message-ID: <abc@mash-japan.co.jp>\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n\r\n"
    b"<html><body><p>Watch this brief report.</p></body></html>\r\n"
)


def _enveloppe(**extra: object):
    rendu = build_junk_envelope(
        BRUT,
        "spam",
        reasons=["Aucune authentification."],
        lessons=[],
        preview=None,
        action_address="maia@sentinel.mondomaine.example",
        assistant_sender="MAIA - SentiMail <maia@mondomaine.example>",
        recipient="operateur@mondomaine.example",
        **extra,  # type: ignore[arg-type]
    )
    return BytesParser(policy=policy.default).parsebytes(rendu)


class ExpediteurDeLAvisTests(unittest.TestCase):
    """Un avis sans expéditeur arrive de personne.

    L'enveloppe posait l'objet, les en-têtes d'audit et le corps, mais jamais
    « From ». Le client de messagerie affichait un message venu de nulle part,
    et le bouton « Répondre » ne menait à rien. Les en-têtes d'origine, eux,
    étaient bien conservés - mais sous X-SentiMail-Original-*, invisibles.
    """

    def test_l_avis_porte_un_expediteur(self) -> None:
        self.assertIn("maia@mondomaine.example", str(_enveloppe()["From"]))

    def test_l_avis_porte_son_destinataire(self) -> None:
        self.assertIn("operateur@mondomaine.example", str(_enveloppe()["To"]))

    def test_repondre_mene_a_l_adresse_d_action(self) -> None:
        # Sans Reply-To, le bouton « Répondre » du client renvoie vers le vide.
        self.assertIn("maia@sentinel.mondomaine.example", str(_enveloppe()["Reply-To"]))

    def test_l_expediteur_d_origine_n_est_jamais_repris(self) -> None:
        # Reprendre l'adresse du spammeur en « From » ferait de l'avis un
        # message qui semble venir de lui.
        enveloppe = _enveloppe()
        self.assertNotIn("mash-japan", str(enveloppe["From"]))
        self.assertNotIn("mash-japan", str(enveloppe["Reply-To"]))

    def test_les_entetes_d_origine_restent_pour_l_audit(self) -> None:
        enveloppe = _enveloppe()
        self.assertIn("mash-japan", str(enveloppe["X-SentiMail-Original-From"]))

    def test_l_objet_reste_reconnaissable(self) -> None:
        self.assertIn("Tired during ordinary activity", str(_enveloppe()["Subject"]))


class RefusDeLIncompletTests(unittest.TestCase):
    """Mieux vaut échouer que produire un avis sans retour possible."""

    def test_un_expediteur_manquant_est_refuse(self) -> None:
        with self.assertRaises(ValueError):
            build_junk_envelope(
                BRUT,
                "spam",
                reasons=[],
                lessons=[],
                preview=None,
                action_address="maia@sentinel.mondomaine.example",
                assistant_sender="",
                recipient="operateur@mondomaine.example",
            )

    def test_un_destinataire_manquant_est_refuse(self) -> None:
        with self.assertRaises(ValueError):
            build_junk_envelope(
                BRUT,
                "spam",
                reasons=[],
                lessons=[],
                preview=None,
                action_address="maia@sentinel.mondomaine.example",
                assistant_sender="MAIA <maia@mondomaine.example>",
                recipient="   ",
            )


if __name__ == "__main__":
    unittest.main()
