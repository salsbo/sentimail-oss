from __future__ import annotations

import unittest

from sentimail_v3.observation.dossier.hooks.content import (
    _extorsion,
    _FINANCIAL_TRANSFER,
)


class ExtorsionTests(unittest.TestCase):
    def test_le_chantage_est_reconnu_dans_les_deux_langues(self) -> None:
        for texte in (
            "Your account is hacked. Your data is stolen. Learn how to regain access.",
            "I have recorded you through your webcam.",
            "Je vais publier vos videos compromettantes.",
            "Pay me 500 to keep this private.",
        ):
            self.assertTrue(_extorsion(texte), texte)

    def test_un_message_ordinaire_n_est_pas_du_chantage(self) -> None:
        for texte in (
            "Votre commande a bien ete enregistree, merci de votre confiance.",
            "Reunion demain a 14h en salle 3.",
            "Your invoice is attached.",
        ):
            self.assertFalse(_extorsion(texte), texte)

    def test_un_mot_ambigu_seul_n_accuse_personne(self) -> None:
        # Une confirmation d'examen surveillé demande une webcam ; un avis de
        # sécurité parle de comptes piratés. Accusés de chantage sur ce seul
        # mot, ces messages se voyaient poser une question à leur destinataire
        # alors que rien ne pesait contre eux.
        for texte in (
            "A webcam, microphone, and speaker are required for the exam.",
            "Nous vous informons qu'un compte a ete compromis chez un tiers.",
            "Please pay 250 EUR before the due date.",
        ):
            self.assertFalse(_extorsion(texte), texte)

    def test_deux_mots_ambigus_font_un_faisceau(self) -> None:
        self.assertTrue(
            _extorsion("Your device was hacked and I used your webcam.")
        )

    def test_le_meme_mot_repete_ne_compte_qu_une_fois(self) -> None:
        # Répéter « webcam » ne menace pas davantage que le dire une fois.
        self.assertFalse(_extorsion("webcam, webcam et encore webcam"))

    def test_la_rancon_en_cryptomonnaie_est_un_canal_de_paiement(self) -> None:
        for texte in (
            "Send 0.5 bitcoin to this wallet address",
            "Paiement en BTC uniquement",
            "transfer in USDT",
        ):
            self.assertTrue(_FINANCIAL_TRANSFER.search(texte), texte)
