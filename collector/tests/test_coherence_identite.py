from __future__ import annotations

import unittest

from sentimail_v3.code.activity_coherence import (
    COHERENCE_PROMPT,
    coherence_question,
    should_ask,
)

SITE_IMPRIMANTES = (
    "Printer Point - vente et réparation d'imprimantes, cartouches et "
    "consommables pour particuliers et entreprises."
)


class LaQuestionPoseeTests(unittest.TestCase):
    """Le nom affiché fait partie de la comparaison, sinon elle est aveugle.

    « CIC-Passerelle <info@printerpoint.co.in> » : le modèle ne voyait que le
    propos du message et le métier de printerpoint. Il a répondu, sans se
    tromper dans son cadre, qu'un vendeur d'imprimantes peut envoyer une
    notification - et le destinataire a lu « Ce message correspond bien à
    l'activité de cet expéditeur » sur une usurpation de banque.
    """

    def test_le_nom_affiche_est_dans_la_question(self) -> None:
        question = coherence_question(
            site_headline=SITE_IMPRIMANTES,
            display_name="CIC-Passerelle",
            subject="MARTIN, Vous avez un nouveau message.",
            body="Consultez votre messagerie sécurisée.",
        )
        self.assertIn("CIC-Passerelle", question)

    def test_le_site_et_le_propos_y_sont_toujours(self) -> None:
        question = coherence_question(
            site_headline=SITE_IMPRIMANTES,
            display_name="Printer Point",
            subject="Votre commande",
            body="Votre cartouche est expédiée.",
        )
        self.assertIn("imprimantes", question)
        self.assertIn("Votre commande", question)
        self.assertIn("cartouche", question)

    def test_un_nom_affiche_vide_ne_casse_pas_la_question(self) -> None:
        question = coherence_question(
            site_headline=SITE_IMPRIMANTES, display_name="",
            subject="Objet", body="Corps",
        )
        self.assertIn("Objet", question)

    def test_chaque_element_est_annonce_par_son_role(self) -> None:
        # Trois blocs colles sans etiquette se lisent comme un seul texte.
        question = coherence_question(
            site_headline=SITE_IMPRIMANTES, display_name="CIC-Passerelle",
            subject="Objet", body="Corps",
        )
        for etiquette in ("NOM AFFICHÉ", "SITE", "MESSAGE"):
            with self.subTest(etiquette=etiquette):
                self.assertIn(etiquette, question)


class ConsigneDuModeleTests(unittest.TestCase):
    """La consigne doit nommer le cas qu'elle manquait."""

    def test_l_identite_revendiquee_est_un_motif_d_incoherence(self) -> None:
        self.assertIn("nom affiché", COHERENCE_PROMPT)

    def test_la_consigne_ne_dit_plus_d_ignorer_le_message(self) -> None:
        # « Tu ne juges pas le message » faisait ecarter la seule chose qui
        # trahissait l'usurpation.
        self.assertNotIn("Tu ne juges pas le message", COHERENCE_PROMPT)

    def test_le_doute_reste_favorable(self) -> None:
        # Le repli prudent demeure : une accusation par defaut serait pire.
        self.assertIn("coherent=true", COHERENCE_PROMPT)


class QuandPoserLaQuestionTests(unittest.TestCase):
    """Les conditions d'appel ne changent pas."""

    def test_un_site_muet_ne_declenche_rien(self) -> None:
        self.assertFalse(should_ask("Bienvenue", set()))

    def test_un_expediteur_deja_confirme_ne_declenche_rien(self) -> None:
        self.assertFalse(
            should_ask(SITE_IMPRIMANTES, {"HISTORY_CONFIRMED_LEGITIMATE_SENDER"})
        )

    def test_un_inconnu_au_site_parlant_declenche(self) -> None:
        self.assertTrue(should_ask(SITE_IMPRIMANTES, set()))


if __name__ == "__main__":
    unittest.main()
