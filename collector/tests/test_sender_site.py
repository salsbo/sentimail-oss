from __future__ import annotations

import unittest

from sentimail_v3.code.sender_site import (
    is_interstitial,
)
from sentimail_v3.code.sender_site import (
    activity_registers,
    site_contradicts_message,
)

FIORE = (
    "Fiore Srl - Soluzioni ICT integrate: distribuzione e supporto per "
    "cablaggio, networking e comunicazione unificata. Chi Siamo Prodotti"
)
MORENI = (
    "Arredamenti Moreni CUCINA CAMERA DA LETTO CAMERETTA BAGNI SOGGIORNO "
    "COMPLEMENTI D'ARREDO Chi siamo I nostri Brand Progettazione"
)
FAUX_LAPOSTE = (
    "LA POSTE : notif-colissimo-laposte.info SOCLE NOTIFICATION GROUPE LA "
    "POSTE Infrastructure de routage email transactionnel"
)
TRANSPORTEUR = (
    "Transport et logistique : suivi de colis, livraison express, "
    "expédition nationale et internationale, points relais"
)


class ActivityRegisterTests(unittest.TestCase):
    def test_un_message_de_livraison_est_reconnu(self) -> None:
        self.assertIn(
            "livraison",
            activity_registers(
                "Votre paquet est en attente de vos instructions",
                "Votre colis n'a pas pu être livré. Régularisez les frais de port.",
            ),
        )

    def test_le_vocabulaire_reel_des_arnaques_au_colis_est_couvert(self) -> None:
        """Sujets réellement reçus : « paquet », « retrait », « envoi »."""
        for sujet in (
            "Votre paquet est en attente de vos instructions",
            "Votre envoi n'a pas pu être remis",
            "Point de retrait : action requise",
        ):
            with self.subTest(sujet=sujet):
                self.assertIn("livraison", activity_registers(sujet, ""))

    def test_un_message_bancaire_est_reconnu(self) -> None:
        self.assertIn(
            "paiement",
            activity_registers(
                "Virement en attente",
                "Merci de confirmer vos coordonnées bancaires et votre IBAN.",
            ),
        )

    def test_un_message_ordinaire_n_invoque_aucun_registre(self) -> None:
        self.assertEqual(
            activity_registers("Compte rendu de réunion", "Voici les notes de lundi."),
            set(),
        )


# Extraits réels : le métier est annoncé en tête, mais la livraison est
# mentionnée plus bas - comme sur presque tout site commercial.
FIORE_COMPLET = (
    "Fiore Srl - Soluzioni ICT integrate: distribuzione e supporto per "
    "cablaggio, networking e comunicazione unificata. Vai al contenuto "
    "Chi Siamo Prodotti Servizi Contatti. " + "Testo di presentazione. " * 20
    + "La nostra affidabilita non si esaurisce con la velocita nella consegna "
    "dei prodotti. Sede Uffici direzionali e logistica a Paderno Dugnano."
)
MORENI_COMPLET = (
    "Arredamenti Moreni CUCINA CAMERA DA LETTO CAMERETTA BAGNI SOGGIORNO "
    "COMPLEMENTI D'ARREDO Chi siamo I nostri Brand Progettazione Servizi. "
    + "Descrizione dei nostri prodotti su misura. " * 20
    + "Montaggio Consegna e Montaggio prestando attenzione ai dettagli."
)


class SiteContradictionTests(unittest.TestCase):
    def test_une_mention_de_livraison_en_bas_de_page_ne_fait_pas_le_metier(self) -> None:
        """Fiore vend du réseau et mentionne la « consegna » plus bas : le
        métier s'annonce en tête, pas dans les conditions de vente."""
        self.assertTrue(site_contradicts_message(FIORE_COMPLET, {"livraison"}))

    def test_un_installateur_reseau_ne_livre_pas_de_colis(self) -> None:
        """Le cas réel : fioresrl.com, une SSII, annonçant un colis."""
        self.assertTrue(site_contradicts_message(FIORE, {"livraison"}))

    def test_un_vendeur_de_meubles_peut_livrer(self) -> None:
        # Portée volontairement réduite : l'ameublement livre ses clients, donc
        # ce signal ne l'attrape plus. Retenir à tort un code de sécurité coûte
        # plus cher qu'un indice de moins sur un envoi que d'autres signaux
        # couvrent déjà.
        self.assertFalse(site_contradicts_message(MORENI, {"livraison"}))

    def test_un_transporteur_peut_parler_de_colis(self) -> None:
        self.assertFalse(site_contradicts_message(TRANSPORTEUR, {"livraison"}))

    def test_sans_registre_invoque_il_n_y_a_rien_a_contredire(self) -> None:
        self.assertFalse(site_contradicts_message(MORENI, set()))

    def test_un_site_muet_ne_contredit_rien(self) -> None:
        # Sans contenu lisible, on ne sait pas : l'absence n'accuse pas.
        self.assertFalse(site_contradicts_message("", {"livraison"}))


MUTUELLE = (
    "Mutuelle santé, prévoyance et retraite complémentaire | Harmonie Mutuelle "
    "Accéder directement au contenu Tarif en 2 minutes Espace personnel "
    "Particuliers Entrepreneurs Mes salariés Entreprises ESS Nous découvrir "
    "Suivez-nous sur Instagram LinkedIn Facebook"
)


class ActiviteNonIdentifieeTests(unittest.TestCase):
    """Ne pas reconnaître un métier n'est pas constater qu'il diffère."""

    def test_une_mutuelle_peut_parler_d_argent(self) -> None:
        # « Mutuelle, prévoyance » identifie le secteur financier : un message
        # de remboursement ou de cotisation y est plausible.
        self.assertFalse(site_contradicts_message(MUTUELLE, {"paiement"}))

    def test_un_metier_non_reconnu_ne_contredit_rien(self) -> None:
        # Un site dont le secteur nous échappe ne prouve rien. Le contraire
        # avait retenu un code de sécurité de mutuelle, faute d'avoir su lire
        # son métier. C'est le principe déjà tenu pour un titulaire RDAP masqué.
        self.assertFalse(
            site_contradicts_message(
                "Association loi 1901 pour la sauvegarde du patrimoine local "
                "et l'animation culturelle de la vallée. Nos actions, nos "
                "adhérents, notre histoire et nos rendez-vous.",
                {"livraison"},
            )
        )

    def test_un_secteur_identifie_et_incompatible_contredit(self) -> None:
        # Un installateur réseau n'annonce pas de colis : c'est le cas réel du
        # 16 août, un serveur compromis dont le métier trahissait le message.
        self.assertTrue(site_contradicts_message(FIORE_COMPLET, {"livraison"}))


if __name__ == "__main__":
    unittest.main()


class UnePageDeVerificationNeDecritAucuneActiviteTests(unittest.TestCase):
    """« Enable JavaScript and cookies to continue » n'est pas un métier.

    Le 21/08, une alerte de connexion OpenAI a été retenue parce que le modèle
    comparait le message à cette phrase : la sandbox n'avait pas obtenu le site
    d'OpenAI mais l'interstitiel de son hébergeur. Le modèle a répondu, sans se
    tromper, que le site n'avait rien à voir avec OpenAI - et c'est le message
    qui en a payé le prix.

    Ces pages sont reconnaissables et n'appartiennent à personne : les traiter
    comme une description d'activité revient à accuser un expéditeur de ce que
    son hébergeur a répondu à notre place.
    """

    def test_les_interstitiels_connus_sont_ecartes(self) -> None:
        for page in (
            "Enable JavaScript and cookies to continue",
            "Just a moment... Checking your browser before accessing the site.",
            "Verify you are human by completing the action below.",
            "Attention Required! | Cloudflare · Please enable cookies.",
            "Access denied · Error 1020 · You do not have access to this page.",
            "Please turn JavaScript on and reload the page to continue browsing.",
        ):
            with self.subTest(page=page[:30]):
                self.assertTrue(is_interstitial(page), page)

    def test_une_vraie_page_d_accueil_est_gardee(self) -> None:
        for page in (
            "Mermaid Chart Products Solutions Pricing Community Open Source Docs "
            "Contact sales You already think in systems. Now you can diagram them.",
            "Mutuelle santé, prévoyance et retraite complémentaire pour les "
            "entreprises et les particuliers depuis 1945.",
        ):
            with self.subTest(page=page[:30]):
                self.assertFalse(is_interstitial(page), page)

    def test_une_page_riche_qui_mentionne_javascript_est_gardee(self) -> None:
        # Beaucoup de sites demandent JavaScript en note de bas de page tout en
        # decrivant leur metier : c'est la page reduite a ce message qui ne
        # dit rien, pas la mention elle-meme.
        page = (
            "Banque et assurances pour les particuliers, les professionnels et "
            "les entreprises. Consultez vos comptes, effectuez vos virements et "
            "souscrivez en ligne. Pour une meilleure expérience, veuillez "
            "activer JavaScript dans votre navigateur."
        )
        self.assertFalse(is_interstitial(page))
