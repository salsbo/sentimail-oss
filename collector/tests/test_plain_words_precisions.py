"""Un grief d'identité doit nommer la marque, le domaine, et ce qu'on attendait.

« Le nom affiché est celui d'une marque connue, mais le message vient
d'ailleurs » : quelle marque, et venant d'où ? Le 27 août, un destinataire a
reçu cette phrase pour un message signé « DISNEY+ RECOVERY » et n'a pas pu la vérifier. Les trois faits
étaient dans l'indice, en base, depuis le début.
"""

from __future__ import annotations

import unittest

from sentimail_v3.code.plain_words import plain_clue

FAITS_DISNEY = {
    "brand": "disney",
    "from_apex": "careerwiseenglish.com.au",
    "official_apexes": ["disney.com", "disneyplus.com", "disney.fr"],
}


class MarqueUsurpeeTests(unittest.TestCase):
    def test_la_marque_et_le_domaine_sont_nommes(self) -> None:
        phrase = plain_clue("IDENTITY_BRAND_MISMATCH", "énoncé du Code", FAITS_DISNEY)
        self.assertIn("Disney", phrase)
        self.assertIn("careerwiseenglish.com.au", phrase)

    def test_les_domaines_attendus_sont_dits(self) -> None:
        # Sans eux, le lecteur doit croire sur parole que ce n'est pas le bon.
        phrase = plain_clue("IDENTITY_BRAND_MISMATCH", "énoncé du Code", FAITS_DISNEY)
        self.assertIn("disney.com", phrase)

    def test_aucun_code_interne_ne_transparait(self) -> None:
        phrase = plain_clue("IDENTITY_BRAND_MISMATCH", "énoncé du Code", FAITS_DISNEY)
        for interdit in ("IDENTITY", "apex", "brand", "_"):
            self.assertNotIn(interdit, phrase)

    def test_la_phrase_ne_dit_pas_deux_fois_la_meme_chose(self) -> None:
        # « ... une marque connue, mais le message vient d'ailleurs. Le nom
        # annonce Disney, mais le message a été envoyé depuis... » : la
        # seconde dit tout, la première ne sert plus qu'à faire longueur.
        phrase = plain_clue("IDENTITY_BRAND_MISMATCH", "énoncé du Code", FAITS_DISNEY)
        self.assertNotIn("marque connue", phrase)
        self.assertEqual(phrase.count("message"), 1)

    def test_sans_faits_la_phrase_reste_celle_qu_on_connait(self) -> None:
        phrase = plain_clue("IDENTITY_BRAND_MISMATCH", "énoncé du Code", {})
        self.assertIn("marque connue", phrase)


class OrganisationDementieTests(unittest.TestCase):
    def test_les_sites_officiels_trouves_sont_cites(self) -> None:
        phrase = plain_clue(
            "IDENTITY_CLAIMED_ORGANISATION_REFUTED",
            "énoncé du Code",
            {
                "claimed_organisation": "Disney+",
                "from_apex": "careerwiseenglish.com.au",
                "official_apexes": ["disneyplus.com", "disney.com"],
            },
        )
        self.assertIn("Disney+", phrase)
        self.assertIn("disneyplus.com", phrase)
        self.assertIn("careerwiseenglish.com.au", phrase)


class DomaineVoisinTests(unittest.TestCase):
    def test_le_domaine_imite_est_nomme(self) -> None:
        # Le message peut ne rien annoncer : la phrase montre les deux
        # domaines, pas un nom qu'il n'a pas écrit.
        phrase = plain_clue(
            "IDENTITY_COUSIN_DOMAIN",
            "énoncé du Code",
            {
                "from_apex": "exemp1ebanque.fr",
                "from_domain": "exemp1ebanque.fr",
                "imite": "exemplebanque.fr",
                "imitated_organisation": "exemple banque",
            },
        )
        self.assertIn("exemp1ebanque.fr", phrase)
        self.assertIn("exemplebanque.fr", phrase)
        self.assertNotIn("Le nom annonce", phrase)


class CompteSupposeDetourneTests(unittest.TestCase):
    def test_les_adresses_affichee_et_technique_sont_citees(self) -> None:
        phrase = plain_clue(
            "CORRELATION_COMPROMISED_SENDER",
            "énoncé du Code",
            {
                "identity": {
                    "claimed_name": "Seafy",
                    "displayed_email": "no-reply@seafy.com",
                    "technical_email": "bounce-123@mg.seafy.com",
                }
            },
        )
        self.assertIn("identité annoncée : Seafy", phrase)
        self.assertIn("adresse affichée : no-reply@seafy.com", phrase)
        self.assertIn("adresse technique : bounce-123@mg.seafy.com", phrase)

    def test_l_expediteur_son_metier_et_le_propos_sont_illustres(self) -> None:
        phrase = plain_clue(
            "CORRELATION_COMPROMISED_SENDER",
            "énoncé du Code",
            {
                "identity": {
                    "claimed_name": "Réseaux Martin",
                    "displayed_email": "contact@reseaux-martin.example",
                },
                "activity": {
                    "claimed_name": "Réseaux Martin",
                    "sender_apex": "reseaux-martin.example",
                    "published_activity": (
                        "Installation et maintenance de réseaux professionnels"
                    ),
                    "message_subject": "Votre colis est bloqué en douane",
                },
            },
        )
        self.assertIn("Réseaux Martin", phrase)
        self.assertIn("réseaux professionnels", phrase)
        self.assertIn("colis est bloqué", phrase)
        self.assertIn("reseaux-martin.example", phrase)

    def test_le_detournement_reste_une_hypothese(self) -> None:
        phrase = plain_clue("CORRELATION_COMPROMISED_SENDER", "", {})
        self.assertIn("peut signaler", phrase)
        self.assertIn("mauvaise interprétation", phrase)


if __name__ == "__main__":
    unittest.main()


class AdresseAuthentiqueTests(unittest.TestCase):
    """« L'expéditeur est bien celui qu'il annonce » laissait croire à la
    légitimité : DMARC prouve que le domaine a écrit, pas qui est derrière."""

    def test_le_domaine_et_l_organisation_sont_nommes(self) -> None:
        phrase = plain_clue(
            "AUTH_DMARC_PASS",
            "énoncé du Code",
            {
                "method": "dmarc",
                "result": "pass",
                "from_apex": "e-ca-paris.fr",
                "claimed_organisation": "Crédit Agricole d'Ile-de-France",
            },
        )
        self.assertEqual(
            phrase,
            "L’adresse d’envoi est authentique : e-ca-paris.fr a bien écrit ce "
            "message. Reste à savoir si e-ca-paris.fr est bien Crédit Agricole "
            "d'Ile-de-France.",
        )

    def test_sans_nom_affiche_on_demande_qui_est_derriere(self) -> None:
        phrase = plain_clue(
            "AUTH_DMARC_PASS",
            "énoncé du Code",
            {"method": "dmarc", "result": "pass", "from_apex": "e-ca-paris.fr"},
        )
        self.assertEqual(
            phrase,
            "L’adresse d’envoi est authentique : e-ca-paris.fr a bien écrit ce "
            "message. Reste à savoir qui est derrière e-ca-paris.fr.",
        )

    def test_un_nom_qui_reprend_le_domaine_ne_se_demande_pas(self) -> None:
        phrase = plain_clue(
            "AUTH_DMARC_PASS",
            "énoncé du Code",
            {"from_apex": "synology.com", "claimed_organisation": "Synology News"},
        )
        self.assertIn("synology.com a bien écrit ce message", phrase)
        self.assertNotIn("est bien Synology", phrase)

    def test_sans_fait_la_phrase_reste_honnete(self) -> None:
        phrase = plain_clue("AUTH_DMARC_PASS", "énoncé du Code", {})
        self.assertNotIn("celui qu’il annonce", phrase)
        self.assertIn("authentique", phrase)
