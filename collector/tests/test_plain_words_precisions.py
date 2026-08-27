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
    def test_la_marque_imitee_est_nommee(self) -> None:
        phrase = plain_clue(
            "IDENTITY_COUSIN_DOMAIN",
            "énoncé du Code",
            {
                "brand": "paypal",
                "from_apex": "paypa1.com",
                "official_apexes": ["paypal.com"],
            },
        )
        self.assertIn("PayPal", phrase)
        self.assertIn("paypa1.com", phrase)


if __name__ == "__main__":
    unittest.main()
