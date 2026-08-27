from __future__ import annotations

import unittest

from sentimail_v3.code.organisation import organisation_signature, same_organisation


def _rdap(nom: str, email: str = "") -> dict[str, object]:
    vcard: list[list[object]] = [["fn", {}, "text", nom]]
    if email:
        vcard.append(["email", {}, "text", email])
    return {
        "entities": [
            {"roles": ["registrant"], "vcardArray": ["vcard", vcard]}
        ]
    }


class AnonymisationTests(unittest.TestCase):
    """Un titulaire masqué ne dit rien, et ne doit rapprocher personne.

    Depuis le RGPD, les registres remplacent le nom du titulaire par un
    libellé de substitution. Le filtre en connaissait quelques-uns mais pas
    « Anonymous » ni « Ano Nymous », celui qu'OVH inscrit - alors deux
    domaines anonymisés chez le même bureau partageaient une signature et
    passaient pour appartenir au même maître.

    C'est exactement ce que le module s'interdit dans son propre en-tête :
    retenir un intermédiaire partagé ferait de tout l'internet une seule
    maison. L'intention était juste, le motif la trahissait.
    """

    def test_les_libelles_de_substitution_ne_signent_rien(self) -> None:
        for masque in (
            "Ano Nymous",
            "ANONYMOUS",
            "Anonymous",
            "REDACTED FOR PRIVACY",
            "Data Protected",
            "Whois Privacy Service",
            "Not Disclosed",
            "Non divulgué",
            "GDPR Masked",
            "Privacy Protect, LLC",
        ):
            with self.subTest(masque=masque):
                self.assertEqual(organisation_signature(_rdap(masque)), set())

    def test_deux_domaines_anonymises_ne_se_rapprochent_plus(self) -> None:
        gauche = organisation_signature(_rdap("Ano Nymous", "abuse@ovh.net"))
        droite = organisation_signature(_rdap("Ano Nymous", "abuse@ovh.net"))
        self.assertFalse(same_organisation(gauche, droite))

    def test_un_vrai_titulaire_signe_toujours(self) -> None:
        signature = organisation_signature(_rdap("Air France KLM"))
        self.assertTrue(signature)
        self.assertIn("air france klm", signature)

    def test_deux_domaines_du_meme_titulaire_se_reconnaissent(self) -> None:
        gauche = organisation_signature(_rdap("Twitter, Inc."))
        droite = organisation_signature(_rdap("Twitter Inc"))
        self.assertTrue(same_organisation(gauche, droite))

    def test_le_bureau_d_enregistrement_ne_signe_pas_a_lui_seul(self) -> None:
        # Une adresse d'abus chez l'hébergeur est partagée par tous ses
        # clients : elle ne désigne pas une organisation.
        signature = organisation_signature(_rdap("Ano Nymous", "abuse@ovh.net"))
        self.assertNotIn("@ovh.net", signature)

    def test_un_titulaire_reel_garde_son_adresse(self) -> None:
        signature = organisation_signature(_rdap("Air France KLM", "dns@airfrance.fr"))
        self.assertIn("@airfrance.fr", signature)


if __name__ == "__main__":
    unittest.main()
