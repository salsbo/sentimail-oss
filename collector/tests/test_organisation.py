from __future__ import annotations

import unittest

from sentimail_v3.code.organisation import organisation_signature, same_organisation


def _rdap(org: str = "", email: str = "", handle: str = "") -> dict[str, object]:
    entity: dict[str, object] = {"roles": ["registrant"]}
    vcard: list[list[object]] = [["version", {}, "text", "4.0"]]
    if org:
        vcard.append(["org", {}, "text", org])
    if email:
        vcard.append(["email", {}, "text", email])
    entity["vcardArray"] = ["vcard", vcard]
    if handle:
        entity["handle"] = handle
    return {"entities": [entity]}


class OrganisationSignatureTests(unittest.TestCase):
    def test_le_nom_de_l_organisation_est_retenu(self) -> None:
        # La forme juridique ne fait pas partie de l'identité : « S.A. », « SAS »
        # ou « GmbH » varient d'un enregistrement à l'autre pour un même groupe.
        self.assertIn(
            "credit agricole", organisation_signature(_rdap(org="Crédit Agricole S.A."))
        )

    def test_la_casse_et_les_accents_ne_separent_pas_deux_fois_la_meme_organisation(
        self,
    ) -> None:
        gauche = organisation_signature(_rdap(org="Crédit Agricole S.A."))
        droite = organisation_signature(_rdap(org="CREDIT AGRICOLE SA"))
        self.assertTrue(same_organisation(gauche, droite))

    def test_le_domaine_du_contact_vaut_signature(self) -> None:
        self.assertIn(
            "@example.org", organisation_signature(_rdap(email="dns-admin@example.org"))
        )

    def test_deux_organisations_distinctes_ne_se_confondent_pas(self) -> None:
        self.assertFalse(
            same_organisation(
                organisation_signature(_rdap(org="Alpha SAS")),
                organisation_signature(_rdap(org="Beta GmbH")),
            )
        )

    def test_un_registrant_masque_ne_conclut_rien(self) -> None:
        """Le RGPD masque la plupart des registrants : l'absence n'est pas une preuve."""
        masque = organisation_signature(_rdap(org="REDACTED FOR PRIVACY"))
        self.assertEqual(masque, set())
        self.assertFalse(same_organisation(masque, masque))

    def test_deux_signatures_vides_ne_sont_jamais_la_meme_organisation(self) -> None:
        self.assertFalse(same_organisation(set(), set()))

    def test_un_fournisseur_de_registrar_ne_fait_pas_organisation_commune(self) -> None:
        # Des milliers de domaines partagent le même bureau d'enregistrement :
        # le retenir ferait de tout l'internet une seule organisation.
        gauche = organisation_signature(
            {"entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["org", {}, "text", "OVH SAS"]]]}]}
        )
        self.assertEqual(gauche, set())


if __name__ == "__main__":
    unittest.main()
