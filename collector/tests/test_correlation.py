from __future__ import annotations

import unittest

from sentimail_v3.code.correlation import CORRELATIONS, correlations


def _codes(observed: set[str]) -> dict[str, dict[str, object]]:
    return {value["clue_code"]: value for value in correlations(observed)}


class CorrelationTests(unittest.TestCase):
    def test_une_marque_usurpee_sans_authentification_est_une_convergence(self) -> None:
        """Aucun des deux faits ne suffit ; ensemble ils décrivent le montage."""
        found = _codes({"IDENTITY_BRAND_MISMATCH", "AUTH_DMARC_FAIL"})
        self.assertIn("CORRELATION_BRAND_SPOOFING", found)
        self.assertEqual(found["CORRELATION_BRAND_SPOOFING"]["direction"], "adverse")

    def test_une_marque_citee_par_un_expediteur_authentifie_ne_converge_pas(self) -> None:
        # Une agence qui envoie pour son client cite la marque en toute
        # légitimité : sans défaut d'authentification, il n'y a pas de montage.
        self.assertNotIn(
            "CORRELATION_BRAND_SPOOFING", _codes({"IDENTITY_BRAND_MISMATCH"})
        )

    def test_une_signature_non_alignee_vaut_defaut_d_authentification(self) -> None:
        self.assertIn(
            "CORRELATION_BRAND_SPOOFING",
            _codes({"IDENTITY_BRAND_MISMATCH", "AUTH_DKIM_UNALIGNED"}),
        )

    def test_un_formulaire_hors_domaine_sans_authentification_converge(self) -> None:
        found = _codes(
            {"URL_SANDBOX_FORM", "URL_UNAUTHENTICATED_CROSS_APEX", "AUTH_DMARC_FAIL"}
        )
        self.assertIn("CORRELATION_CREDENTIAL_HARVESTING", found)

    def test_un_formulaire_sur_le_domaine_de_l_expediteur_ne_converge_pas(self) -> None:
        self.assertNotIn(
            "CORRELATION_CREDENTIAL_HARVESTING",
            _codes({"URL_SANDBOX_FORM", "AUTH_DMARC_PASS"}),
        )

    def test_une_copie_cachee_promotionnelle_converge(self) -> None:
        found = _codes(
            {
                "HEADERS_RECIPIENT_NOT_ADDRESSED",
                "NATURE_UNVERIFIABLE_PROMOTIONAL_CLAIMS",
            }
        )
        self.assertIn("CORRELATION_UNSOLICITED_BULK", found)

    def test_un_domaine_sosie_recent_converge(self) -> None:
        found = _codes({"IDENTITY_COUSIN_DOMAIN", "SENDER_DOMAIN_RECENT"})
        self.assertIn("CORRELATION_COUSIN_DOMAIN_APPROACH", found)

    def test_un_domaine_du_jour_qui_detourne_les_reponses_converge(self) -> None:
        """Le montage ciblé : un domaine créé pour l'occasion, réponses ailleurs.

        Aucune marque connue n'est imitée, donc rien ne le signale ; ce sont
        la fraîcheur du domaine et le détournement des réponses qui, ensemble,
        décrivent une approche préparée.
        """
        found = _codes({"SENDER_DOMAIN_RECENT", "HEADERS_REPLY_TO_DIFFERENT_DOMAIN"})
        self.assertIn("CORRELATION_PREPARED_APPROACH", found)

    def test_un_domaine_recent_seul_ne_converge_pas(self) -> None:
        self.assertNotIn("CORRELATION_PREPARED_APPROACH", _codes({"SENDER_DOMAIN_RECENT"}))

    def test_une_marque_empruntee_par_un_inconnu_converge_meme_bien_authentifiee(
        self,
    ) -> None:
        """L'usurpateur qui configure correctement son propre domaine.

        « La Poste-Colissimo » depuis notif-colissimo-laposte.info : SPF, DKIM
        et DMARC y sont valides, puisque le domaine appartient à l'attaquant.
        Exiger un défaut d'authentification laissait passer le montage le plus
        soigné - quatre fois en boîte de réception, les 12, 13 et 14 août.
        """
        found = _codes({"IDENTITY_BRAND_MISMATCH", "HISTORY_FIRST_OBSERVATION"})
        self.assertIn("CORRELATION_BRAND_FIRST_CONTACT", found)

    def test_une_marque_deja_recue_et_acceptee_ne_converge_pas(self) -> None:
        # La lettre d'information d'une marque, envoyée par son prestataire
        # habituel et déjà acceptée, ne doit pas ressortir à chaque envoi.
        self.assertNotIn(
            "CORRELATION_BRAND_FIRST_CONTACT",
            _codes({"IDENTITY_BRAND_MISMATCH", "HISTORY_CONFIRMED_LEGITIMATE_SENDER"}),
        )

    def test_un_message_ordinaire_ne_produit_aucune_convergence(self) -> None:
        self.assertEqual(
            correlations({"AUTH_DMARC_PASS", "STRUCT_PARSEABLE", "NATURE_BULK_MAILING"}),
            [],
        )

    def test_chaque_convergence_nomme_les_indices_qui_la_fondent(self) -> None:
        """Une corrélation qui ne dit pas d'où elle vient n'est pas une preuve."""
        for value in correlations({code for rule in CORRELATIONS for code in rule.requires}):
            self.assertTrue(value["facts"]["supporting_clue_codes"])

    def test_chaque_convergence_designe_une_technique_du_registre(self) -> None:
        for rule in CORRELATIONS:
            self.assertTrue(rule.technique_code)


if __name__ == "__main__":
    unittest.main()
