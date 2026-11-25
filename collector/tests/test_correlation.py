from __future__ import annotations

import unittest

from sentimail_v3.code.correlation import CORRELATIONS, correlations, identity_facts


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

    def test_un_domaine_sosie_qui_detourne_les_reponses_converge(self) -> None:
        found = _codes({"IDENTITY_COUSIN_DOMAIN", "HEADERS_REPLY_TO_DIFFERENT_DOMAIN"})
        self.assertIn("CORRELATION_COUSIN_DOMAIN_APPROACH", found)

    def test_un_domaine_sosie_seul_ne_forme_pas_l_approche(self) -> None:
        self.assertNotIn(
            "CORRELATION_COUSIN_DOMAIN_APPROACH", _codes({"IDENTITY_COUSIN_DOMAIN"})
        )

    def test_un_domaine_sosie_en_premier_contact_est_une_identite_empruntee(self) -> None:
        found = _codes({"IDENTITY_COUSIN_DOMAIN", "HISTORY_FIRST_OBSERVATION"})
        self.assertIn("CORRELATION_BRAND_FIRST_CONTACT", found)

    def test_une_hypothese_de_phishing_non_authentifiee_converge(self) -> None:
        """Le symbole d'hameçonnage change de sens sans authentification.

        Comme la divergence d'un lien entre DEEP-011 et DEEP-010 : une même
        observation, deux lectures selon que l'expéditeur répond ou non de ce
        qu'il envoie.
        """
        found = _codes({"RSPAMD_PHISHING_HEURISTIC", "AUTH_DMARC_INCONCLUSIVE"})
        self.assertIn("CORRELATION_UNAUTHENTICATED_PHISHING_HEURISTIC", found)
        clue = found["CORRELATION_UNAUTHENTICATED_PHISHING_HEURISTIC"]
        self.assertEqual(clue["article_code"], "CORR-018")
        self.assertEqual(clue["strength"], 45)
        self.assertEqual(
            set(clue["facts"]["supporting_clue_codes"]),
            {"RSPAMD_PHISHING_HEURISTIC", "AUTH_DMARC_INCONCLUSIVE"},
        )

    def test_une_hypothese_de_phishing_authentifiee_reste_neutre(self) -> None:
        # Sous DMARC validé, le symbole est le bruit des campagnes
        # authentifiées : 94 messages sur la base, dont 52 légitimes.
        self.assertNotIn(
            "CORRELATION_UNAUTHENTICATED_PHISHING_HEURISTIC",
            _codes({"RSPAMD_PHISHING_HEURISTIC", "AUTH_DMARC_PASS"}),
        )

    def test_un_dmarc_valide_l_emporte_sur_un_spf_en_echec(self) -> None:
        self.assertNotIn(
            "CORRELATION_UNAUTHENTICATED_PHISHING_HEURISTIC",
            _codes({"RSPAMD_PHISHING_HEURISTIC", "AUTH_DMARC_PASS", "AUTH_SPF_SOFTFAIL"}),
        )

    def test_sans_resultat_d_authentification_rien_ne_converge(self) -> None:
        # Un hook d'authentification en erreur n'écrit aucun défaut : il
        # n'accuse personne.
        self.assertNotIn(
            "CORRELATION_UNAUTHENTICATED_PHISHING_HEURISTIC",
            _codes({"RSPAMD_PHISHING_HEURISTIC"}),
        )

    def test_le_score_eleve_ne_converge_jamais(self) -> None:
        # Le score agrégé additionne les symboles d'authentification déjà
        # comptés par AUTH-002, AUTH-006 et AUTH-008.
        found = correlations({"RSPAMD_HIGH_SCORE", "AUTH_DMARC_FAIL"})
        self.assertNotIn("CORR-018", [value["article_code"] for value in found])

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

    def test_un_apex_deja_etabli_localement_defait_le_compte_detourne(self) -> None:
        # Le premier contact est vrai à perpétuité chez un envoyeur mutualisé,
        # qui tire une adresse au hasard à chaque message. Sans cette réserve,
        # le faisceau se réduisait à son seul membre d'activité et portait à 75
        # ce qu'un unique indice affirmait à 55.
        codes = {
            value["clue_code"]
            for value in correlations(
                {
                    "SENDER_ACTIVITY_INCOHERENT",
                    "HISTORY_FIRST_OBSERVATION",
                    "HISTORY_APEX_ESTABLISHED_LOCALLY",
                    "AUTH_DMARC_PASS",
                }
            )
        }
        self.assertNotIn("CORRELATION_COMPROMISED_SENDER", codes)

    def test_un_apex_inconnu_authentifie_declenche_le_compte_detourne(self) -> None:
        codes = {
            value["clue_code"]
            for value in correlations(
                {"SENDER_ACTIVITY_INCOHERENT", "HISTORY_FIRST_OBSERVATION", "AUTH_DMARC_PASS"}
            )
        }
        self.assertIn("CORRELATION_COMPROMISED_SENDER", codes)

    def test_un_compte_suppose_detourne_garde_les_identites_observees(self) -> None:
        identity = identity_facts(
            "Seafy <no-reply@seafy.com>",
            "bounce-123@mg.seafy.com",
            "support@seafy.com",
        )
        found = {
            value["clue_code"]: value
            for value in correlations(
                {"SENDER_ACTIVITY_INCOHERENT", "HISTORY_FIRST_OBSERVATION", "AUTH_DMARC_PASS"},
                identity=identity,
            )
        }
        facts = found["CORRELATION_COMPROMISED_SENDER"]["facts"]
        self.assertEqual(facts["identity"]["claimed_name"], "Seafy")
        self.assertEqual(
            facts["identity"]["displayed_email"], "no-reply@seafy.com"
        )

    def test_un_compte_suppose_detourne_garde_le_metier_compare(self) -> None:
        found = {
            value["clue_code"]: value
            for value in correlations(
                {"SENDER_ACTIVITY_INCOHERENT", "HISTORY_FIRST_OBSERVATION", "AUTH_DMARC_PASS"},
                evidence={
                    "SENDER_ACTIVITY_INCOHERENT": {
                        "claimed_name": "Réseaux Martin",
                        "sender_apex": "reseaux-martin.example",
                        "published_activity": "Installation de réseaux professionnels",
                        "message_subject": "Votre colis est bloqué",
                    }
                },
            )
        }
        facts = found["CORRELATION_COMPROMISED_SENDER"]["facts"]
        self.assertIn("réseaux professionnels", facts["activity"]["published_activity"])


if __name__ == "__main__":
    unittest.main()


# 15 octobre 2026. Faisceau posé à tort chez une destinataire : M-d0d979
# (lettre d'information). Décision du mainteneur : la séparation vaut pour tous.
class AmbientFormTests(unittest.TestCase):
    """Le formulaire ambiant ne compte que sur la destination étrangère."""

    def test_une_page_de_connexion_ailleurs_que_la_redirection_ne_converge_pas(self) -> None:
        # M-d0d979 : la connexion LinkedIn derrière l'icône, les redirections
        # chez le routeur d'envoi. Rien ne relie le formulaire au détour.
        evidence = {
            "URL_AMBIENT_SENSITIVE_FORM": {"final_apexes": ["linkedin.com"]},
            "URL_UNAUTHENTICATED_CROSS_APEX": {
                "pairs": [["bit.ly", "issuu.com"], ["sendibm3.com", "brevo.com"]]
            },
        }
        found = correlations(
            {"URL_AMBIENT_SENSITIVE_FORM", "URL_UNAUTHENTICATED_CROSS_APEX", "AUTH_DMARC_INCONCLUSIVE"},
            evidence=evidence,
        )
        self.assertNotIn("CORRELATION_CREDENTIAL_HARVESTING", {c["clue_code"] for c in found})

    def test_un_formulaire_sur_la_destination_recente_converge(self) -> None:
        # Un lien direct vers domaine-piege.top/login : ni redirection ni
        # affichage trompeur, mais le formulaire est sur la destination récente.
        evidence = {
            "URL_AMBIENT_SENSITIVE_FORM": {"final_apexes": ["domaine-piege.top"]},
            "URL_CROSS_APEX_FRESH_DESTINATION": {"apexes": ["domaine-piege.top"]},
        }
        found = correlations(
            {"URL_AMBIENT_SENSITIVE_FORM", "URL_CROSS_APEX_FRESH_DESTINATION", "AUTH_DMARC_FAIL"},
            evidence=evidence,
        )
        self.assertIn("CORRELATION_CREDENTIAL_HARVESTING", {c["clue_code"] for c in found})

    def test_un_formulaire_au_bout_de_la_redirection_converge(self) -> None:
        evidence = {
            "URL_AMBIENT_SENSITIVE_FORM": {"final_apexes": ["piege.example"]},
            "URL_SANDBOX_CROSS_APEX": {"pairs": [["suivi.example", "piege.example"]]},
        }
        found = correlations(
            {"URL_AMBIENT_SENSITIVE_FORM", "URL_SANDBOX_CROSS_APEX", "AUTH_DKIM_UNALIGNED"},
            evidence=evidence,
        )
        self.assertIn("CORRELATION_CREDENTIAL_HARVESTING", {c["clue_code"] for c in found})

    def test_un_formulaire_trompeur_converge_toujours(self) -> None:
        evidence = {
            "URL_SANDBOX_FORM": {"final_apexes": ["linkedin.com"]},
            "URL_UNAUTHENTICATED_CROSS_APEX": {"pairs": [["bit.ly", "issuu.com"]]},
        }
        found = correlations(
            {"URL_SANDBOX_FORM", "URL_UNAUTHENTICATED_CROSS_APEX", "AUTH_DMARC_FAIL"},
            evidence=evidence,
        )
        self.assertIn("CORRELATION_CREDENTIAL_HARVESTING", {c["clue_code"] for c in found})


class BrandFirstContactUnreadLinkTests(unittest.TestCase):
    """Revue de sécurité du 15 octobre 2026 : un lien que le bac à sable ne lit
    pas ne prouve pas l'absence d'acte. L'usurpateur qui authentifie son
    propre domaine choisit un chemin en /verify/ ou un jeton dans l'adresse,
    et son lien n'est jamais visité. CORR-006 reste posé ; une dispense pour
    les plateformes qui écrivent au nom de leur client attend l'arbitrage de
    Alice.
    """

    def test_un_lien_non_visite_ne_dispense_pas_le_premier_contact(self) -> None:
        found = _codes({
            "IDENTITY_CLAIMED_ORGANISATION_REFUTED", "HISTORY_FIRST_OBSERVATION",
            "AUTH_DMARC_PASS", "URL_PROTECTED_ACTION_NOT_VISITED",
        })
        self.assertIn("CORRELATION_BRAND_FIRST_CONTACT", found)
