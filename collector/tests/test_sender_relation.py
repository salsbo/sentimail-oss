"""Le domaine qui écrit et ce que le message dit de lui : les briques pures.

Le 16 septembre 2026, « Annuel-Famille <noreply@mozn.space> » a livré un faux
reçu « Prime Famille » : le nom affiché ne désignait personne, le site était
muet, et les deux contrôles d'identité se sont tus. La marque empruntée était
dans le corps, que ni l'un ni l'autre ne lisait. Ce module confronte le
domaine réel à ce que le message affiche, où qu'il l'affiche, et rend toujours
un constat.
"""

from __future__ import annotations

import unittest

from sentimail_v3.code.families import family_of
from sentimail_v3.code.identity_relation import (
    CLAIM_PROMPT,
    claim_question,
    claimed_in_message,
    names_the_recipient,
    parse_claim,
)
from sentimail_v3.code.plain_words import _PLAIN
from sentimail_v3.code.sender_relation import (
    activity_readable,
    consistent_clue,
    footprint_clue,
    published_activity,
    unverified_clue,
)

TEXTE_PRIME = (
    "prime CONFIRMÉ Votre paiement a été accepté Bonjour MARTIN ALICE "
    "Réf. FR-827364-2026 Montant 69,90 € Prime Famille — Abonnement annuel "
    "activé Gérer mon abonnement Annulation possible sous 14 jours."
)


class ClaimedInMessageTests(unittest.TestCase):
    """Le modèle propose, le message confirme : une identité qu'il n'affiche pas
    ne peut fonder aucune accusation."""

    def test_une_marque_ecrite_dans_le_corps_est_revendiquee(self) -> None:
        self.assertTrue(
            claimed_in_message(
                "Prime Famille",
                display_name="Annuel-Famille",
                subject="ALICE, Achat confirmé",
                text=TEXTE_PRIME,
            )
        )

    def test_tous_les_mots_du_nom_doivent_etre_ecrits(self) -> None:
        # « Amazon Prime » quand seul « prime » est écrit : Amazon est une
        # lecture du modèle, pas une revendication du message.
        self.assertFalse(
            claimed_in_message(
                "Amazon Prime", display_name="Annuel-Famille", subject="", text=TEXTE_PRIME
            )
        )

    def test_un_nom_commun_ne_fait_pas_une_organisation(self) -> None:
        self.assertFalse(
            claimed_in_message(
                "Société Générale",
                display_name="Compta",
                subject="Bilan",
                text="Votre société a clôturé son exercice.",
            )
        )

    def test_le_nom_affiche_compte_comme_texte_du_message(self) -> None:
        self.assertTrue(
            claimed_in_message(
                "Doctolib", display_name="Doctolib", subject="Rappel", text="Votre rendez-vous"
            )
        )

    def test_un_sigle_ecrit_lettre_a_lettre_est_reconnu(self) -> None:
        self.assertTrue(
            claimed_in_message("CIC", display_name="C I C", subject="", text="Nouveau message")
        )

    def test_un_nom_vide_ne_revendique_rien(self) -> None:
        self.assertFalse(claimed_in_message("", display_name="X", subject="", text="X"))


class NamesTheRecipientTests(unittest.TestCase):
    """Ce qui part vers le moteur de recherche ne doit jamais être le destinataire."""

    def test_le_nom_du_destinataire_est_reconnu(self) -> None:
        self.assertTrue(names_the_recipient("MARTIN ALICE", "amartin@example.org"))

    def test_une_marque_n_est_pas_le_destinataire(self) -> None:
        self.assertFalse(names_the_recipient("Prime Famille", "amartin@example.org"))

    def test_sans_destinataire_rien_n_est_refuse(self) -> None:
        self.assertFalse(names_the_recipient("Martin", ""))

    def test_un_mot_court_ne_suffit_pas(self) -> None:
        # « Lu » dans « lucie@ » : trois lettres ne désignent personne.
        self.assertFalse(names_the_recipient("Lu Conseil", "lucie@exemple.fr"))


class ClaimParsingTests(unittest.TestCase):
    def test_l_organisation_est_lue_dans_la_reponse(self) -> None:
        self.assertEqual(
            parse_claim('{"organisation": "Prime Famille", "sujet": "reçu"}'),
            "Prime Famille",
        )

    def test_une_absence_d_organisation_rend_une_chaine_vide(self) -> None:
        for reponse in ('{"organisation": null}', '{"organisation": ""}', "{}", "pas du json", ""):
            with self.subTest(reponse=reponse):
                self.assertEqual(parse_claim(reponse), "")

    def test_la_reponse_est_bornee(self) -> None:
        self.assertLessEqual(len(parse_claim('{"organisation": "' + "A" * 500 + '"}')), 80)


class ClaimPromptTests(unittest.TestCase):
    def test_la_consigne_exige_le_nom_tel_qu_ecrit(self) -> None:
        prompt = CLAIM_PROMPT.casefold()
        self.assertIn("tel qu", prompt)
        self.assertIn("null", prompt)

    def test_la_consigne_ecarte_le_nom_commun(self) -> None:
        # « votre prime de fin d'année » n'est pas Prime Video.
        self.assertIn("nom commun", CLAIM_PROMPT.casefold())

    def test_la_question_porte_le_nom_l_objet_et_le_texte(self) -> None:
        question = claim_question(
            display_name="Annuel-Famille", subject="Achat confirmé", text=TEXTE_PRIME
        )
        self.assertIn("Annuel-Famille", question)
        self.assertIn("Achat confirmé", question)
        self.assertIn("Prime Famille", question)

    def test_le_texte_est_borne(self) -> None:
        question = claim_question(display_name="", subject="", text="x" * 10_000)
        self.assertLess(len(question), 3_000)


class OutcomeTests(unittest.TestCase):
    """Un constat, jamais zéro : ne pas savoir s'écrit, il n'accuse pas."""

    def test_sans_repondant_est_un_fait_neutre(self) -> None:
        clue = footprint_clue(
            "mozn.space",
            claimed="",
            results_on_domain=0,
            site_read=False,
        )
        self.assertEqual(clue["clue_code"], "SENDER_WITHOUT_PUBLIC_FOOTPRINT")
        self.assertEqual(clue["article_code"], "DEEP-023")
        self.assertEqual(clue["direction"], "neutral")
        self.assertEqual(clue["strength"], 0)
        self.assertIn("mozn.space", clue["statement"])
        self.assertEqual(clue["facts"]["from_apex"], "mozn.space")

    def test_non_verifie_est_distinct_de_sans_repondant(self) -> None:
        clue = unverified_clue("mozn.space", reason="search_unavailable")
        self.assertEqual(clue["clue_code"], "SENDER_RELATION_UNVERIFIED")
        self.assertEqual(clue["article_code"], "DEEP-023")
        self.assertEqual(clue["direction"], "neutral")
        self.assertEqual(clue["facts"]["reason"], "search_unavailable")

    def test_un_nom_qui_reprend_le_domaine_est_un_constat_neutre(self) -> None:
        # Un rapport plausible n'est pas une preuve d'authenticité : rassurer
        # sur cette base referait l'erreur que ce contrôle existe pour corriger.
        clue = consistent_clue("synology.com", organisation="Synology News", how="domain_label")
        self.assertEqual(clue["clue_code"], "SENDER_RELATION_CONSISTENT")
        self.assertEqual(clue["direction"], "neutral")
        self.assertEqual(clue["strength"], 0)
        self.assertEqual(clue["facts"]["how"], "domain_label")


class PublishedActivityTests(unittest.TestCase):
    def test_le_site_lisible_passe_en_premier(self) -> None:
        texte, source = published_activity(
            {"apex": "exemple.fr", "text": "Mutuelle santé, prévoyance et retraite complémentaire."},
            [{"title": "Autre", "content": "Rien"}],
        )
        self.assertIn("Mutuelle", texte)
        self.assertEqual(source, "site")

    def test_sans_site_la_recherche_sur_le_domaine_decrit_le_metier(self) -> None:
        texte, source = published_activity(
            None,
            [
                {"title": "CareerWise English", "url": "https://careerwiseenglish.com.au/",
                 "content": "English school for international students in Sydney."},
            ],
        )
        self.assertIn("English school", texte)
        self.assertEqual(source, "search")

    def test_sans_rien_le_metier_est_inconnu(self) -> None:
        self.assertEqual(published_activity(None, []), ("", ""))

    def test_le_texte_de_recherche_est_borne(self) -> None:
        texte, _ = published_activity(None, [{"title": "T", "content": "x" * 5000}] * 5)
        self.assertLessEqual(len(texte), 700)


class ActivityReadableTests(unittest.TestCase):
    def test_une_description_de_metier_est_lisible(self) -> None:
        self.assertTrue(
            activity_readable("Mutuelle santé, prévoyance et retraite complémentaire.")
        )

    def test_un_mot_de_bienvenue_ne_dit_aucun_metier(self) -> None:
        self.assertFalse(activity_readable("Bienvenue"))

    def test_un_menu_de_navigation_ne_dit_aucun_metier(self) -> None:
        # Le menu d'anthropic.com du 1er septembre 2026 : long, et muet.
        self.assertFalse(
            activity_readable(
                "Home \\ Anthropic Skip to main content Skip to footer "
                "Research Overview Alignment Economics Engineering Frontier"
            )
        )

    def test_un_interstitiel_d_hebergeur_ne_dit_aucun_metier(self) -> None:
        self.assertFalse(activity_readable("Enable JavaScript and cookies to continue"))


class VocabulaireEtFamilleTests(unittest.TestCase):
    def test_chaque_constat_se_dit_en_mots_simples(self) -> None:
        for code in (
            "SENDER_WITHOUT_PUBLIC_FOOTPRINT",
            "SENDER_RELATION_UNVERIFIED",
            "SENDER_RELATION_CONSISTENT",
            "CONTENT_FINANCIAL_CONTEXT",
            "CORRELATION_FAKE_TRANSACTION_LURE",
        ):
            with self.subTest(code=code):
                self.assertIn(code, _PLAIN)

    def test_le_repondant_public_est_une_question_d_identite(self) -> None:
        self.assertEqual(family_of("DEEP-023"), "identite")


if __name__ == "__main__":
    unittest.main()
