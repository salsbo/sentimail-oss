from __future__ import annotations

import unittest

from sentimail_v3.code.activity_coherence import (
    COHERENCE_PROMPT,
    coherence_clue,
    coherence_question,
    should_ask,
)


class ShouldAskTests(unittest.TestCase):
    """La question ne se pose que si elle peut apprendre quelque chose."""

    def test_un_expediteur_inconnu_avec_un_site_lisible_merite_la_question(self) -> None:
        self.assertTrue(
            should_ask(
                site_headline="Mutuelle santé, prévoyance et retraite complémentaire",
                clue_codes={"HISTORY_FIRST_OBSERVATION"},
            )
        )

    def test_un_correspondant_habituel_ne_merite_pas_la_question(self) -> None:
        # Son métier ne change pas d'un message à l'autre, et l'historique dit
        # déjà l'essentiel : dépenser un appel ici n'apprendrait rien.
        self.assertFalse(
            should_ask(
                site_headline="Mutuelle santé, prévoyance",
                clue_codes={"HISTORY_CONFIRMED_LEGITIMATE_SENDER"},
            )
        )

    def test_un_site_muet_ne_merite_pas_la_question(self) -> None:
        self.assertFalse(
            should_ask(site_headline="", clue_codes={"HISTORY_FIRST_OBSERVATION"})
        )

    def test_un_site_trop_court_ne_merite_pas_la_question(self) -> None:
        self.assertFalse(
            should_ask(site_headline="Bienvenue", clue_codes={"HISTORY_FIRST_OBSERVATION"})
        )

    def test_un_apex_deja_etabli_localement_ne_merite_pas_la_question(self) -> None:
        # Un envoyeur mutualisé tire une adresse au hasard à chaque message :
        # l'expéditeur reste éternellement inédit à l'adresse alors que son
        # domaine a déjà livré vingt et un messages. L'historique tranche.
        self.assertFalse(
            should_ask(
                site_headline="Recherche en intelligence artificielle et sécurité",
                clue_codes={
                    "HISTORY_FIRST_OBSERVATION",
                    "HISTORY_APEX_ESTABLISHED_LOCALLY",
                },
            )
        )

    def test_un_menu_de_navigation_ne_merite_pas_la_question(self) -> None:
        # Le seuil de longueur laisse passer un menu : il est long. Il ne dit
        # pourtant aucun métier, et le comparer à un objet ne peut rien
        # apprendre - seulement accuser.
        self.assertFalse(
            should_ask(
                site_headline=(
                    "Home \\ Anthropic Skip to main content Skip to footer "
                    "Research Overview Alignment Economics Engineering Frontier "
                    "Red Team Interpretability Science Societal Impacts Policy"
                ),
                clue_codes={"HISTORY_FIRST_OBSERVATION"},
            )
        )

    def test_un_code_ou_une_verification_de_compte_ne_compare_pas_les_metiers(
        self,
    ) -> None:
        for purpose in ("one_time_authentication", "account_security"):
            with self.subTest(purpose=purpose):
                self.assertFalse(
                    should_ask(
                        site_headline=(
                            "Wi-Fi à bord, connectivité et services sur les ferries"
                        ),
                        clue_codes={"HISTORY_FIRST_OBSERVATION"},
                        message_purpose=purpose,
                    )
                )


class CoherenceClueTests(unittest.TestCase):
    def test_une_incoherence_affirmee_devient_un_indice_a_charge(self) -> None:
        clue = coherence_clue(
            {"coherent": False, "explication": "Un installateur réseau n’expédie pas de colis."},
            sender_apex="fioresrl.com",
            published_activity="Installation et maintenance de réseaux professionnels",
            message_subject="Votre colis est bloqué en douane",
        )
        self.assertIsNotNone(clue)
        self.assertEqual(clue["clue_code"], "SENDER_ACTIVITY_INCOHERENT")
        self.assertEqual(clue["direction"], "adverse")
        self.assertIn("colis", str(clue["statement"]))

    def test_une_coherence_confirmee_devient_un_indice_favorable(self) -> None:
        clue = coherence_clue(
            {"coherent": True, "explication": "Une mutuelle envoie des codes de sécurité."},
            sender_apex="harmonie-mutuelle.fr",
        )
        self.assertEqual(clue["clue_code"], "SENDER_ACTIVITY_COHERENT")
        self.assertEqual(clue["direction"], "favorable")

    def test_une_reponse_illisible_ne_produit_aucun_indice(self) -> None:
        """Un modèle muet ou incohérent ne doit rien affirmer à sa place."""
        for reponse in ({}, {"coherent": "peut-être"}, {"explication": "..."}, None):
            with self.subTest(reponse=reponse):
                self.assertIsNone(coherence_clue(reponse, sender_apex="x.fr"))

    def test_l_indice_cite_ce_qui_l_a_fonde(self) -> None:
        clue = coherence_clue(
            {"coherent": False, "explication": "Sans rapport."},
            sender_apex="x.fr",
            display_name="Entreprise X",
            published_activity="Installation de réseaux pour entreprises",
            message_subject="Colis à dédouaner",
        )
        self.assertEqual(clue["facts"]["sender_apex"], "x.fr")
        self.assertIn("explication", clue["facts"])
        self.assertIn("réseaux", clue["facts"]["published_activity"])
        self.assertEqual(clue["facts"]["message_subject"], "Colis à dédouaner")

    def test_une_accusation_sans_activite_observee_est_refusee(self) -> None:
        clue = coherence_clue(
            {"coherent": False, "explication": "Le propos serait incohérent."},
            sender_apex="x.fr",
        )
        self.assertIsNone(clue)

    def test_un_objet_invente_comme_nom_affiche_est_refuse(self) -> None:
        clue = coherence_clue(
            {
                "coherent": False,
                "explication": (
                    "Le nom affiché (Vérifie ton compte) ne correspond pas "
                    "à l’activité de Wi-Fi maritime."
                ),
            },
            sender_apex="seafy.com",
            display_name="Seafy",
            published_activity="Wi-Fi et connectivité à bord des ferries",
            message_subject="Vérifie ton compte Seafy",
        )
        self.assertIsNone(clue)


class PromptTests(unittest.TestCase):
    def test_la_reponse_et_sa_demande_citee_sont_separees(self) -> None:
        question = coherence_question(
            site_headline="Services aux entreprises et missions professionnelles",
            display_name="Conseillère RH", subject="Documents de mission",
            body="Documents fournis.\n> Envoyez le RIB sans délai.",
        )
        current, quoted = question.split("FIL CITÉ (non authentifié) :")
        self.assertIn("Documents fournis.", current)
        self.assertNotIn("Envoyez le RIB", current)
        self.assertIn("Envoyez le RIB", quoted)

    def test_le_doute_profite_a_l_expediteur(self) -> None:
        """Sans cette règle, tout site mal rédigé deviendrait suspect."""
        self.assertIn("doute", COHERENCE_PROMPT.casefold())

    def test_le_prompt_ne_demande_aucun_verdict(self) -> None:
        # Il apprécie une correspondance, il ne juge pas le message : le
        # verdict appartient au moteur de jugement, pas à cette question.
        for mot in ("spam", "phishing", "dangereux", "livrer"):
            self.assertNotIn(mot, COHERENCE_PROMPT.casefold())

    def test_le_prompt_exige_une_illustration_concrete(self) -> None:
        for element in ("organisation", "activité publiée", "sujet du message"):
            self.assertIn(element, COHERENCE_PROMPT)


if __name__ == "__main__":
    unittest.main()
