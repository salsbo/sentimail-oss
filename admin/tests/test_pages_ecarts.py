"""La page des écarts se rend, s'instruit, et ne réécrit pas la mesure."""

from __future__ import annotations

import unittest

from sentimail_admin import pages, queries


class PageEcartsTests(unittest.TestCase):
    def test_la_page_vide_se_rend(self) -> None:
        html = pages.page_ecarts([], [], vue_traites=False)
        self.assertIn("Aucun écart à traiter", html)
        self.assertIn("La mesure des désaccords", html)
        self.assertIn("/ecarts?vue=traites", html)

    def test_les_quatre_sens_figurent_dans_la_mesure(self) -> None:
        html = pages.page_ecarts([], [], vue_traites=False)
        self.assertIn("Livré, jugé indésirable", html)
        self.assertIn("Écarté, jugé ordinaire", html)
        self.assertIn("Avis demandé, jugé indésirable", html)
        self.assertIn("Avis demandé, jugé ordinaire", html)

    _ECART = {
        "id": "0f0e0d0c-0b0a-0908-0706-050403020100",
        "direction": "laisse_passer",
        "human_label": "spam",
        "model_classification": "legitimate",
        "model_confidence": 0.92,
        "model_rationale": "Envoi promotionnel authentifié d'un expéditeur connu.",
        "created_at": "2026-08-23 06:30:00+00",
        "acknowledged_at": None,
        "acknowledged_by": None,
        "participant_email": "elisabeth@exemple.org",
        "sender_normalized": "service@marque.example",
        "subject": "Summer Sale Still On",
        "label_context": (
            '{"signals": ["AUTH_DMARC_PASS", "CONTENT_HIDDEN_TEXT_SALTING"], '
            '"llm_reasons": ["Le message contient du texte masqué par CSS."], '
            '"user_reason": "C\'est du spam : bloque les prochains.", '
            '"llm_explanation": "Tu as qualifié ce message de spam."}'
        ),
        "message_id": "1a2b3c4d-5e6f-7081-9203-a4b5c6d7e8f9",
        "charges": (
            '[{"code": "CONTENT_HIDDEN_TEXT_SALTING", "strength": 45, '
            '"statement": "Le message contient du texte masqué par CSS."}]'
        ),
        "deep_complete": True,
        "blocage": None,
    }

    def test_un_ecart_ouvert_porte_son_bouton(self) -> None:
        html = pages.page_ecarts(
            [{"direction": "laisse_passer", "j7": 1, "j30": 2, "ouverts": 1}],
            [dict(self._ECART)],
            vue_traites=False,
        )
        self.assertIn("/ecarts/traiter", html)
        self.assertIn("Marquer traité", html)
        self.assertIn("service@marque.example", html)
        self.assertIn("legitimate", html)
        self.assertIn("0.92", html)

    def test_les_elements_disent_les_deux_jugements_et_la_charge(self) -> None:
        # Instruire un écart, c'est répondre à une question : qu'est-ce que le
        # moteur avait à opposer ? Les deux étiquettes, la charge dite en
        # clair, et les mots de la personne suffisent à y répondre.
        html = pages.page_ecarts([], [dict(self._ECART)], vue_traites=False)
        self.assertIn("<strong>Moteur</strong>", html)
        self.assertIn("<strong>Humain</strong>", html)
        self.assertIn("Ce qui pesait contre", html)
        self.assertIn("texte masqué par CSS", html)
        self.assertIn("CONTENT_HIDDEN_TEXT_SALTING", html)
        self.assertIn("Envoi promotionnel authentifié", html)
        self.assertIn("bloque les prochains", html)
        self.assertIn("<details>", html)

    def test_le_volet_ne_deverse_plus_tout_le_dossier(self) -> None:
        # Les critères favorables noyaient l'unique indice qui avait fait
        # basculer le verdict : ils ne sont plus listés tant que le message
        # existe et que sa charge est connue.
        html = pages.page_ecarts([], [dict(self._ECART)], vue_traites=False)
        self.assertNotIn("AUTH_DMARC_PASS", html)

    def test_ce_qui_a_interdit_la_livraison_est_traduit(self) -> None:
        ecart = dict(self._ECART, blocage='["deep_execution_incomplete"]')
        html = pages.page_ecarts([], [ecart], vue_traites=False)
        self.assertIn("Ce qui a interdit la livraison", html)
        self.assertIn("analyse profonde n&#x27;a pas abouti", html)
        self.assertNotIn("deep_execution_incomplete", html)

    def test_le_preambule_d_analyse_inaboutie_ne_mange_pas_la_conclusion(
        self,
    ) -> None:
        # Un jugement rejeté porte une annonce devant sa motivation d'origine.
        # La console dit déjà, en plus précis, ce qui a empêché de conclure.
        ecart = dict(
            self._ECART,
            model_rationale=(
                "Mon analyse n’a pas pu être menée à son terme, je préfère te "
                "demander. Ce que j’avais retenu jusque-là : "
                "L’expéditeur est authentifié."
            ),
        )
        html = pages.page_ecarts([], [ecart], vue_traites=False)
        self.assertIn("L’expéditeur est authentifié.", html)
        self.assertNotIn("je préfère te demander", html)

    def test_un_message_purge_retombe_sur_les_criteres_de_l_avis(self) -> None:
        ecart = dict(self._ECART, message_id=None, charges=None)
        html = pages.page_ecarts([], [ecart], vue_traites=False)
        self.assertIn("Message purgé", html)
        self.assertIn("AUTH_DMARC_PASS", html)

    def test_un_contexte_absent_ne_casse_pas_la_page(self) -> None:
        ecart = dict(self._ECART, label_context=None, model_rationale=None)
        html = pages.page_ecarts([], [ecart], vue_traites=False)
        self.assertIn("<strong>Moteur</strong>", html)
        self.assertIn("Ce qui pesait contre", html)

    def test_un_contexte_illisible_ne_casse_pas_la_page(self) -> None:
        ecart = dict(self._ECART, label_context="{pas du json")
        html = pages.page_ecarts([], [ecart], vue_traites=False)
        self.assertIn("<strong>Moteur</strong>", html)

    def test_chaque_ecart_porte_sa_reference_citable(self) -> None:
        html = pages.page_ecarts([], [dict(self._ECART)], vue_traites=False)
        self.assertIn("E-0f0e0d", html)
        self.assertIn("<th>Réf.</th>", html)

    def test_une_reference_citee_montre_l_ecart_hors_des_deux_files(self) -> None:
        # Citer une référence désigne un dossier : qu'il soit ouvert ou déjà
        # traité ne doit plus faire répondre « introuvable ».
        ecart = dict(self._ECART, acknowledged_at="2026-08-25 09:00:00+00")
        html = pages.page_ecarts([], [ecart], vue_traites=False, cite="E-0f0e0d")
        self.assertIn("Écart E-0f0e0d", html)
        self.assertIn("traité le", html)
        self.assertNotIn("Marquer traité", html)

    def test_une_reference_sans_correspondance_le_dit(self) -> None:
        html = pages.page_ecarts([], [], vue_traites=False, cite="E-abcdef")
        self.assertIn("Aucun écart ne porte la référence E-abcdef", html)

    def test_la_vue_traites_montre_qui_et_quand(self) -> None:
        html = pages.page_ecarts(
            [],
            [
                {
                    "id": "0f0e0d0c-0b0a-0908-0706-050403020100",
                    "direction": "demande_au_lieu_de_livrer",
                    "human_label": "legitimate",
                    "model_classification": "undetermined",
                    "model_confidence": None,
                    "created_at": "2026-08-22 10:59:00+00",
                    "acknowledged_at": "2026-08-25 09:00:00+00",
                    "acknowledged_by": "100.108.112.2",
                    "participant_email": "elisabeth@exemple.org",
                    "sender_normalized": "prod@exemple.net",
                    "subject": "Votre facture",
                }
            ],
            vue_traites=True,
        )
        self.assertIn("traité le", html)
        self.assertIn("100.108.112.2", html)
        self.assertNotIn("Marquer traité", html)

    def test_l_onglet_existe_dans_la_navigation(self) -> None:
        self.assertIn(("/ecarts", "Écarts"), pages.ONGLETS)

    def test_les_avis_du_geste_existent(self) -> None:
        self.assertIn("ecart_traite", pages.AVIS)
        self.assertIn("ecart_inconnu", pages.AVIS)


class RequetesEcartsTests(unittest.TestCase):
    """Les requêtes se construisent sans base et paramètrent toute saisie."""

    def test_l_acquittement_ne_touche_qu_un_ecart_ouvert(self) -> None:
        sql, params = queries.acknowledge_discrepancy("abc", "1.2.3.4")
        self.assertIn("acknowledged_at IS NULL", sql)
        self.assertNotIn("abc", sql)
        self.assertEqual(params, ("abc", "1.2.3.4"))

    def test_la_mesure_compte_aussi_les_traites(self) -> None:
        sql, _ = queries.discrepancy_metrics()
        self.assertIn("7 days", sql)
        self.assertIn("30 days", sql)
        self.assertNotIn("acknowledged_at IS NULL)\nFROM", sql)

    def test_la_liste_separe_ouverts_et_traites(self) -> None:
        sql, params = queries.list_discrepancies(False, 200)
        self.assertIn("(d.acknowledged_at IS NOT NULL) = $1", sql)
        self.assertEqual(params, (False, 200))

    def test_la_liste_remonte_la_charge_et_le_blocage(self) -> None:
        sql, _ = queries.list_discrepancies(False, 200)
        self.assertIn("c.direction = 'adverse'", sql)
        self.assertIn("structural_contradiction", sql)

    def test_la_reference_cherche_sans_interpoler_la_saisie(self) -> None:
        sql, params = queries.discrepancy_by_reference("c62805", 200)
        self.assertIn("d.id::text LIKE $1 || '%'", sql)
        self.assertNotIn("c62805", sql)
        self.assertEqual(params, ("c62805", 200))
        self.assertNotIn("acknowledged_at IS NOT NULL) = $", sql)


if __name__ == "__main__":
    unittest.main()
