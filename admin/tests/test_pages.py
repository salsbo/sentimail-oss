from __future__ import annotations

import unittest
from datetime import datetime, timezone

from sentimail_admin import pages

DOMAINE = {
    "id": "a2a2e0f0-0000-4000-8000-000000000001",
    "fqdn": "mondomaine.example",
    "status": "active",
    "admin_email": "operateur@mondomaine.example",
    "verification_token": "jeton-affiche-factice",  # gitleaks:allow
    "verified_at": datetime(2026, 8, 12, 9, 30, tzinfo=timezone.utc),
    "created_at": datetime(2026, 8, 12, 9, 0, tzinfo=timezone.utc),
    "updated_at": datetime(2026, 8, 12, 9, 30, tzinfo=timezone.utc),
}


class RenduTests(unittest.TestCase):
    def test_la_page_ne_charge_aucune_ressource_distante(self) -> None:
        html = pages.document("Domaines", "/domaines", pages.page_domaines([DOMAINE]))
        for interdit in ("http://", "https://", "<script", "cdn"):
            self.assertNotIn(interdit, html)

    def test_le_jeton_et_son_enregistrement_sont_affiches(self) -> None:
        html = pages.page_domaines([DOMAINE])
        self.assertIn("_sentimail.mondomaine.example", html)
        self.assertIn("jeton-affiche-factice", html)

    def test_les_modifications_passent_par_un_formulaire_post(self) -> None:
        html = pages.page_domaines([DOMAINE])
        self.assertIn('method="post"', html)
        self.assertIn('action="/domaines/suspendre"', html)
        self.assertNotIn('method="get"', html)

    def test_un_domaine_en_attente_propose_l_activation(self) -> None:
        html = pages.page_domaines([{**DOMAINE, "status": "pending"}])
        self.assertIn('action="/domaines/activer"', html)
        self.assertNotIn('action="/domaines/suspendre"', html)

    def test_les_valeurs_de_la_base_sont_echappees(self) -> None:
        html = pages.page_courrier(
            [
                {
                    "captured_at": datetime(2026, 8, 12, tzinfo=timezone.utc),
                    "delivery_status": "held",
                    "subject": "<script>alert(1)</script>",
                    "from_header": 'x" onmouseover="alert(1)',
                    "envelope_from": "a@b.fr",
                    "envelope_recipients": ["operateur@mondomaine.example"],
                }
            ],
            10,
        )
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn('onmouseover="alert', html)

    def test_l_avis_vient_d_une_liste_fermee(self) -> None:
        html = pages.document("Domaines", "/domaines", "", "<img src=x onerror=1>")
        self.assertNotIn("onerror", html)
        html = pages.document("Domaines", "/domaines", "", "domaine_active")
        self.assertIn("Domaine activé", html)

    def test_le_destinataire_selectionne_est_encode_dans_le_lien(self) -> None:
        html = pages.page_apprentissage(
            [{"email": "operateur+spam@mondomaine.example", "regles": 2, "retours": 5}],
            None,
            [],
            [],
        )
        self.assertIn("destinataire=operateur%2Bspam%40mondomaine.example", html)

    def test_les_transitions_montrent_l_etat_precedent(self) -> None:
        html = pages.page_etat(
            [
                {
                    "component": "collector",
                    "status": "ok",
                    "details": {"reasons": []},
                    "observed_at": datetime(2026, 8, 12, tzinfo=timezone.utc),
                }
            ],
            [
                {
                    "component": "collector",
                    "status": "degraded",
                    "previous_status": "ok",
                    "reasons": ["file d'attente"],
                    "observed_at": datetime(2026, 8, 12, tzinfo=timezone.utc),
                }
            ],
        )
        self.assertIn("opérationnel", html)
        self.assertIn("dégradé", html)
        self.assertIn("file d&#x27;attente", html)


if __name__ == "__main__":
    unittest.main()


QUOTAS = {
    "id": "a2a2e0f0-0000-4000-8000-000000000001",
    "fqdn": "mondomaine.example",
    "status": "active",
    "assistant_hourly_limit": None,
    "assistant_daily_limit": 250,
    "verdict_hourly_limit": None,
    "verdict_daily_limit": None,
}
ROUTAGE = [
    {
        "role": "conversation",
        "model_name": "qwen2.5:7b",
        "enabled": True,
        "fallback_enabled": True,
        "updated_at": datetime(2026, 8, 13, 18, 0, tzinfo=timezone.utc),
    }
]


class ReglagesTests(unittest.TestCase):
    def test_un_plafond_absent_laisse_le_champ_vide(self) -> None:
        html = pages.page_reglages([QUOTAS], ROUTAGE)
        self.assertIn('name="assistant_horaire" value=""', html)
        self.assertIn('name="assistant_quotidien" value="250"', html)
        # Le mot « instance » dit ce que vaut un champ vide.
        self.assertIn('placeholder="instance"', html)

    def test_les_deux_roles_apparaissent_meme_sans_routage(self) -> None:
        html = pages.page_reglages([QUOTAS], [])
        self.assertIn("Verdicts", html)
        # Le libellé est échappé à l'affichage, comme tout ce qui est écrit.
        self.assertIn("Échanges avec l&#x27;utilisateur", html)
        self.assertIn("Confier au local", html)

    def test_un_role_servi_en_local_propose_le_retour_au_distant(self) -> None:
        html = pages.page_reglages([QUOTAS], ROUTAGE)
        self.assertIn("Rendre au distant", html)
        self.assertIn("qwen2.5:7b", html)

    def test_la_page_dit_comment_eprouver_un_modele(self) -> None:
        html = pages.page_reglages([QUOTAS], ROUTAGE)
        self.assertIn("--probe", html)


DEUX_LIGNES = [
    {"role": "verdict", "provider": "openai_compatible",
     "base_url": "https://api.deepseek.com", "model_name": "deepseek-v4-pro",
     "token_limit_param": "max_tokens", "secret_filename": "deepseek_api_key",
     "validated_at": None, "configured_by": "93.184.216.1"},
    {"role": "conversation", "provider": "openai_compatible",
     "base_url": "https://api.deepseek.com", "model_name": "deepseek-v4-pro",
     "token_limit_param": "max_tokens", "secret_filename": "deepseek_api_key",
     "validated_at": None, "configured_by": "93.184.216.1"},
]


class ReglagesMoteurTests(unittest.TestCase):
    """Deux cartes, une par rôle - chacune choisit librement son moteur."""

    def test_chaque_role_a_sa_carte(self) -> None:
        html = pages.page_reglages_moteur(DEUX_LIGNES, [], {})
        self.assertIn("Verdict", html)
        self.assertIn("Conversation", html)
        self.assertEqual(html.count('name="base_url"'), 2)

    def test_la_cle_n_est_jamais_reaffichee(self) -> None:
        html = pages.page_reglages_moteur(DEUX_LIGNES, [], {})
        self.assertNotIn("cle-secrete", html)  # valeur absente
        self.assertIn('type="password"', html)

    def test_le_preset_premplit_le_formulaire(self) -> None:
        html = pages.page_reglages_moteur(DEUX_LIGNES, [], {"verdict": "openai"})
        self.assertIn("https://api.openai.com/v1", html)

    def test_l_encart_dit_ou_part_le_courrier(self) -> None:
        html = pages.encart_confidentialite(DEUX_LIGNES, [])
        self.assertIn("api.deepseek.com", html)

    def test_l_encart_dit_rien_ne_sort_en_local(self) -> None:
        routage = [
            {"role": "verdict", "model_name": "qwen3", "enabled": True,
             "fallback_enabled": False}
        ]
        html = pages.encart_confidentialite(DEUX_LIGNES, routage)
        self.assertIn("rien ne sort", html)

    # --- Compléments imposés par la revue de la tâche 5 --------------------

    def test_les_six_presets_sont_proposes_par_role(self) -> None:
        html = pages.page_reglages_moteur(DEUX_LIGNES, [], {})
        for preset in ("deepseek", "openai", "mistral", "ollama", "anthropic", "custom"):
            with self.subTest(preset=preset):
                self.assertEqual(
                    html.count(f"preset={preset}"), 2, f"{preset} absent d'un rôle"
                )

    def test_un_role_sans_configuration_affiche_un_formulaire_vide(self) -> None:
        html = pages.page_reglages_moteur([DEUX_LIGNES[0]], [], {})
        self.assertIn("Aucun moteur configuré", html)
        # Le champ de l'autre rôle reste présent et vide, pas absent.
        self.assertEqual(html.count('name="base_url"'), 2)

    def test_la_cle_deja_posee_propose_de_ne_pas_la_changer(self) -> None:
        ligne = {**DEUX_LIGNES[0], "secret_pose": True}
        html = pages.page_reglages_moteur([ligne], [], {})
        self.assertIn("inchangée si vide", html)

    def test_sans_cle_posee_le_placeholder_ne_ment_pas(self) -> None:
        ligne = {**DEUX_LIGNES[0], "secret_pose": False}
        html = pages.page_reglages_moteur([ligne], [], {})
        self.assertNotIn("inchangée si vide", html)

    def test_le_role_pilote_le_formulaire_de_son_role(self) -> None:
        html = pages.page_reglages_moteur(DEUX_LIGNES, [], {})
        self.assertIn('name="role" value="verdict"', html)
        self.assertIn('name="role" value="conversation"', html)

    def test_le_preregle_choisi_voyage_avec_le_formulaire(self) -> None:
        html = pages.page_reglages_moteur(DEUX_LIGNES, [], {"verdict": "openai"})
        self.assertIn('name="preset" value="openai"', html)

    def test_le_formulaire_est_toujours_en_post(self) -> None:
        html = pages.page_reglages_moteur(DEUX_LIGNES, [], {})
        self.assertIn('method="post"', html)
        self.assertIn('action="/reglages/moteur"', html)
        self.assertNotIn('method="get" action="/reglages/moteur"', html)

    def test_l_encart_mentionne_le_repli_distant(self) -> None:
        routage = [
            {"role": "verdict", "model_name": "qwen3", "enabled": True,
             "fallback_enabled": True}
        ]
        html = pages.encart_confidentialite(DEUX_LIGNES, routage)
        self.assertIn("distant", html.casefold())

    def test_l_encart_sans_routage_local_reste_lisible(self) -> None:
        html = pages.encart_confidentialite(DEUX_LIGNES, [])
        self.assertNotIn("rien ne sort", html)

    def test_l_encart_sans_moteur_ni_local_le_dit(self) -> None:
        html = pages.encart_confidentialite([], [])
        self.assertIn("aucun", html.casefold())

    def test_les_valeurs_de_l_encart_sont_echappees(self) -> None:
        piege = [
            {**DEUX_LIGNES[0], "base_url": "<script>alert(1)</script>"},
        ]
        html = pages.encart_confidentialite(piege, [])
        self.assertNotIn("<script>alert(1)</script>", html)

    # --- Repère synthétique construit par /reglages (pas une vraie ligne) --

    def test_le_repere_sans_base_url_reste_non_configure_dans_la_carte(self) -> None:
        """Reproduit exactement ce que `reglages()` construit sans ligne.

        `connu[role] = {"role": role, "secret_pose": pose}` : ce repère n'a
        pas de `base_url`, contrairement à toute vraie ligne de
        `llm_role_providers` (colonne NOT NULL). La carte doit rester
        « non configuré », jamais afficher un faux « Configuré par - ».
        """
        repere = {"role": "conversation", "secret_pose": False}
        html = pages.page_reglages_moteur([DEUX_LIGNES[0], repere], [], {})
        self.assertIn("Aucun moteur configuré", html)
        self.assertNotIn("Configuré par -", html)

    def test_le_repere_sans_base_url_reste_non_configure_dans_l_encart(self) -> None:
        repere = {"role": "conversation", "secret_pose": False}
        html = pages.encart_confidentialite([DEUX_LIGNES[0], repere], [])
        self.assertIn("aucun moteur configuré", html.casefold())
        self.assertNotIn("part vers -", html)


class EtatsLivraisonTests(unittest.TestCase):
    def test_un_dossier_sans_destinataire_se_lit_en_clair(self) -> None:
        """Un état affiché en anglais brut ne dit rien à celui qui le lit."""
        self.assertIn(
            "destinataire inexistant",
            pages.pastille("undeliverable", pages.ETATS_LIVRAISON),
        )


RAPPORT = {
    "window_days": 30,
    "coverage": {
        "deliver": {"total": 220, "labelled": 1, "rate": 0.0045},
        "ask_user": {"total": 52, "labelled": 27, "rate": 0.519},
        "filed_as_junk": {"total": 94, "labelled": 24, "rate": 0.255},
    },
    "matrix": {
        "total": 366,
        "rows": {
            "deliver": {"legitimate": 1, "spam": 0, "ambiguous": 0,
                        "unknown": 219, "total": 220, "labelled": 1,
                        "coverage": 0.0045},
            "ask_user": {"legitimate": 24, "spam": 3, "ambiguous": 0,
                         "unknown": 25, "total": 52, "labelled": 27,
                         "coverage": 0.519},
            "filed_as_junk": {"legitimate": 0, "spam": 24, "ambiguous": 0,
                              "unknown": 70, "total": 94, "labelled": 24,
                              "coverage": 0.255},
        },
    },
    "hold_precision": {"value": 0.111, "labelled": 27, "total": 52},
    "generalized_risk": {"value": 0.0, "observed": 0, "total": 366,
                         "lower_bound_only": True},
    "trec_rates": {"hm_optimistic": 0.0, "sm_optimistic": 0.0,
                   "hm_pessimistic": 0.96, "sm_pessimistic": 0.111,
                   "legitimate_observed": 25, "spam_observed": 27},
    "lam_optimistic": 0.0001, "lam_pessimistic": 0.32,
    "utility": {"raw": -14, "scored": 52, "normalised": -0.027,
                "weights": {"deliver": {"spam": -10, "legitimate": 10}}},
}


class PageMesureTests(unittest.TestCase):
    """La page dit d'abord sur quoi elle a le droit de conclure."""

    def _page(self, rapport: object = RAPPORT) -> str:
        return pages.page_mesure(rapport, "2026-08-18T17:00:00+00:00")

    def test_la_couverture_precede_les_taux(self) -> None:
        page = self._page()
        self.assertLess(page.index("Couverture"), page.index("Précision"))

    def test_l_inconnu_est_affiche_et_non_masque(self) -> None:
        # 219 messages livrés sans qualification : les cacher ferait lire la
        # ligne « livré » comme si elle était mesurée.
        self.assertIn("219", self._page())

    def test_le_risque_est_annonce_comme_borne_basse(self) -> None:
        page = self._page().casefold()
        self.assertIn("borne", page)

    def test_les_deux_bornes_d_erreur_sont_montrees(self) -> None:
        # Un système dont les bornes divergent ne décide pas : il transfère.
        page = self._page()
        self.assertIn("96", page)
        self.assertIn("11", page)

    def test_sans_rapport_la_page_reste_lisible(self) -> None:
        page = pages.page_mesure(None, None)
        self.assertIn("<", page)
        self.assertNotIn("None", page)

    def test_un_rapport_corrompu_ne_casse_pas_la_page(self) -> None:
        page = pages.page_mesure({"matrix": "pas un dictionnaire"}, None)
        self.assertIn("<", page)

    def test_le_contenu_du_rapport_est_echappe(self) -> None:
        piege = dict(RAPPORT)
        piege["window_days"] = "<script>alert(1)</script>"
        self.assertNotIn("<script>", pages.page_mesure(piege, None))


VALEURS_ENV = {
    "action_address": "maia@sentinel.mondomaine.example",
    "action_aliases": ["kitt@sentinel.mondomaine.example"],
    "assistant_sender": "MAIA - SentiMail <maia@mondomaine.example>",
    "probe_recipient": "sentinel-probe@mondomaine.example",
}

LIGNE_IDENTITE = {
    "action_address": "action@mondomaine.example",
    "action_aliases": ["alias@mondomaine.example"],
    "assistant_sender": "MAIA <maia@mondomaine.example>",
    "probe_recipient": "sonde@mondomaine.example",
    "configured_by": "100.64.0.1",
    "updated_at": datetime(2026, 8, 22, 9, 0, tzinfo=timezone.utc),
}


class PageReglagesIdentiteTests(unittest.TestCase):
    """Tant que la table est vide, l'instance suit les valeurs d'environnement."""

    def test_le_formulaire_est_present_en_post(self) -> None:
        html = pages.page_reglages_identite(None, VALEURS_ENV)
        self.assertIn('method="post"', html)
        self.assertIn('action="/reglages/identite"', html)
        self.assertIn('name="action_address"', html)
        self.assertIn('name="action_aliases"', html)
        self.assertIn('name="assistant_sender"', html)
        self.assertIn('name="probe_recipient"', html)

    def test_sans_ligne_les_valeurs_d_environnement_sont_affichees(self) -> None:
        html = pages.page_reglages_identite(None, VALEURS_ENV)
        self.assertIn("valeurs de l'environnement", html)
        self.assertIn("maia@sentinel.mondomaine.example", html)
        self.assertIn("kitt@sentinel.mondomaine.example", html)
        self.assertIn("sentinel-probe@mondomaine.example", html)

    def test_sans_ligne_le_bouton_propose_de_reprendre_la_main(self) -> None:
        html = pages.page_reglages_identite(None, VALEURS_ENV)
        self.assertIn("Reprendre la main", html)

    def test_avec_une_ligne_ses_valeurs_remplissent_le_formulaire(self) -> None:
        html = pages.page_reglages_identite(LIGNE_IDENTITE, VALEURS_ENV)
        self.assertIn("action@mondomaine.example", html)
        self.assertIn("alias@mondomaine.example", html)
        self.assertIn("sonde@mondomaine.example", html)
        # Les valeurs de l'environnement ne sont plus la source affichée.
        self.assertNotIn("valeurs de l'environnement", html)

    def test_avec_une_ligne_le_bouton_dit_enregistrer(self) -> None:
        html = pages.page_reglages_identite(LIGNE_IDENTITE, VALEURS_ENV)
        self.assertIn("Enregistrer", html)

    def test_les_valeurs_sont_echappees(self) -> None:
        piege = {**LIGNE_IDENTITE, "action_address": '"><script>alert(1)</script>'}
        html = pages.page_reglages_identite(piege, VALEURS_ENV)
        self.assertNotIn("<script>alert(1)</script>", html)
