from __future__ import annotations

import unittest
from pathlib import Path

from sentimail_v3.code.one_time_code import (
    DISQUALIFYING,
    apexes_are_close,
    express_delivery_reason,
    shows_one_time_code,
)

# Ce qu'un vrai code de connexion présente : il donne le code, il n'en demande
# aucun, et l'identité de l'expéditeur est établie.
# Indices releves sur les vrais envois d'OpenAI et de 1Password : ils annoncent
# un code a saisir et son expiration. « Un code fourni sans etre demande » est
# un troisieme marqueur, plus rare.
BASE = {
    "CONTENT_EXPECTED_ONE_TIME_CODE_INPUT",
    "AUTH_DMARC_PASS",
    "AUTH_SPF_PASS",
    "STRUCT_PARSEABLE",
}
# Les deux constats que la voie exige en plus des indices : un code montré, et
# une adresse déjà reçue. Chaque appel les fournit, pour que chaque test porte
# sur la condition qu'il nomme et pas sur leur absence.
CONFIRME = {"established": True, "code_visible": True}


class ApexProximityTests(unittest.TestCase):
    def test_le_meme_apex_est_proche(self) -> None:
        """OpenAI écrit depuis tm.openai.com et renvoie vers openai.com."""
        self.assertTrue(apexes_are_close("openai.com", ["openai.com"], {}))

    def test_la_meme_marque_sous_un_autre_tld_reste_proche(self) -> None:
        """1Password écrit depuis 1password.eu et renvoie vers 1password.com."""
        self.assertTrue(apexes_are_close("1password.eu", ["1password.com"], {}))

    def test_le_meme_titulaire_reste_proche(self) -> None:
        self.assertTrue(
            apexes_are_close(
                "credit-agricole.fr",
                ["ca-des-savoie.fr"],
                {
                    "credit-agricole.fr": {"credit agricole"},
                    "ca-des-savoie.fr": {"credit agricole"},
                },
            )
        )

    def test_un_domaine_sans_rapport_est_eloigne(self) -> None:
        self.assertFalse(apexes_are_close("openai.com", ["collecte-inconnue.top"], {}))

    def test_un_seul_lien_eloigne_suffit_a_eloigner(self) -> None:
        self.assertFalse(
            apexes_are_close("openai.com", ["openai.com", "ailleurs.top"], {})
        )

    def test_un_message_sans_lien_reste_proche(self) -> None:
        # Un code envoyé sans aucun lien est le cas le plus simple et le plus sûr.
        self.assertTrue(apexes_are_close("openai.com", [], {}))


class ExpressDeliveryTests(unittest.TestCase):
    def test_un_code_authentifie_vers_son_propre_domaine_part_vite(self) -> None:
        self.assertIsNotNone(
            express_delivery_reason(BASE, "openai.com", ["openai.com"], {}, **CONFIRME)
        )

    def test_sans_authentification_aucune_voie_rapide(self) -> None:
        """La vitesse ne se paie jamais par l'identité de l'expéditeur."""
        codes = (BASE - {"AUTH_DMARC_PASS"}) | {"AUTH_DMARC_FAIL"}
        self.assertIsNone(
            express_delivery_reason(codes, "openai.com", ["openai.com"], {}, **CONFIRME)
        )

    def test_les_trois_marqueurs_reels_ouvrent_la_voie(self) -> None:
        for marqueur in (
            "CONTENT_EXPECTED_ONE_TIME_CODE_INPUT",
            "CONTENT_EXPECTED_ONE_TIME_EXPIRATION",
            "CONTENT_ONE_TIME_CREDENTIAL_PROVIDED_NOT_REQUESTED",
        ):
            with self.subTest(marqueur=marqueur):
                codes = {marqueur, "AUTH_DMARC_PASS"}
                self.assertIsNotNone(
                    express_delivery_reason(
                        codes, "openai.com", ["openai.com"], {}, **CONFIRME
                    )
                )

    def test_un_code_demande_plutot_que_fourni_n_est_pas_eligible(self) -> None:
        # « Renvoyez-nous votre code » est l'attaque, pas le service.
        codes = BASE | {"CONTENT_SENSITIVE_REQUEST"}
        self.assertIsNone(
            express_delivery_reason(codes, "openai.com", ["openai.com"], {}, **CONFIRME)
        )

    def test_une_destination_etrangere_fait_passer_par_la_voie_normale(self) -> None:
        self.assertIsNone(
            express_delivery_reason(
                BASE, "openai.com", ["collecte.top"], {}, **CONFIRME
            )
        )

    def test_une_premiere_observation_ne_part_jamais_vite(self) -> None:
        """Le 1er septembre 2026, un faux avis de double authentification.

        Il venait d'un domaine d'envoi jetable, authentifié pour lui-même,
        jamais vu ici. Aucun hook synchrone ne compare le nom revendiqué au
        domaine réel : une adresse jamais reçue passe donc toujours par
        l'examen complet, même si le texte montre un code.
        """
        self.assertIsNone(
            express_delivery_reason(
                BASE,
                "openai.com",
                ["openai.com"],
                {},
                established=False,
                code_visible=True,
            )
        )

    def test_un_lien_sans_code_visible_ne_part_pas_vite(self) -> None:
        """Une réclame à code promo, le 31 août : le mot, pas la chose."""
        self.assertIsNone(
            express_delivery_reason(
                BASE,
                "openai.com",
                ["openai.com"],
                {},
                established=True,
                code_visible=False,
            )
        )

    def test_sans_les_deux_constats_la_voie_reste_fermee(self) -> None:
        # Un appelant qui ne fournit pas les constats n'ouvre jamais la voie.
        self.assertIsNone(
            express_delivery_reason(BASE, "openai.com", ["openai.com"], {})
        )

    def test_une_piece_jointe_annule_la_voie_rapide(self) -> None:
        # Un code de connexion n'a aucune raison de porter un fichier.
        codes = BASE | {"ATTACHMENT_EXECUTABLE"}
        self.assertIsNone(
            express_delivery_reason(codes, "openai.com", ["openai.com"], {}, **CONFIRME)
        )

    def test_une_pression_coercitive_annule_la_voie_rapide(self) -> None:
        # La pression est portée par CONTENT_URGENCY, adverse : c'est la
        # charge qui referme la voie, pas un nom de code sans producteur.
        self.assertIsNone(
            express_delivery_reason(
                BASE,
                "openai.com",
                ["openai.com"],
                {},
                adverse={"CONTENT_URGENCY"},
                **CONFIRME,
            )
        )

    def test_un_seul_indice_adverse_referme_la_voie(self) -> None:
        """Le 26 août, un faux « DISNEY+ » est parti par la voie rapide.

        Il portait pourtant un indice adverse - du texte masqué par CSS - mais
        son code n'était pas dans la liste nominative des disqualifiants, écrite
        avant que cet article existe. Une liste de codes ne peut pas suivre les
        articles qu'on ajoute : c'est la charge elle-même qui referme la voie.
        """
        self.assertIsNone(
            express_delivery_reason(
                BASE,
                "openai.com",
                ["openai.com"],
                {},
                adverse={"CONTENT_HIDDEN_TEXT_SALTING"},
                **CONFIRME,
            )
        )

    def test_un_article_adverse_inconnu_referme_aussi_la_voie(self) -> None:
        # Ce qui compte est la direction de l'indice, pas son code.
        self.assertIsNone(
            express_delivery_reason(
                BASE,
                "openai.com",
                ["openai.com"],
                {},
                adverse={"ARTICLE-A-VENIR"},
                **CONFIRME,
            )
        )

    def test_un_dossier_sans_charge_garde_la_voie_ouverte(self) -> None:
        self.assertIsNotNone(
            express_delivery_reason(
                BASE, "openai.com", ["openai.com"], {}, adverse=set(), **CONFIRME
            )
        )

    def test_le_motif_rendu_est_exploitable(self) -> None:
        """Une livraison accélérée doit pouvoir s'expliquer après coup."""
        motif = express_delivery_reason(
            BASE, "openai.com", ["openai.com"], {}, **CONFIRME
        )
        self.assertIn("code", str(motif).casefold())


class VisibleCodeTests(unittest.TestCase):
    """Le texte montre-t-il un code, et pas seulement le mot ?"""

    def test_un_code_apres_le_mot_code_est_vu(self) -> None:
        self.assertTrue(
            shows_one_time_code(
                "Saisissez ce code de vérification temporaire pour continuer : 162113"
            )
        )

    def test_un_code_avant_le_mot_code_est_vu(self) -> None:
        self.assertTrue(shows_one_time_code("897819 est votre code de vérification"))

    def test_un_code_en_deux_groupes_de_trois_est_vu(self) -> None:
        self.assertTrue(
            shows_one_time_code(
                "Veuillez saisir le code à 6 chiffres suivant : 069 344 Ce code expire"
            )
        )

    def test_un_code_de_quatre_chiffres_est_vu(self) -> None:
        self.assertTrue(shows_one_time_code("Enter this code to sign in\n\n8374\n\nEnter"))

    def test_un_code_colle_aux_deux_points_est_vu(self) -> None:
        self.assertTrue(shows_one_time_code("Votre code:482913"))

    def test_un_code_promo_alphanumerique_n_est_pas_un_code(self) -> None:
        for texte in (
            "10€ offerts avec le code BTS26",
            "Code promo à usage unique à saisir en majuscules dans votre "
            "récapitulatif de commande BTS26",
            "Saisis ton code dans le panier AUTUMN2026",
        ):
            with self.subTest(texte=texte):
                self.assertFalse(shows_one_time_code(texte))

    def test_une_plage_d_annees_n_est_pas_un_code(self) -> None:
        for texte in (
            "en demandant un second code de vérification à chaque connexion. "
            "L'équipe Espace client 1999-2026 exemple.fr",
            "Le code 2026 est une année",
        ):
            with self.subTest(texte=texte):
                self.assertFalse(shows_one_time_code(texte))

    def test_une_date_n_est_pas_un_code(self) -> None:
        self.assertFalse(
            shows_one_time_code("Votre lien sécurisé est ici | 2026-08-12 13:03:06 code")
        )

    def test_un_long_numero_n_est_pas_un_code(self) -> None:
        self.assertFalse(
            shows_one_time_code("Code de la réunion. Numéro de réunion : 361 869 400 350 7")
        )

    def test_une_adresse_postale_n_est_pas_un_code(self) -> None:
        for texte in (
            "régie par le Code des Assurances. Siège Social : 66 rue X, 76100 Ville",
            "Votre code postal 75008 est enregistré",
        ):
            with self.subTest(texte=texte):
                self.assertFalse(shows_one_time_code(texte))

    def test_un_prix_n_est_pas_un_code(self) -> None:
        self.assertFalse(shows_one_time_code("Utilisez le code pour gagner 1000€"))

    def test_un_nombre_loin_du_mot_code_ne_compte_pas(self) -> None:
        texte = "Votre code de vérification" + " mot" * 120 + " 482913"
        self.assertFalse(shows_one_time_code(texte))

    def test_sans_mot_code_aucun_nombre_ne_compte(self) -> None:
        self.assertFalse(shows_one_time_code("Commande 482913 expédiée"))

    def test_un_texte_vide_ou_absent_ne_montre_rien(self) -> None:
        self.assertFalse(shows_one_time_code(""))
        self.assertFalse(shows_one_time_code(None))

    def test_le_constat_est_un_booleen_jamais_le_code(self) -> None:
        # Le code est un secret vivant : le constat ne le rend jamais.
        self.assertIs(type(shows_one_time_code("code 482913")), bool)


class ProducteursDesFermeturesTests(unittest.TestCase):
    def test_chaque_disqualifiant_a_un_producteur_synchrone(self) -> None:
        """La décision précède l'analyse profonde.

        Un code qu'aucun hook synchrone n'émet ne referme jamais la voie et
        donne une fausse assurance : IDENTITY_BRAND_MISMATCH, cité jusqu'au 29
        septembre 2026, n'avait plus de producteur depuis le 27 août.
        """
        from sentimail_v3.observation.dossier import hooks

        dossier = Path(hooks.__file__).parent
        sources = "".join(
            chemin.read_text(encoding="utf-8") for chemin in sorted(dossier.glob("*.py"))
        )
        orphelins = sorted(code for code in DISQUALIFYING if f'"{code}"' not in sources)
        self.assertEqual(
            orphelins,
            [],
            f"codes de fermeture sans producteur synchrone : {orphelins}",
        )


if __name__ == "__main__":
    unittest.main()
