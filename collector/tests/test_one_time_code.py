from __future__ import annotations

import unittest

from sentimail_v3.code.one_time_code import apexes_are_close, express_delivery_reason

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
            express_delivery_reason(BASE, "openai.com", ["openai.com"], {})
        )

    def test_sans_authentification_aucune_voie_rapide(self) -> None:
        """La vitesse ne se paie jamais par l'identité de l'expéditeur."""
        codes = (BASE - {"AUTH_DMARC_PASS"}) | {"AUTH_DMARC_FAIL"}
        self.assertIsNone(
            express_delivery_reason(codes, "openai.com", ["openai.com"], {})
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
                    express_delivery_reason(codes, "openai.com", ["openai.com"], {})
                )

    def test_un_code_demande_plutot_que_fourni_n_est_pas_eligible(self) -> None:
        # « Renvoyez-nous votre code » est l'attaque, pas le service.
        codes = BASE | {"CONTENT_SENSITIVE_REQUEST"}
        self.assertIsNone(
            express_delivery_reason(codes, "openai.com", ["openai.com"], {})
        )

    def test_une_destination_etrangere_fait_passer_par_la_voie_normale(self) -> None:
        self.assertIsNone(
            express_delivery_reason(BASE, "openai.com", ["collecte.top"], {})
        )

    def test_une_marque_usurpee_annule_la_voie_rapide(self) -> None:
        codes = BASE | {"IDENTITY_BRAND_MISMATCH"}
        self.assertIsNone(
            express_delivery_reason(codes, "openai.com", ["openai.com"], {})
        )

    def test_une_piece_jointe_annule_la_voie_rapide(self) -> None:
        # Un code de connexion n'a aucune raison de porter un fichier.
        codes = BASE | {"ATTACHMENT_EXECUTABLE"}
        self.assertIsNone(
            express_delivery_reason(codes, "openai.com", ["openai.com"], {})
        )

    def test_une_pression_coercitive_annule_la_voie_rapide(self) -> None:
        codes = BASE | {"CONTENT_COERCIVE_PRESSURE"}
        self.assertIsNone(
            express_delivery_reason(codes, "openai.com", ["openai.com"], {})
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
            )
        )

    def test_un_article_adverse_inconnu_referme_aussi_la_voie(self) -> None:
        # Ce qui compte est la direction de l'indice, pas son code.
        self.assertIsNone(
            express_delivery_reason(
                BASE, "openai.com", ["openai.com"], {}, adverse={"ARTICLE-A-VENIR"}
            )
        )

    def test_un_dossier_sans_charge_garde_la_voie_ouverte(self) -> None:
        self.assertIsNotNone(
            express_delivery_reason(
                BASE, "openai.com", ["openai.com"], {}, adverse=set()
            )
        )

    def test_le_motif_rendu_est_exploitable(self) -> None:
        """Une livraison accélérée doit pouvoir s'expliquer après coup."""
        motif = express_delivery_reason(BASE, "openai.com", ["openai.com"], {})
        self.assertIn("code", str(motif).casefold())


if __name__ == "__main__":
    unittest.main()
