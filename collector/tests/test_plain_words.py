from __future__ import annotations

import json
import re
import unittest

from sentimail_v3.code.plain_words import (
    confidence_badge,
    gap_lines,
    plain_clue,
    plain_limits,
    plain_points,
    plain_rationale,
    sender_addresses,
    sender_gap,
)

_CODE = re.compile(r"\b[A-Z][A-Z0-9]*(?:[-_.][A-Z0-9_]+)+\b")


class PlainWordsTests(unittest.TestCase):
    def test_a_known_clue_is_said_in_plain_french(self) -> None:
        said = plain_clue("AUTH_DMARC_FAIL", "Le relais de confiance indique DMARC=fail.")
        self.assertIsNotNone(said)
        self.assertNotIn("DMARC", said or "")
        self.assertIn("prétend", said or "")

    def test_an_unknown_clue_falls_back_without_its_code(self) -> None:
        said = plain_clue(
            "FUTURE_UNKNOWN_SIGNAL",
            "L’indice FUTURE-042 attribue 60/100 à ce message.",
        )
        self.assertIsNotNone(said)
        self.assertNotRegex(said or "", _CODE)
        self.assertNotIn("60/100", said or "")

    def test_operational_clues_never_reach_the_recipient(self) -> None:
        for code in ("STRUCT_PARSEABLE", "DATE_PARSEABLE", "STRUCT_MESSAGE_ID_PRESENT"):
            self.assertIsNone(plain_clue(code, "détail interne"))

    def test_the_rationale_keeps_its_sense_without_its_references(self) -> None:
        said = plain_rationale(
            "Le message échoue AUTH_DMARC_FAIL (70/100) et cite NATURE-003, "
            "je préfère demander."
        )
        self.assertNotRegex(said, _CODE)
        self.assertNotIn("70/100", said)
        self.assertIn("je préfère demander", said)

    def test_an_absent_rationale_still_says_something(self) -> None:
        self.assertTrue(plain_rationale(None))
        self.assertTrue(plain_rationale(""))

    def test_points_are_deduplicated_and_capped(self) -> None:
        rows = [
            {"clue_code": "AUTH_DMARC_FAIL", "statement": "a"},
            {"clue_code": "AUTH_DMARC_FAIL", "statement": "b"},
            {"clue_code": "STRUCT_PARSEABLE", "statement": "c"},
            {"clue_code": "CONTENT_URGENCY", "statement": "d"},
            {"clue_code": "URL_CLOAKING", "statement": "e"},
            {"clue_code": "ATTACHMENT_MACRO", "statement": "f"},
        ]
        points = plain_points(rows, 3)
        self.assertEqual(len(points), 3)
        self.assertEqual(len(set(points)), 3)
        for point in points:
            self.assertNotRegex(point, _CODE)


class PlainLimitsTests(unittest.TestCase):
    def test_only_a_failed_check_is_a_limit(self) -> None:
        rows = [
            {"clue_code": "URL_SANDBOX_INCOMPLETE", "statement": "a"},
            {"clue_code": "HISTORY_FIRST_OBSERVATION", "statement": "b"},
            {"clue_code": "RSPAMD_HIGH_SCORE", "statement": "c"},
            {"clue_code": "URL_CROSS_APEX", "statement": "d"},
        ]
        limits = plain_limits(rows, 3)
        self.assertEqual(len(limits), 1)
        self.assertIn("liens", limits[0])

    def test_a_context_fact_is_never_shown_as_a_limit(self) -> None:
        rows = [
            {"clue_code": "HISTORY_FIRST_OBSERVATION", "statement": "b"},
            {"clue_code": "NATURE_BULK_MAILING", "statement": "c"},
        ]
        self.assertEqual(plain_limits(rows, 3), [])


if __name__ == "__main__":
    unittest.main()


class NouveauxCriteresTests(unittest.TestCase):
    """Un critère sans traduction sort en jargon dans l'avis envoyé."""

    CODES = (
        "AUTH_DKIM_UNALIGNED",
        "IDENTITY_BRAND_MISMATCH",
        "IDENTITY_COUSIN_DOMAIN",
        "HEADERS_RECIPIENT_NOT_ADDRESSED",
        "NATURE_MESSAGE_LANGUAGE",
        "CORRELATION_BRAND_SPOOFING",
        "CORRELATION_CREDENTIAL_HARVESTING",
        "CORRELATION_UNSOLICITED_BULK",
        "CORRELATION_COUSIN_DOMAIN_APPROACH",
        # Codes déjà émis en production et restés sans traduction.
        "URL_STATIC_RISK",
        "URL_UNAUTHENTICATED_CROSS_APEX",
        "AUTH_DKIM_FAIL",
        "AUTH_SPF_INCONCLUSIVE",
        "AUTH_DMARC_INCONCLUSIVE",
        "IDENTITY_ASCII_LOOKALIKE",
        "CONTENT_ACTIVE_HTML",
        "RSPAMD_PHISHING_HEURISTIC",
        "CORRELATION_UNAUTHENTICATED_PHISHING_HEURISTIC",
        # Émis en production et retombés jusque-là sur le repli.
        "HISTORY_CONFIRMED_LEGITIMATE_SENDER",
        "HISTORY_BEHAVIOR_DEVIATION",
    )

    def test_chaque_critere_se_dit_en_francais_sans_jargon(self) -> None:
        for code in self.CODES:
            with self.subTest(code=code):
                phrase = plain_clue(code, "énoncé technique de repli")
                self.assertIsNotNone(phrase)
                self.assertNotIn("apex", str(phrase).casefold())
                self.assertNotIn("dkim", str(phrase).casefold())
                self.assertNotEqual(phrase, "énoncé technique de repli.")

    def test_l_heuristique_est_absorbee_par_son_faisceau(self) -> None:
        # Le faisceau dit le soupçon du filtre et le défaut d'identité : le
        # soupçon seul, à côté, redirait la moitié de la même chose.
        from sentimail_v3.code.plain_words import _SHORT, short_points

        points = short_points(
            [
                {"clue_code": "RSPAMD_PHISHING_HEURISTIC", "statement": ""},
                {
                    "clue_code": "CORRELATION_UNAUTHENTICATED_PHISHING_HEURISTIC",
                    "statement": "",
                },
            ],
            5,
        )
        self.assertEqual(
            points, [_SHORT["CORRELATION_UNAUTHENTICATED_PHISHING_HEURISTIC"]]
        )


class JargonDuVerdictTests(unittest.TestCase):
    """Le verdict du modèle arrive parfois truffé de vocabulaire interne."""

    def test_les_drapeaux_techniques_disparaissent(self) -> None:
        brut = (
            "Aucun élément défavorable matériel n'est présent, mais l'analyse "
            "profonde est incomplète (deep_execution_complete=false) et une URL "
            "actionnable n'a pas pu être inspectée."
        )
        clair = plain_rationale(brut)
        self.assertNotIn("deep_execution_complete", clair)
        self.assertNotIn("=false", clair)

    def test_la_phrase_de_procedure_interne_disparait(self) -> None:
        """« Conformément aux règles, cela impose ask_user » ne s'adresse pas
        au destinataire : c'est le moteur qui se parle à lui-même."""
        brut = (
            "Le lien mène vers un site sans rapport avec l'expéditeur. "
            "Conformément aux règles, une analyse réellement incomplète impose "
            "undetermined et ask_user."
        )
        clair = plain_rationale(brut)
        self.assertIn("sans rapport avec l'expéditeur", clair)
        self.assertNotIn("undetermined", clair.casefold())
        self.assertNotIn("ask_user", clair.casefold())
        self.assertNotIn("Conformément aux règles", clair)

    def test_une_motivation_entierement_procedurale_est_remplacee(self) -> None:
        brut = "Conformément aux règles, cela impose undetermined et ask_user."
        self.assertEqual(
            plain_rationale(brut),
            "Je préfère te demander avant de décider.",
        )

    def test_une_motivation_deja_claire_reste_intacte(self) -> None:
        brut = "Le message se fait passer pour une enseigne connue."
        self.assertEqual(plain_rationale(brut), brut)


class MotifDeClassementTests(unittest.TestCase):
    """Un indésirable sans indice adverse doit quand même dire pourquoi.

    Le 20/08 à 19:31, un avis d'indésirable n'affichait que « Un faisceau
    d'indices concordants » : le dossier n'avait aucun indice adverse, le
    classement venait du jugement seul, et sa motivation restait en base.
    """

    def test_sans_indice_adverse_le_motif_du_juge_est_donne(self) -> None:
        from sentimail_v3.code.plain_words import classification_reasons

        raisons = classification_reasons(
            [], "Le gabarit correspond à une campagne déjà qualifiée de spam"
        )
        self.assertEqual(len(raisons), 1)
        self.assertIn("campagne", raisons[0])

    def test_les_indices_adverses_restent_prioritaires(self) -> None:
        from sentimail_v3.code.plain_words import classification_reasons

        raisons = classification_reasons(
            [{"clue_code": "IDENTITY_BRAND_MISMATCH", "statement": "x"}],
            "motif du juge",
        )
        self.assertNotIn("motif du juge", " ".join(raisons))
        self.assertTrue(raisons)


class LExplicationDuJugeEstMontreeTests(unittest.TestCase):
    """La phrase toute faite dit le grief, l'explication dit le pourquoi.

    Le 21/08, un avis reprochait à une alerte de connexion OpenAI de « parler
    de quelque chose qui n'a rien à voir avec ce que fait cet expéditeur ».
    Personne ne pouvait comprendre : la vraie raison - le site lu était une
    page anti-robot, pas celui d'OpenAI - existait dans l'indice et n'était pas
    affichée. Le grief sans son motif ne s'explique pas, il s'impose.
    """

    CODE = "SENDER_ACTIVITY_INCOHERENT"
    EXPLICATION = (
        "Le message prétend provenir d’OpenAI mais le site fourni est une page "
        "générique de vérification sans rapport avec OpenAI."
    )

    def test_l_explication_suit_la_phrase_toute_faite(self) -> None:
        # Forme réellement stockée : le dossier du clue entier dans la colonne.
        rendu = plain_clue(
            self.CODE,
            "Le propos de ce message est étranger à l’activité publiée.",
            {"facts": {"explication": self.EXPLICATION}, "strength": 55},
        )
        self.assertTrue(rendu.startswith("Ce message parle de quelque chose"), rendu)
        self.assertIn("page générique de vérification", rendu)

    def test_la_forme_directe_est_acceptee_aussi(self) -> None:
        rendu = plain_clue(self.CODE, "", {"explication": self.EXPLICATION})
        self.assertIn("page générique de vérification", rendu)

    def test_le_json_en_texte_est_lu(self) -> None:
        # asyncpg rend le JSONB comme une chaîne selon le codec en place.
        rendu = plain_clue(
            self.CODE, "", json.dumps({"explication": self.EXPLICATION}, ensure_ascii=False)
        )
        self.assertIn("page générique de vérification", rendu)

    def test_sans_explication_le_domaine_observe_reste_illustre(self) -> None:
        rendu = plain_clue(self.CODE, "peu importe", {"facts": {"sender_apex": "x.fr"}})
        self.assertIn("Expéditeur observé : x.fr", rendu)

    def test_une_explication_qui_redit_le_grief_n_est_pas_repetee(self) -> None:
        rendu = plain_clue(
            self.CODE,
            "",
            {"facts": {"explication": "Ce message parle de quelque chose qui n’a rien à voir avec ce que fait cet expéditeur."}},
        )
        self.assertEqual(rendu.count("rien à voir"), 1, rendu)

    def test_une_explication_bavarde_est_bornee(self) -> None:
        rendu = plain_clue(self.CODE, "", {"facts": {"explication": "détail. " * 80}})
        self.assertLessEqual(len(rendu), 400)

    def test_aucun_code_interne_ne_passe_dans_l_explication(self) -> None:
        rendu = plain_clue(
            self.CODE,
            "",
            {"facts": {"explication": "L’indice DEEP-019 (force 55) le montre."}},
        )
        self.assertNotIn("DEEP-019", rendu)
        self.assertNotIn("55", rendu)


class AdressesDeLExpediteurTests(unittest.TestCase):
    """Ce qu'un avis montre de l'expéditeur en plus de ce qu'il affiche de lui.

    Le `De :` d'un message est déclaratif : un fraudeur y écrit ce qu'il veut.
    L'adresse d'enveloppe est celle que le serveur a réellement annoncée.
    """

    def test_une_enveloppe_differente_est_signalee_comme_telle(self) -> None:
        lignes = sender_addresses(
            "'bro' <info@amazon.com>", "bounce@mailer.example.ru", None
        )
        self.assertIn(
            "Adresse d’enveloppe différente : bounce@mailer.example.ru", lignes
        )

    def test_une_enveloppe_identique_est_dite_sans_alarme(self) -> None:
        lignes = sender_addresses(
            "Amazon <info@amazon.com>", "info@amazon.com", None
        )
        self.assertIn("Adresse d’enveloppe : info@amazon.com", lignes)
        self.assertNotIn("différente", " ".join(lignes))

    def test_une_enveloppe_absente_le_dit_plutot_que_de_se_taire(self) -> None:
        lignes = sender_addresses("Amazon <info@amazon.com>", "", None)
        self.assertIn("Adresse d’enveloppe : (non disponible)", lignes)

    def test_une_adresse_de_reponse_detournee_est_montree(self) -> None:
        lignes = sender_addresses(
            "Amazon <info@amazon.com>", "info@amazon.com", "reply@ailleurs.tld"
        )
        self.assertIn("Adresse de réponse différente : reply@ailleurs.tld", lignes)

    def test_une_adresse_de_reponse_identique_n_encombre_pas(self) -> None:
        lignes = sender_addresses(
            "Amazon <info@amazon.com>", "info@amazon.com", "info@amazon.com"
        )
        self.assertNotIn("réponse", " ".join(lignes))


class EcartDAdresseTests(unittest.TestCase):
    """L'écart entre l'adresse affichée et celle que le serveur a annoncée.

    Il ne se montre que lorsqu'il existe : sans écart, deux lignes identiques
    n'apprennent rien et allongent l'avis.
    """

    def test_sans_ecart_il_n_y_a_rien_a_montrer(self) -> None:
        self.assertIsNone(sender_gap("Amazon <info@amazon.com>", "info@amazon.com"))

    def test_une_enveloppe_differente_fait_l_ecart(self) -> None:
        ecart = sender_gap("'bro' <info@amazon.com>", "bounce@mailer.example.ru")
        self.assertEqual(ecart["displayed"], "info@amazon.com")
        self.assertEqual(ecart["real"], "bounce@mailer.example.ru")

    def test_une_adresse_de_reponse_detournee_fait_l_ecart(self) -> None:
        ecart = sender_gap(
            "Amazon <info@amazon.com>", "info@amazon.com", "reply@ailleurs.tld"
        )
        self.assertEqual(ecart["reply_to"], "reply@ailleurs.tld")
        self.assertIsNone(ecart["real"])

    def test_une_enveloppe_absente_ne_fabrique_pas_d_ecart(self) -> None:
        self.assertIsNone(sender_gap("Amazon <info@amazon.com>", ""))


class IndiceDeConfianceTests(unittest.TestCase):
    """Un niveau, un mot, une couleur : ce que l'œil lit avant de lire."""

    def test_un_message_dangereux_est_dit_dangereux(self) -> None:
        badge = confidence_badge("dangerous", 3)
        self.assertEqual(badge["level"], "danger")
        self.assertEqual(badge["word"], "DANGEREUX")
        self.assertEqual(badge["detail"], "3 écarts relevés")

    def test_un_seul_ecart_ne_prend_pas_le_pluriel(self) -> None:
        self.assertEqual(confidence_badge("suspect", 1)["detail"], "1 écart relevé")

    def test_un_message_suspect_ou_indesirable_reste_douteux(self) -> None:
        for classification in ("suspect", "spam", "undetermined", ""):
            self.assertEqual(confidence_badge(classification, 2)["level"], "doute")

    def test_un_message_legitime_est_dit_sain(self) -> None:
        badge = confidence_badge("legitimate", 0)
        self.assertEqual(badge["level"], "sain")
        self.assertEqual(badge["detail"], "aucun écart relevé")

    def test_chaque_niveau_porte_sa_couleur_et_son_icone(self) -> None:
        for classification in ("dangerous", "suspect", "legitimate"):
            badge = confidence_badge(classification, 1)
            self.assertTrue(badge["color"].startswith("#"))
            self.assertIn(badge["level"], badge["cid"])


class LignesDEcartTests(unittest.TestCase):
    """La version texte de l'encart dit exactement la même chose que lui."""

    CARTE = {
        "claimed": "The Neuropathy Support Group",
        "from_domain": "animalrights.eu",
        "from_apex": "animalrights.eu",
        "official": [],
    }

    def test_l_identite_annoncee_fait_face_au_domaine_reel(self) -> None:
        lignes = gap_lines(self.CARTE, None)
        self.assertEqual(
            lignes,
            [
                "Annoncé : The Neuropathy Support Group",
                "Écrit depuis : animalrights.eu",
            ],
        )

    def test_les_adresses_suivent_l_identite(self) -> None:
        lignes = gap_lines(self.CARTE, {"displayed": "a@b.test", "real": "c@d.test"})
        self.assertEqual(lignes[-2:], ["Affiché : a@b.test", "Réel : c@d.test"])

    def test_sans_rien_a_comparer_il_n_y_a_pas_de_ligne(self) -> None:
        self.assertEqual(gap_lines(None, None), [])
