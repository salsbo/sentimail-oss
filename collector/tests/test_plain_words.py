from __future__ import annotations

import json
import re
import unittest

from sentimail_v3.code.plain_words import (
    plain_clue,
    plain_limits,
    plain_points,
    plain_rationale,
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
    )

    def test_chaque_critere_se_dit_en_francais_sans_jargon(self) -> None:
        for code in self.CODES:
            with self.subTest(code=code):
                phrase = plain_clue(code, "énoncé technique de repli")
                self.assertIsNotNone(phrase)
                self.assertNotIn("apex", str(phrase).casefold())
                self.assertNotIn("dkim", str(phrase).casefold())
                self.assertNotEqual(phrase, "énoncé technique de repli.")


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

    def test_sans_explication_la_phrase_reste_seule(self) -> None:
        rendu = plain_clue(self.CODE, "peu importe", {"facts": {"sender_apex": "x.fr"}})
        self.assertEqual(rendu, plain_clue(self.CODE, "peu importe"))

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
