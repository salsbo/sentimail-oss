from __future__ import annotations

import unittest
from typing import ClassVar

from sentimail_v3.conversation.digest import (
    DigestDecision,
    acknowledgement,
    parse_digest_reply,
    residual_text,
    validate_interpretation,
)


class ParseDigestReplyTests(unittest.TestCase):
    def test_a_line_per_decision(self) -> None:
        decisions = parse_digest_reply("1 A\n2 B\n3 A")
        self.assertEqual(
            [(d.number, d.choice) for d in decisions],
            [(1, "A"), (2, "B"), (3, "A")],
        )

    def test_everything_on_one_line(self) -> None:
        decisions = parse_digest_reply("1 A, 2 A, 3 B")
        self.assertEqual([d.number for d in decisions], [1, 2, 3])
        self.assertEqual([d.choice for d in decisions], ["A", "A", "B"])

    def test_written_forms_are_tolerated(self) -> None:
        for text in ("1A", "1 a", "1: A", "1) a", "1 - A", "1. A"):
            decisions = parse_digest_reply(text)
            self.assertEqual(len(decisions), 1, text)
            self.assertEqual((decisions[0].number, decisions[0].choice), (1, "A"), text)

    def test_c_keeps_its_explanation(self) -> None:
        decisions = parse_digest_reply("3 C je le connais, c’est mon fournisseur")
        self.assertEqual(decisions[0].choice, "C")
        self.assertIn("je le connais", decisions[0].detail)

    def test_a_word_after_a_or_b_is_not_an_explanation(self) -> None:
        # « 1 A oui » reste une decision deterministe, pas un texte a interpreter.
        decisions = parse_digest_reply("1 A oui")
        self.assertEqual(decisions[0].detail, "")

    def test_a_correction_replaces_the_first_answer(self) -> None:
        decisions = parse_digest_reply("2 A\nnon pardon\n2 B")
        self.assertEqual(len(decisions), 1)
        self.assertEqual((decisions[0].number, decisions[0].choice), (2, "B"))

    def test_a_reply_without_decision_yields_nothing(self) -> None:
        self.assertEqual(parse_digest_reply("merci beaucoup"), [])
        self.assertEqual(parse_digest_reply(""), [])

    def test_a_date_is_not_read_as_a_decision(self) -> None:
        self.assertEqual(parse_digest_reply("rendez-vous le 12 septembre"), [])


class AcknowledgementTests(unittest.TestCase):
    def test_it_says_what_was_done_and_what_remains(self) -> None:
        text = acknowledgement(
            [(DigestDecision(1, "A", ""), "Facture Ollama")],
            [DigestDecision(9, "B", "")],
            remaining=3,
        )
        self.assertIn("Facture Ollama", text)
        self.assertIn("livré", text)
        self.assertIn("9", text)
        self.assertIn("3 message(s) en attente", text)

    def test_an_empty_reply_explains_the_expected_form(self) -> None:
        text = acknowledgement([], [], remaining=0)
        self.assertIn("1 A", text)
        self.assertIn("Plus rien", text)


if __name__ == "__main__":
    unittest.main()


class ResidualTextTests(unittest.TestCase):
    def test_a_pure_list_of_pairs_leaves_nothing(self) -> None:
        decisions = parse_digest_reply("1 A\n2 B\n3 A")
        self.assertEqual(residual_text("1 A\n2 B\n3 A", decisions), "")

    def test_a_sentence_is_kept_for_the_model(self) -> None:
        text = "5, 6 A\n\ntous les SentiMail TEST sont A, ce sont des tests."
        decisions = parse_digest_reply(text)
        rest = residual_text(text, decisions)
        self.assertIn("SentiMail TEST", rest)

    def test_an_orphan_number_is_not_lost_in_silence(self) -> None:
        # « 5, 6 A » : le 5 n'a pas de lettre, il doit survivre pour etre compris.
        text = "5, 6 A"
        decisions = parse_digest_reply(text)
        self.assertEqual([d.number for d in decisions], [6])
        self.assertIn("5", residual_text(text, decisions))

    def test_c_is_always_left_for_llm_interpretation(self) -> None:
        text = "2 C c'est mon comptable, conserve cette information"
        decisions = parse_digest_reply(text)
        rest = residual_text(text, decisions)
        self.assertIn("2 C", rest)
        self.assertIn("comptable", rest)


class ValidateInterpretationTests(unittest.TestCase):
    MAPPING: ClassVar[dict[str, str]] = {
        "1": "uuid-1",
        "2": "uuid-2",
        "5": "uuid-5",
    }
    TEXT = "tous les SentiMail TEST sont A, ce sont des tests"

    def test_a_quoted_decision_is_retained(self) -> None:
        retained, question = validate_interpretation(
            {
                "decisions": [
                    {"number": 1, "choice": "A", "quote": "tous les SentiMail TEST sont A"}
                ],
                "question": None,
            },
            self.TEXT,
            self.MAPPING,
            set(),
        )
        self.assertEqual([(d.number, d.choice) for d in retained], [(1, "A")])
        self.assertIsNone(question)

    def test_an_invented_quote_is_refused(self) -> None:
        retained, _ = validate_interpretation(
            {"decisions": [{"number": 1, "choice": "A", "quote": "livre tout"}]},
            self.TEXT,
            self.MAPPING,
            set(),
        )
        self.assertEqual(retained, [])

    def test_an_unknown_number_is_refused(self) -> None:
        retained, _ = validate_interpretation(
            {
                "decisions": [
                    {"number": 42, "choice": "A", "quote": "tous les SentiMail TEST"}
                ]
            },
            self.TEXT,
            self.MAPPING,
            set(),
        )
        self.assertEqual(retained, [])

    def test_a_literal_decision_is_never_overridden(self) -> None:
        retained, _ = validate_interpretation(
            {
                "decisions": [
                    {"number": 2, "choice": "B", "quote": "tous les SentiMail TEST"}
                ]
            },
            self.TEXT,
            self.MAPPING,
            already={2},
        )
        self.assertEqual(retained, [])

    def test_a_question_survives_without_decision(self) -> None:
        retained, question = validate_interpretation(
            {"decisions": [], "question": "Tu veux dire les numéros 1 et 2 ?"},
            self.TEXT,
            self.MAPPING,
            set(),
        )
        self.assertEqual(retained, [])
        self.assertIn("1 et 2", question or "")


class IncidentOfTheThirteenthTests(unittest.TestCase):
    """La phrase qui a fait livrer un phishing, et ce qui l'en empêche."""

    TEXT = (
        "3 ce sont des mails de tests, considere comme OK surtout que "
        "l emmeteur est maia@mondomaine.example"
    )
    MAPPING: ClassVar[dict[str, str]] = {"1": "u1", "2": "u2", "3": "u3"}
    SENDERS: ClassVar[dict[str, str]] = {
        "1": "MAIA Test <maia@mondomaine.example>",
        "2": "MAIA Test <maia@mondomaine.example>",
        "3": "Support Mondomaine <security@evil.example>",
    }

    def test_the_literal_reading_finds_no_decision(self) -> None:
        # « 3 ce » n'est pas « 3 C » : aucune decision litterale ici.
        self.assertEqual(parse_digest_reply(self.TEXT), [])

    def test_a_reason_naming_another_sender_is_refused(self) -> None:
        retained, question = validate_interpretation(
            {
                "decisions": [
                    {
                        "number": 3,
                        "choice": "A",
                        "quote": "considere comme OK surtout que l emmeteur est maia@mondomaine.example",
                    }
                ],
                "question": None,
            },
            self.TEXT,
            self.MAPPING,
            set(),
            senders=self.SENDERS,
        )
        # Le motif parle de maia@mondomaine.example, le dossier vient de evil.example.
        self.assertEqual(retained, [])
        self.assertIn("3", question or "")

    def test_the_same_reason_holds_for_the_matching_case(self) -> None:
        retained, _ = validate_interpretation(
            {
                "decisions": [
                    {
                        "number": 1,
                        "choice": "A",
                        "quote": "considere comme OK surtout que l emmeteur est maia@mondomaine.example",
                    }
                ]
            },
            self.TEXT,
            self.MAPPING,
            set(),
            senders=self.SENDERS,
        )
        self.assertEqual([d.number for d in retained], [1])
        self.assertTrue(retained[0].interpreted)

    def test_an_interpreted_decision_is_marked_as_such(self) -> None:
        retained, _ = validate_interpretation(
            {"decisions": [{"number": 1, "choice": "A", "quote": "ce sont des mails de tests"}]},
            self.TEXT,
            self.MAPPING,
            set(),
            senders=self.SENDERS,
        )
        self.assertTrue(all(d.interpreted for d in retained))
        # Une decision ecrite, elle, n'est jamais marquee comme interpretee.
        self.assertFalse(parse_digest_reply("1 A")[0].interpreted)

    def test_the_acknowledgement_explains_a_refused_delivery(self) -> None:
        text = acknowledgement(
            [],
            [],
            remaining=5,
            needs_confirmation=[(DigestDecision(3, "A", "", True), "Phishing évident")],
        )
        self.assertIn("Phishing évident", text)
        self.assertIn("preuve matérielle", text)
        self.assertIn("3 A", text)


class LettreSeuleTests(unittest.TestCase):
    def test_une_lettre_seule_est_reconnue(self) -> None:
        from sentimail_v3.conversation.digest import lone_choice

        for texte, attendu in (
            ("A", "A"),
            ("a\n\nEnvoyé à partir d'Outlook pour Mac", "A"),
            ("B", "B"),
        ):
            decision = lone_choice(texte)
            self.assertIsNotNone(decision, texte)
            self.assertEqual(decision.choice, attendu)

    def test_une_reponse_numerotee_n_est_pas_une_lettre_seule(self) -> None:
        from sentimail_v3.conversation.digest import parse_digest_reply

        # « 1 A » se lit par le chemin normal ; la lettre seule ne sert qu'au
        # cas où aucun numéro n'a été écrit.
        self.assertTrue(parse_digest_reply("1 A"))

    def test_une_phrase_libre_n_est_pas_une_decision(self) -> None:
        from sentimail_v3.conversation.digest import lone_choice

        for texte in ("je ne sais pas", "peux-tu m'expliquer ?", ""):
            self.assertIsNone(lone_choice(texte), texte)

    def test_un_c_seul_garde_son_explication(self) -> None:
        from sentimail_v3.conversation.digest import lone_choice

        decision = lone_choice("C ce sont mes reservations de vol")
        self.assertIsNotNone(decision)
        self.assertEqual(decision.choice, "C")
        self.assertIn("reservations", decision.detail)


class ConfirmationDuDangerTests(unittest.TestCase):
    def test_accuse_dit_classe_dangereux_sans_preuve_materielle(self) -> None:
        demandes = [
            (DigestDecision(2, "A", "", True), "Colis en attente"),
            (DigestDecision(4, "A", "", True), "Compte suspendu"),
        ]
        texte = acknowledgement(
            [], [], remaining=3, needs_confirmation=demandes, dangerous_numbers={4}
        )
        deuxieme, quatrieme = texte.split("Je n’ai pas livré le ")[1:3]
        self.assertIn("preuve matérielle", deuxieme)
        self.assertNotIn("classe dangereux", deuxieme)
        self.assertIn("classe dangereux", quatrieme)
        self.assertNotIn("preuve matérielle", quatrieme)
        self.assertIn("« 4 A »", quatrieme)


class ACorrigeParLeClavierTests(unittest.TestCase):
    def test_a_accentue_seul_vaut_a_quand_un_dossier_attend(self) -> None:
        from sentimail_v3.conversation.digest import read_reply

        lecture = read_reply("À", "À", "", 1)
        self.assertEqual(
            [(value.number, value.choice) for value in lecture.decisions], [(0, "A")]
        )
        self.assertEqual(read_reply("à demain", "à demain", "", 1).decisions, [])
        self.assertEqual(parse_digest_reply("1 à 3"), [])
