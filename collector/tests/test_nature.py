from __future__ import annotations

import asyncio
import unittest

from sentimail_v3.observation.deep_analysis import _SIGNAL_RULES, _signals
from sentimail_v3.observation.dossier.hooks.content import ContentHook
from sentimail_v3.observation.dossier.hooks.nature import (
    NatureHook,
    is_bulk_mailing,
    sending_mode,
)
from sentimail_v3.observation.dossier.models import InvestigationContext
from sentimail_v3.observation.dossier.pipeline import build_hooks
from sentimail_v3.observation.parser import parse_message

PROMOTIONAL = (
    b"From: Health News <news@wellness-offers.example>\r\n"
    b"To: user@example.org\r\n"
    b"Subject: Pharmaceutical cartels are suppressing this natural solution\r\n"
    b"List-Unsubscribe: <https://wellness-offers.example/u/42>\r\n"
    b"Precedence: bulk\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
    b"Doctors keep this secret: our natural formula changes everything for your\r\n"
    b"cardiovascular function and weight loss.\r\n"
)
NEWSLETTER = (
    b"From: Product Team <news@vendor.example>\r\n"
    b"To: user@example.org\r\n"
    b"Subject: Release notes for version 4.2\r\n"
    b"List-Id: <news.vendor.example>\r\n"
    b"List-Unsubscribe: <https://vendor.example/u/7>\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
    b"Version 4.2 adds incremental backups and a new audit view.\r\n"
)
UNDECLARED_SPAM = (
    b'From: "Dr. Gupta Health Desk" <support@t3.example.cn>\r\n'
    b"To: user@example.org\r\n"
    b"Subject: Pharmaceutical cartels are suppressing this natural solution\r\n"
    b'Content-Type: text/html; charset="utf-8"\r\n\r\n'
    b"<html><body><p>The natural formula doctors keep quiet about your"
    b" cardiovascular function.</p></body></html>\r\n"
)
PERSONAL = (
    b"From: Colleague <colleague@example.org>\r\n"
    b"To: user@example.org\r\n"
    b"Subject: Compte rendu de la reunion\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
    b"Voici le compte rendu promis hier.\r\n"
)
TRANSACTIONAL_WITH_COMPLAINT_HEADER = (
    b"From: Service client <service@notifications.entreprise.example>\r\n"
    b"To: user@example.org\r\n"
    b"Subject: Accuse de reception de votre demande\r\n"
    b"X-CSA-Complaints: complaints@example.org\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
    b"Nous avons bien recu votre demande et nous la traitons.\r\n"
)


def _observe(raw: bytes) -> tuple[list[object], dict[str, object]]:
    context = InvestigationContext(
        raw=raw,
        parsed=parse_message(raw),
        envelope_from="bounce@sender.example",
        recipients=["user@example.org"],
    )
    return asyncio.run(NatureHook().observe(context))


class SendingModeTests(unittest.TestCase):
    def test_list_headers_identify_a_mass_mailing(self) -> None:
        mode = sending_mode(parse_message(NEWSLETTER))
        self.assertEqual(mode["mode"], "bulk")
        self.assertTrue(mode["unsubscribe_offered"])
        self.assertIn("list-id", mode["bulk_headers_present"])

    def test_a_personal_message_is_never_a_mass_mailing(self) -> None:
        self.assertFalse(is_bulk_mailing(parse_message(PERSONAL)))
        self.assertEqual(
            sending_mode(parse_message(PERSONAL))["mode"], "conversational"
        )

    def test_un_canal_de_plainte_seul_ne_prouve_pas_un_envoi_de_masse(self) -> None:
        mode = sending_mode(parse_message(TRANSACTIONAL_WITH_COMPLAINT_HEADER))
        self.assertEqual(mode["mode"], "conversational")
        self.assertIn("x-csa-complaints", mode["bulk_headers_present"])

    def test_precedence_alone_identifies_a_mass_mailing(self) -> None:
        raw = PERSONAL.replace(
            b"Subject: Compte rendu de la reunion\r\n",
            b"Subject: Compte rendu de la reunion\r\nPrecedence: bulk\r\n",
        )
        self.assertTrue(is_bulk_mailing(parse_message(raw)))


class NatureHookTests(unittest.TestCase):
    def test_the_hook_is_part_of_the_ordered_pipeline(self) -> None:
        names = [hook.name for hook in build_hooks()]
        self.assertIn("nature", names)
        self.assertLess(names.index("content"), names.index("nature"))

    def test_unverifiable_promises_are_an_adverse_clue(self) -> None:
        clues, facts = _observe(PROMOTIONAL)
        codes = {clue.clue_code: clue for clue in clues}
        self.assertIn("NATURE_BULK_MAILING", codes)
        promotional = codes["NATURE_UNVERIFIABLE_PROMOTIONAL_CLAIMS"]
        self.assertEqual(promotional.direction, "adverse")
        self.assertEqual(promotional.article_code, "NATURE-003")
        self.assertEqual(facts["claim_registers"], ["health"])

    def test_an_ordinary_newsletter_is_only_described(self) -> None:
        clues, facts = _observe(NEWSLETTER)
        codes = {clue.clue_code for clue in clues}
        self.assertEqual(codes, {"NATURE_BULK_MAILING"})
        self.assertEqual(facts["claim_registers"], [])
        self.assertEqual(
            [
                clue.direction
                for clue in clues
                if clue.clue_code == "NATURE_BULK_MAILING"
            ],
            ["neutral"],
        )

    def test_a_solicitation_that_hides_its_nature_is_still_recognised(self) -> None:
        clues, facts = _observe(UNDECLARED_SPAM)
        codes = {clue.clue_code for clue in clues}
        self.assertEqual(facts["sending_mode"], "conversational")
        self.assertIn("NATURE_UNVERIFIABLE_PROMOTIONAL_CLAIMS", codes)
        self.assertIn("NATURE_SOLICITATION_WITHOUT_OPT_OUT", codes)
        self.assertEqual(facts["claim_registers"], ["health"])

    def test_a_declared_mailing_is_not_blamed_for_its_opt_out(self) -> None:
        codes = {clue.clue_code for clue in _observe(PROMOTIONAL)[0]}
        self.assertNotIn("NATURE_SOLICITATION_WITHOUT_OPT_OUT", codes)

    def test_a_personal_message_produces_no_clue(self) -> None:
        clues, facts = _observe(PERSONAL)
        self.assertEqual(clues, [])
        self.assertEqual(facts["sending_mode"], "conversational")


def _spam(subject: str, body: str = "") -> bytes:
    return (
        b'From: "News Desk" <support@random-host.example>\r\n'
        b"To: user@example.org\r\n"
        b"Subject: " + subject.encode() + b"\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n" + body.encode() + b"\r\n"
    )


class BroadenedCureRhetoricTests(unittest.TestCase):
    """Le démarchage santé au vocabulaire élargi doit être vu, sans faux positif."""

    def _codes(self, raw: bytes) -> set[str]:
        clues, _ = _observe(raw)
        return {clue.clue_code for clue in clues}

    def test_cognitive_and_dated_promises_are_recognised(self) -> None:
        for subject in (
            "Reverse cognitive decline in 45 days with cinnamon",
            "The blend that flushes out neural inflammation",
            "Simple morning routine that restores youthful blood flow",
        ):
            self.assertIn(
                "NATURE_UNVERIFIABLE_PROMOTIONAL_CLAIMS",
                self._codes(_spam(subject)),
                subject,
            )

    def test_a_health_topic_without_cure_rhetoric_stays_silent(self) -> None:
        # Registre santé présent, mais aucune promesse invérifiable : un vrai
        # contenu médical ne doit pas être accusé. Le ET protège du faux positif.
        codes = self._codes(_spam("Your cardiovascular check-up results are ready"))
        self.assertNotIn("NATURE_UNVERIFIABLE_PROMOTIONAL_CLAIMS", codes)

    def test_a_cure_verb_without_health_register_stays_silent(self) -> None:
        # « restore » hors santé (mot de passe) ne fabrique pas un registre
        # médical : sans les deux, aucun indice.
        codes = self._codes(_spam("Restore your password in 3 days"))
        self.assertNotIn("NATURE_UNVERIFIABLE_PROMOTIONAL_CLAIMS", codes)


class AbsenceOfPressureTests(unittest.TestCase):
    def _content_codes(self, raw: bytes) -> set[str]:
        context = InvestigationContext(
            raw=raw,
            parsed=parse_message(raw),
            envelope_from="bounce@sender.example",
            recipients=["user@example.org"],
        )
        clues, _ = asyncio.run(ContentHook().observe(context))
        return {clue.clue_code for clue in clues}

    def test_a_mass_mailing_is_never_credited_for_its_calm_tone(self) -> None:
        for raw in (PROMOTIONAL, NEWSLETTER, UNDECLARED_SPAM):
            self.assertNotIn("CONTENT_NO_SENSITIVE_PRESSURE", self._content_codes(raw))

    def test_a_personal_message_keeps_its_favourable_clue(self) -> None:
        self.assertIn("CONTENT_NO_SENSITIVE_PRESSURE", self._content_codes(PERSONAL))


class UnsolicitedBulkSignalTests(unittest.TestCase):
    def _signal_kinds(
        self, nature: dict[str, object] | None, history: dict[str, object]
    ) -> set[str]:
        signals = _signals([], [], history, True, authenticated=True, nature=nature)
        return {str(item.get("kind")) for item in signals}

    def test_a_first_mass_mailing_without_any_history_is_unsolicited(self) -> None:
        kinds = self._signal_kinds(
            {"sending_mode": "bulk", "unsubscribe_offered": True},
            {"previous_message_count": 0, "ground_truth_labels": {}},
        )
        self.assertIn("unsolicited_bulk", kinds)

    def test_le_signal_distingue_l_adresse_exacte_du_domaine_parent(self) -> None:
        signals = _signals(
            [],
            [],
            {
                "sender_address": "service@campagne.entreprise.example",
                "sender_apex": "entreprise.example",
                "previous_message_count": 0,
                "ground_truth_labels": {},
            },
            True,
            authenticated=True,
            nature={"sending_mode": "bulk"},
        )
        signal = next(
            value for value in signals if value.get("article_code") == "NATURE-002"
        )
        self.assertEqual(signal["sender_apex"], "entreprise.example")
        statement = _SIGNAL_RULES["NATURE-002"][4]
        self.assertIn("adresse exacte", statement)
        self.assertIn("domaine parent est évalué séparément", statement)
        self.assertNotIn("expéditeur inconnu", statement)
        self.assertNotIn("sans abonnement établi", statement)

    def test_a_known_correspondent_mailing_is_not_unsolicited(self) -> None:
        kinds = self._signal_kinds(
            {"sending_mode": "bulk"},
            {"previous_message_count": 12, "ground_truth_labels": {}},
        )
        self.assertNotIn("unsolicited_bulk", kinds)

    def test_a_human_confirmation_settles_the_subscription(self) -> None:
        kinds = self._signal_kinds(
            {"sending_mode": "bulk"},
            {"previous_message_count": 0, "ground_truth_labels": {"legitimate": 1}},
        )
        self.assertNotIn("unsolicited_bulk", kinds)

    def test_a_case_analysed_before_the_hook_stays_neutral(self) -> None:
        kinds = self._signal_kinds(
            {}, {"previous_message_count": 0, "ground_truth_labels": {}}
        )
        self.assertNotIn("unsolicited_bulk", kinds)


if __name__ == "__main__":
    unittest.main()
