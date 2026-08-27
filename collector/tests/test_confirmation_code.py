from __future__ import annotations

import unittest

from sentimail_v3.conversation.confirmation_code import (
    LENGTH,
    TTL_MINUTES,
    code_hash,
    confirms,
    extract_code,
    new_code,
)


class ConfirmationCodeTests(unittest.TestCase):
    def test_a_code_is_short_unambiguous_and_never_twice_the_same(self) -> None:
        codes = {new_code() for _ in range(200)}
        self.assertGreater(len(codes), 150)
        for code in codes:
            self.assertEqual(len(code), LENGTH)
            # Ce code se recopie à la main : rien qui se confonde à la lecture.
            self.assertFalse(set(code) & set("ILOU01"))

    def test_the_sentence_alone_no_longer_confirms_anything(self) -> None:
        code = new_code()
        self.assertFalse(confirms("CONFIRME MAIA", code_hash(code)))
        self.assertFalse(confirms("Confirme maia.", code_hash(code)))

    def test_the_right_code_confirms(self) -> None:
        code = new_code()
        self.assertTrue(confirms(f"CONFIRME MAIA {code}", code_hash(code)))

    def test_another_code_never_confirms(self) -> None:
        self.assertFalse(confirms("CONFIRME MAIA 234567", code_hash(new_code())))

    def test_a_human_transcription_is_accepted(self) -> None:
        code = "ABCD23"
        expected = code_hash(code)
        for written in (
            "confirme maia abcd23",
            "CONFIRME MAIA  ABC D23",
            "Confirme MAIA : ABCD-23",
            "Bonjour, CONFIRME MAIA ABCD23 merci",
        ):
            self.assertTrue(confirms(written, expected), written)

    def test_a_code_without_the_sentence_confirms_nothing(self) -> None:
        # Un rebond automatique qui recopie le corps ne doit pas valider.
        code = "ABCD23"
        self.assertFalse(confirms(f"ABCD23 est ton code", code_hash(code)))

    def test_an_action_without_a_stored_code_cannot_be_confirmed(self) -> None:
        # Les challenges émis avant cette protection ne sont pas rattrapables.
        self.assertFalse(confirms("CONFIRME MAIA ABCD23", None))
        self.assertFalse(confirms("CONFIRME MAIA ABCD23", ""))

    def test_extraction_ignores_what_is_not_a_code(self) -> None:
        self.assertIsNone(extract_code("CONFIRME MAIA"))
        self.assertIsNone(extract_code("rien à voir"))
        self.assertEqual(extract_code("confirme maia zzz234"), "ZZZ234")

    def test_the_code_lives_five_minutes(self) -> None:
        self.assertEqual(TTL_MINUTES, 5)


if __name__ == "__main__":
    unittest.main()
