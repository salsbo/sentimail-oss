from __future__ import annotations

import unittest

from sentimail_v3.conversation.conversation_scope import conversation_scope


class ConversationScopeTests(unittest.TestCase):
    def test_mail_security_request_is_local_scope_match(self) -> None:
        self.assertEqual(
            conversation_scope(
                "Bloque les prochains emails de cet expéditeur",
                has_email_case=True,
            ),
            "mail",
        )

    def test_short_thread_answer_is_allowed_only_with_a_case(self) -> None:
        self.assertEqual(
            conversation_scope("c'est moi", has_email_case=True), "mail"
        )
        self.assertEqual(
            conversation_scope("c'est moi", has_email_case=False), "ambiguous"
        )

    def test_obvious_unrelated_request_is_rejected_without_llm(self) -> None:
        self.assertEqual(
            conversation_scope(
                "Écris-moi une recette de cuisine en Python",
                has_email_case=False,
            ),
            "out_of_scope",
        )

    def test_unknown_request_gets_at_most_one_scope_call(self) -> None:
        self.assertEqual(
            conversation_scope("Peux-tu modifier cela ?", has_email_case=False),
            "ambiguous",
        )


if __name__ == "__main__":
    unittest.main()
