from __future__ import annotations

import unittest

from sentimail_v3.supervision.training_store import annotation_provenance


class AnnotationProvenanceTests(unittest.TestCase):
    def test_smtp_feedback_is_a_mailbox_preference(self) -> None:
        self.assertEqual(
            annotation_provenance("smtp_feedback_user"),
            ("user", "mailbox_preference"),
        )

    def test_adjudication_is_security_expertise(self) -> None:
        self.assertEqual(
            annotation_provenance("expert_adjudication"),
            ("expert", "security"),
        )
