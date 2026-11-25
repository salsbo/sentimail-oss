from __future__ import annotations

import json
import unittest
from unittest.mock import AsyncMock, patch

from sentimail_v3.conversation.human_decision import (
    HumanDecision,
    apply_human_decision,
)


class ApplicationTests(unittest.IsolatedAsyncioTestCase):
    async def test_une_decision_applique_tous_ses_effets_dans_la_connexion(
        self,
    ) -> None:
        connection = AsyncMock()
        connection.fetch.return_value = [{"clue_code": "BODY-001"}]
        connection.fetchrow.return_value = {
            "from_header": "Sender <sender@example.net>",
            "envelope_from": "sender@example.net",
            "dmarc": True,
            "spf": True,
            "dkim": None,
        }
        decision = HumanDecision(
            message_id="11111111-1111-1111-1111-111111111111",
            participant_email="User@Example.org",
            sender="sender@example.net",
            subject="Un objet",
            classification="spam",
            list_action="hold",
            policy_source="authenticated_smtp_choice_b",
            label_context={"interpretation": "test"},
            case_id="case-id",
            close_current=True,
            close_details={"closed_by": "test"},
            audit_choice="B",
        )
        with patch(
            "sentimail_v3.conversation.human_decision.store_ground_truth_sample",
            new=AsyncMock(),
        ) as store:
            signals = await apply_human_decision(connection, decision)

        self.assertEqual(signals, ["BODY-001"])
        store.assert_awaited_once_with(connection, decision.message_id, "spam")
        label_call = next(
            call
            for call in connection.execute.await_args_list
            if "INSERT INTO labels" in call.args[0]
        )
        self.assertEqual(json.loads(label_call.args[5])["signals"], ["BODY-001"])
        self.assertTrue(
            any(
                "UPDATE delivery_cases" in call.args[0]
                for call in connection.execute.await_args_list
            )
        )
        self.assertTrue(
            any(
                "INSERT INTO sender_policies" in call.args[0]
                for call in connection.execute.await_args_list
            )
        )

    async def test_sans_classification_ni_liste_aucun_effet_metier(self) -> None:
        connection = AsyncMock()
        signals = await apply_human_decision(
            connection,
            HumanDecision(
                message_id="11111111-1111-1111-1111-111111111111",
                participant_email="user@example.org",
                sender="sender@example.net",
                subject=None,
            ),
        )
        self.assertEqual(signals, [])
        connection.fetch.assert_not_awaited()
        connection.execute.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
