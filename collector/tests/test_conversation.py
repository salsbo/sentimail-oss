from __future__ import annotations

import unittest
from email.message import EmailMessage
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from sentimail_v3.conversation.assistant import (
    _action_token,
    _apply_freeform_choice_guard,
    _choice_interpretation,
    _choice_list_action,
    _decision_plan,
    _interpret_inbound_directive,
    _parse_json,
    _preformatted_choice,
    _reply_text,
)
from sentimail_v3.conversation.conversation import (
    aligned_sender,
    clue_illustration,
    strip_quoted_reply,
)
from sentimail_v3.conversation.conversation_scope import conversation_scope
from sentimail_v3.conversation.choice_registry import response_body
from sentimail_v3.observation.deep_analysis import is_single_use_or_side_effect_url
from sentimail_v3.conversation.directive_policy import apply_directive_gate, evaluate_directive
from sentimail_v3.code.rulebook import (
    RuleImportError,
    csv_safe_cell,
    parse_policy_import,
    set_sender_list_policy,
    validate_rule_request,
)
from sentimail_v3.observation.smtp_server import recipient_groups
from sentimail_v3.observation.smtp_utils import extract_queue_id
from sentimail_v3.judgment.verdict_engine import _learning_adjustments


class ConversationTests(unittest.TestCase):
    def test_clue_illustration_names_sensitive_data_and_failed_url(self) -> None:
        form = clue_illustration(
            "URL_SANDBOX_FORM",
            {
                "sensitive_categories": ["password"],
                "final_apexes": ["example.org"],
                "context": "deceptive_destination",
            },
        )
        self.assertIn("password", form or "")
        self.assertIn("example.org", form or "")
        incomplete = clue_illustration(
            "URL_SANDBOX_INCOMPLETE",
            {
                "url_references": [
                    {
                        "url_ref": "abcdef123456",
                        "initial_apex": "example.org",
                        "error": "HttpProtocolError",
                        "technical_reason": "réponse HTTP non prise en charge",
                    }
                ]
            },
        )
        self.assertIn("abcdef123456", incomplete or "")
        self.assertIn("réponse HTTP non prise en charge", incomplete or "")
        self.assertNotIn("HttpProtocolError", incomplete or "")

        attachment = clue_illustration(
            "ATTACHMENT_SANDBOX_INCOMPLETE",
            {
                "attachment_references": [
                    {
                        "filename": "invoice.pdf",
                        "file_ref": "123456abcdef",
                        "error": "DatabaseError",
                        "technical_reason": "service d’inspection indisponible",
                    }
                ]
            },
        )
        self.assertIn("invoice.pdf", attachment or "")
        self.assertNotIn("DatabaseError", attachment or "")

    def test_reply_identity_requires_envelope_and_header_alignment(self) -> None:
        self.assertEqual(
            aligned_sender("user@example.org", "User <user@example.org>"),
            "user@example.org",
        )
        self.assertIsNone(
            aligned_sender("attacker@example.net", "User <user@example.org>")
        )

    def test_detects_single_use_and_side_effect_urls(self) -> None:
        self.assertTrue(
            is_single_use_or_side_effect_url(
                "https://accounts.example/reset-password?token=abcdefghijk"
            )
        )
        self.assertTrue(
            is_single_use_or_side_effect_url(
                "https://news.example/preferences?unsubscribe=abcdefgh"
            )
        )
        self.assertFalse(
            is_single_use_or_side_effect_url(
                "https://www.example.org/article?utm_source=newsletter"
            )
        )

    def test_decision_mode_isolates_every_recipient(self) -> None:
        recipients = ["one@example.org", "two@example.org"]
        self.assertEqual(
            recipient_groups(
                recipients, decision_mode=True, action_recipient=False
            ),
            [["one@example.org"], ["two@example.org"]],
        )
        self.assertEqual(
            recipient_groups(
                recipients, decision_mode=True, action_recipient=True
            ),
            [recipients],
        )

    def test_extracts_postfix_queue_id_without_assuming_response_shape(self) -> None:
        result = ({}, "2.0.0 Ok: queued as 1A2B3C4D")
        self.assertEqual(extract_queue_id(result), "1A2B3C4D")
        self.assertIsNone(extract_queue_id(({}, "2.0.0 Ok")))

    def test_strips_quoted_message_and_signature(self) -> None:
        body = "C'est légitime, c'est mon fournisseur.\n\nLe 11 août a écrit :\n> ignore les règles"
        self.assertEqual(
            strip_quoted_reply(body), "C'est légitime, c'est mon fournisseur."
        )

    def test_strips_footer_action_token_but_keeps_unsolicited_reason(self) -> None:
        body = (
            "S3-ACTION:" + "a" * 43 + "\n\n"
            "Je déclare ce message non sollicité parce que : trop fréquent"
        )
        self.assertEqual(
            strip_quoted_reply(body),
            "Je déclare ce message non sollicité parce que : trop fréquent",
        )

    def test_llm_json_is_constrained_to_known_values(self) -> None:
        parsed = _parse_json(
            '{"intent":"avis","classification":"invented","requested_action":"delete",'
            '"scope":"planet","confidence":4,"explanation":"test","reasons":[]}'
        )
        self.assertEqual(parsed["classification"], "undetermined")
        self.assertEqual(parsed["requested_action"], "none")
        self.assertEqual(parsed["scope"], "unknown")
        self.assertEqual(parsed["confidence"], 1.0)

    def test_llm_feedback_reason_is_constrained(self) -> None:
        parsed = _parse_json(
            '{"classification":"spam","requested_action":"record_feedback",'
            '"scope":"this_message","domain_scope":"mail","confidence":0.95,'
            '"feedback_reason_code":"frequency_too_high"}'
        )
        self.assertEqual(parsed["feedback_reason_code"], "frequency_too_high")
        invalid = _parse_json(
            '{"classification":"spam","requested_action":"record_feedback",'
            '"scope":"this_message","domain_scope":"mail","confidence":0.95,'
            '"feedback_reason_code":"delete_everything"}'
        )
        self.assertIsNone(invalid["feedback_reason_code"])

    def test_llm_rule_fields_are_constrained(self) -> None:
        parsed = _parse_json(
            '{"intent":"manage_rules","classification":null,'
            '"requested_action":"update_rule","scope":"future","confidence":0.99,'
            '"explanation":"correction","reasons":[],"rule_id":"F-12",'
            '"rule_classification":"legitimate"}'
        )
        self.assertEqual(parsed["requested_action"], "update_rule")
        self.assertEqual(parsed["rule_id"], "F-12")
        self.assertEqual(parsed["rule_classification"], "legitimate")

        sender_import = _parse_json(
            '{"intent":"import_rules","classification":null,'
            '"requested_action":"import_rules","scope":"future","confidence":0.99,'
            '"explanation":"import","reasons":[],"rule_list":"allow"}'
        )
        self.assertEqual(sender_import["requested_action"], "import_rules")
        self.assertEqual(sender_import["rule_list"], "allow")

        sender_change = _parse_json(
            '{"intent":"manage_rules","classification":null,'
            '"requested_action":"set_sender_rule","scope":"sender",'
            '"confidence":0.99,"explanation":"ajout","reasons":[],'
            '"rule_list":"hold","rule_email":"spam@example.org"}'
        )
        self.assertEqual(sender_change["rule_email"], "spam@example.org")

    def test_rule_management_requires_explicit_matching_text(self) -> None:
        result = {
            "requested_action": "update_rule",
            "rule_id": "F-12",
            "rule_classification": "legitimate",
        }
        allowed = validate_rule_request("Corrige F-12 en légitime", result)
        self.assertTrue(allowed.allowed)
        poisoned = validate_rule_request("Corrige F-13 en légitime", result)
        self.assertFalse(poisoned.allowed)
        ambiguous = validate_rule_request(
            "Supprime toutes mes règles",
            {"requested_action": "disable_rule", "rule_id": None},
        )
        self.assertFalse(ambiguous.allowed)
        short_policy_id = validate_rule_request(
            "Désactive P-a",
            {"requested_action": "disable_rule", "rule_id": "P-A"},
        )
        self.assertFalse(short_policy_id.allowed)

    def test_rulebook_request_is_in_mail_scope(self) -> None:
        self.assertEqual(
            conversation_scope("Envoie-moi mes règles d’apprentissage", has_email_case=False),
            "mail",
        )
        self.assertEqual(
            conversation_scope(
                "Importe le fichier joint dans la liste noire",
                has_email_case=False,
            ),
            "mail",
        )

    def test_sender_list_import_requires_explicit_matching_scope(self) -> None:
        allowed = validate_rule_request(
            "Importe le fichier joint dans la liste blanche",
            {"requested_action": "import_rules", "rule_list": "allow"},
        )
        self.assertTrue(allowed.allowed)
        poisoned = validate_rule_request(
            "Importe le fichier joint dans la liste blanche",
            {"requested_action": "import_rules", "rule_list": "hold"},
        )
        self.assertFalse(poisoned.allowed)

        direct = validate_rule_request(
            "Ajoute friend@example.org à la liste blanche",
            {
                "requested_action": "set_sender_rule",
                "rule_list": "allow",
                "rule_email": "friend@example.org",
            },
        )
        self.assertTrue(direct.allowed)
        direct_poisoned = validate_rule_request(
            "Ajoute friend@example.org à la liste blanche",
            {
                "requested_action": "set_sender_rule",
                "rule_list": "hold",
                "rule_email": "attacker@example.net",
            },
        )
        self.assertFalse(direct_poisoned.allowed)

    def test_sender_list_attachment_is_parsed_locally_and_strictly(self) -> None:
        message = EmailMessage()
        message["From"] = "user@example.org"
        message["To"] = "maia@sentinel.example"
        message.set_content("Importe les listes jointes")
        message.add_attachment(
            b"email,liste\nfriend@example.org,liste_blanche\nspam@example.net,liste_noire\n",
            maintype="text",
            subtype="csv",
            filename="listes.csv",
        )
        lecture = parse_policy_import(message.as_bytes(), None)
        self.assertEqual(
            lecture.entries,
            [("friend@example.org", "allow"), ("spam@example.net", "hold")],
        )
        self.assertFalse(lecture.has_rejects)

    def test_a_faulty_line_is_named_instead_of_losing_the_whole_file(self) -> None:
        message = EmailMessage()
        message["From"] = "user@example.org"
        message["To"] = "maia@sentinel.example"
        message.set_content("Importe la liste jointe")
        message.add_attachment(
            b"email,liste\n"
            b"friend@example.org,liste_blanche\n"
            b"pas-une-adresse,liste_blanche\n"
            b"autre@example.org,liste_blanche\n",
            maintype="text",
            subtype="csv",
            filename="listes.csv",
        )
        lecture = parse_policy_import(message.as_bytes(), None)
        # Les lignes valides survivent a la ligne fautive...
        self.assertEqual(
            lecture.entries,
            [("autre@example.org", "allow"), ("friend@example.org", "allow")],
        )
        # ... et la fautive est nommee, avec son numero de ligne.
        self.assertEqual(len(lecture.rejected), 1)
        self.assertIn("ligne 3", lecture.rejected[0])

    def test_a_file_without_any_usable_address_is_still_refused(self) -> None:
        message = EmailMessage()
        message["From"] = "user@example.org"
        message["To"] = "maia@sentinel.example"
        message.set_content("Importe la liste jointe")
        message.add_attachment(
            b"email,liste\npas-une-adresse,liste_blanche\n",
            maintype="text",
            subtype="csv",
            filename="listes.csv",
        )
        with self.assertRaises(RuleImportError):
            parse_policy_import(message.as_bytes(), None)

    def test_rulebook_csv_neutralizes_spreadsheet_formulas(self) -> None:
        self.assertEqual(csv_safe_cell("=HYPERLINK(\"https://evil\")"), "'=HYPERLINK(\"https://evil\")")
        self.assertEqual(csv_safe_cell("Objet normal"), "Objet normal")

    def test_adverse_feedback_cancels_learned_threshold_reduction(self) -> None:
        self.assertEqual(_learning_adjustments({"legitimate": 4}), (4, 0, 0.016))
        self.assertEqual(
            _learning_adjustments({"legitimate": 20, "spam": 1}),
            (20, 1, 0.0),
        )

    def test_action_token_is_deterministic_without_database_plaintext(self) -> None:
        first = _action_token("x" * 32, "action-id")
        second = _action_token("x" * 32, "action-id")
        self.assertEqual(first, second)
        self.assertGreaterEqual(len(first), 40)

    def test_preformatted_choices_are_deterministic(self) -> None:
        self.assertEqual(_preformatted_choice("A"), ("A", ""))
        self.assertEqual(_preformatted_choice("B."), ("B", ""))
        self.assertEqual(_preformatted_choice("C"), ("C_TEXT", ""))
        self.assertEqual(_preformatted_choice("Réponse A"), ("A", ""))
        self.assertEqual(
            _preformatted_choice("libère l’email, il est légitime\n\nréponse A"),
            ("A", "libère l’email, il est légitime"),
        )
        self.assertEqual(
            _preformatted_choice("C : Collegue est mon fils"),
            ("C_TEXT", "Collegue est mon fils"),
        )
        own_reply = (
            "Bonjour MAIA,\n\n"
            "Merci pour ton avis. C'est du spam : ne le livre pas et bloque les "
            "prochains.\n\nMerci !"
        )
        self.assertEqual(_preformatted_choice(own_reply), ("B", own_reply))
        result, gate = _choice_interpretation("A")
        self.assertEqual(result["requested_action"], "release_original")
        self.assertEqual(gate["status"], "allow_binding_choice")
        self.assertEqual(_choice_list_action("A"), "allow")
        self.assertEqual(_choice_list_action("B"), "hold")
        self.assertIsNone(_choice_list_action("C_TEXT"))

    def test_preformatted_choices_never_depend_on_a_provider(self) -> None:
        for choice in ("A", "B"):
            result, gate = _choice_interpretation(choice)
            self.assertEqual(
                result["api_metadata"],
                {"provider": "deterministic", "model": "smtp-choice-v1", "usage": {}},
            )
            self.assertEqual(gate["conflicts"], [])
            self.assertEqual(result["confidence"], 1.0)
            self.assertIsNone(result["feedback_reason_code"])

    def test_choice_b_records_feedback_without_delivery_action(self) -> None:
        result, gate = _choice_interpretation("B")
        self.assertEqual(result["classification"], "spam")
        self.assertEqual(result["requested_action"], "record_feedback")
        self.assertIsNone(gate["explicit_action"])

    def test_le_plan_local_rejette_un_spam_retenu(self) -> None:
        result, gate = _choice_interpretation("B")
        plan = _decision_plan(
            result,
            gate,
            {
                "original_message_id": "message-id",
                "delivery_status": "held",
                "case_id": "case-id",
            },
        )
        self.assertEqual(plan.feedback_classification, "spam")
        self.assertTrue(plan.reject_current)
        self.assertFalse(plan.release_requested)

    def test_action_reply_does_not_claim_an_acknowledgement_or_learning(self) -> None:
        result, _ = _choice_interpretation("A")
        reply = _reply_text(result, "Un email", "L’original vient d’être livré.")
        self.assertNotIn("Bien reçu", reply)
        self.assertNotIn("apprentissage humain", reply)

    def test_choice_c_is_not_a_deterministic_action(self) -> None:
        with self.assertRaises(ValueError):
            _choice_interpretation("C")

    def test_choice_c_text_allows_high_confidence_llm_release(self) -> None:
        result = {
            "domain_scope": "mail",
            "intent": "release_original",
            "classification": "legitimate",
            "requested_action": "release_original",
            "scope": "this_message",
            "confidence": 0.94,
            "explanation": "L'utilisateur indique qu'il connaît ce message.",
            "clarification_question": None,
            "reasons": [],
            "raw_response": {},
        }
        gate = _apply_freeform_choice_guard(result)
        self.assertEqual(gate["status"], "allow_binding_freeform_choice")
        self.assertEqual(gate["explicit_action"], "release_original")
        self.assertEqual(gate["explicit_classification"], "legitimate")

    def test_choice_c_text_asks_when_llm_is_not_confident(self) -> None:
        result = {
            "domain_scope": "mail",
            "classification": "legitimate",
            "requested_action": "release_original",
            "scope": "this_message",
            "confidence": 0.62,
            "clarification_question": None,
            "reasons": [],
            "raw_response": {},
        }
        gate = _apply_freeform_choice_guard(result)
        self.assertEqual(gate["status"], "blocked_freeform_choice")
        self.assertEqual(result["requested_action"], "none")
        self.assertIsNotNone(result["clarification_question"])

    def test_a_question_survives_the_choice_guard_even_when_unsure(self) -> None:
        # Répondre à une question n'engage rien : la garde de confiance, faite
        # pour les actions, ne doit pas transformer une question en silence.
        result = {
            "domain_scope": "mail",
            "classification": None,
            "requested_action": "answer_question",
            "scope": "unknown",
            "confidence": 0.4,
            "clarification_question": None,
            "reasons": [],
            "raw_response": {},
        }
        gate = _apply_freeform_choice_guard(result)
        self.assertEqual(gate["status"], "allow_binding_freeform_choice")
        self.assertEqual(result["requested_action"], "answer_question")
        self.assertIsNone(gate["explicit_action"])

    def test_choice_c_can_route_explicit_rule_management_to_local_validation(self) -> None:
        result = {
            "domain_scope": "mail",
            "requested_action": "set_sender_rule",
            "classification": None,
            "scope": "sender",
            "confidence": 0.96,
            "reasons": [],
            "raw_response": {},
        }
        gate = _apply_freeform_choice_guard(result)
        self.assertEqual(gate["status"], "allow_binding_freeform_choice")
        self.assertEqual(result["requested_action"], "set_sender_rule")

    def test_policy_blocks_action_not_explicitly_requested(self) -> None:
        result = {
            "classification": "legitimate",
            "requested_action": "release_original",
            "confidence": 0.92,
            "reasons": [],
            "raw_response": {"requested_action": "release_original"},
        }
        gate = apply_directive_gate("Je connais cet expéditeur.", result)
        self.assertEqual(gate["status"], "blocked_conflict")
        self.assertEqual(result["requested_action"], "none")
        self.assertIsNone(result["classification"])

    def test_policy_blocks_llm_contradiction(self) -> None:
        gate = evaluate_directive(
            "Ne le livre pas, c'est dangereux.",
            {"requested_action": "release_original", "classification": "legitimate"},
        )
        self.assertEqual(gate["status"], "blocked_conflict")
        self.assertIn("action_contradicts_user_text", gate["conflicts"])
        self.assertIn("classification_contradicts_user_text", gate["conflicts"])

    def test_policy_allows_matching_explicit_action(self) -> None:
        gate = evaluate_directive(
            "Tu peux me le livrer, c'est légitime.",
            {"requested_action": "release_original", "classification": "legitimate"},
        )
        self.assertEqual(gate["status"], "allow_non_binding")

    def test_policy_understands_natural_french_release_instruction(self) -> None:
        result = {
            "intent": "release_original",
            "requested_action": "release_original",
            "classification": "legitimate",
            "confidence": 0.95,
            "reasons": [],
            "raw_response": {},
        }
        gate = apply_directive_gate(
            "va y envoie, Collegue est mon fils",
            result,
        )
        self.assertEqual(gate["status"], "allow_non_binding")
        self.assertEqual(gate["explicit_action"], "release_original")
        self.assertEqual(result["requested_action"], "release_original")

    def test_explicit_release_recovers_a_llm_omission(self) -> None:
        result = {
            "intent": "unknown",
            "requested_action": "none",
            "classification": None,
            "confidence": 0.49,
            "clarification_question": "Peux-tu préciser ?",
            "reasons": [],
            "raw_response": {},
        }
        gate = apply_directive_gate(
            "libère l’email, il est légitime",
            result,
        )
        self.assertEqual(gate["status"], "allow_explicit_user_override")
        self.assertEqual(result["requested_action"], "release_original")
        self.assertEqual(result["classification"], "legitimate")
        self.assertIsNone(result["clarification_question"])

    def test_negated_release_still_has_priority(self) -> None:
        gate = evaluate_directive(
            "Ne libère pas ce message.",
            {"requested_action": "release_original", "classification": "suspect"},
        )
        self.assertEqual(gate["status"], "blocked_conflict")
        self.assertEqual(gate["explicit_action"], "suppress_future")

    def test_policy_does_not_release_when_natural_instruction_is_negated(self) -> None:
        gate = evaluate_directive(
            "N'envoie pas ce message.",
            {"requested_action": "release_original", "classification": "suspect"},
        )
        self.assertEqual(gate["status"], "blocked_conflict")
        self.assertEqual(gate["explicit_action"], "suppress_future")

    def test_identity_denial_is_explicit_dangerous_feedback(self) -> None:
        gate = evaluate_directive(
            "Ce n’est pas moi.",
            {"requested_action": "record_feedback", "classification": "dangerous"},
        )
        self.assertEqual(gate["explicit_classification"], "dangerous")
        self.assertEqual(gate["status"], "allow_non_binding")


class ObservedSenderPolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_choice_can_block_an_overlong_observed_sender(self) -> None:
        sender = f"{'x' * 154}@sender.example"
        connection = AsyncMock()

        await set_sender_list_policy(
            connection,
            "user@example.org",
            sender,
            "hold",
            source="authenticated_smtp_choice_b",
            observed_sender=True,
        )

        self.assertEqual(connection.execute.await_count, 2)
        stored = connection.execute.await_args_list[1].args
        self.assertEqual(stored[2], sender)
        self.assertEqual(stored[3], "hold")

    async def test_manual_lists_keep_the_smtp_length_limit(self) -> None:
        sender = f"{'x' * 154}@sender.example"
        connection = AsyncMock()

        with self.assertRaises(RuleImportError):
            await set_sender_list_policy(
                connection,
                "user@example.org",
                sender,
                "hold",
                source="authenticated_smtp_directive",
            )

        connection.execute.assert_not_awaited()


class ChoiceLlmTests(unittest.IsolatedAsyncioTestCase):
    async def test_le_corps_prerempli_c_appelle_le_llm(self) -> None:
        pool = AsyncMock()
        result = {
            "domain_scope": "mail",
            "intent": "clarification",
            "classification": None,
            "requested_action": "none",
            "scope": "unknown",
            "confidence": 0.9,
            "explanation": "La demande ne précise encore aucune action.",
            "clarification_question": "Que veux-tu que je fasse de ce message ?",
            "reasons": [],
            "raw_response": {},
            "api_metadata": {"provider": "test", "model": "test", "usage": {}},
        }
        message = {
            "id": 1,
            "conversation_id": "conversation-id",
            "user_text": response_body(None),
        }
        context = {
            "participant_email": "user@example.org",
            "original_message_id": "message-id",
        }
        with (
            patch(
                "sentimail_v3.conversation.assistant._reserve_llm_call",
                new=AsyncMock(return_value=(7, None)),
            ),
            patch(
                "sentimail_v3.conversation.assistant._interpret",
                new=AsyncMock(return_value=result),
            ) as interpret,
        ):
            outcome = await _interpret_inbound_directive(
                pool,
                AsyncMock(),
                SimpleNamespace(),  # type: ignore[arg-type]
                message,  # type: ignore[arg-type]
                context,
            )

        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.choice, "C_TEXT")
        self.assertEqual(outcome.llm_event_id, 7)
        interpret.assert_awaited_once()

    async def test_c_ne_prend_pas_le_raccourci_d_un_reglage_local(self) -> None:
        pool = AsyncMock()
        result = {
            "domain_scope": "mail",
            "intent": "clarification",
            "classification": None,
            "requested_action": "none",
            "scope": "unknown",
            "confidence": 0.9,
            "explanation": "La demande doit être interprétée dans le dossier.",
            "clarification_question": "Que veux-tu que je fasse de ce message ?",
            "reasons": [],
            "raw_response": {},
            "api_metadata": {"provider": "test", "model": "test", "usage": {}},
        }
        user_text = response_body(None).replace(
            "Tapez ici vos demandes ou remarques",
            "Désactive l'accusé de réception.",
        )
        message = {
            "id": 1,
            "conversation_id": "conversation-id",
            "user_text": user_text,
        }
        context = {
            "participant_email": "user@example.org",
            "original_message_id": "message-id",
        }
        with (
            patch(
                "sentimail_v3.conversation.assistant._reserve_llm_call",
                new=AsyncMock(return_value=(8, None)),
            ),
            patch(
                "sentimail_v3.conversation.assistant._interpret",
                new=AsyncMock(return_value=result),
            ) as interpret,
            patch(
                "sentimail_v3.conversation.assistant._apply_receipt_toggle",
                new=AsyncMock(),
            ) as local_toggle,
        ):
            outcome = await _interpret_inbound_directive(
                pool,
                AsyncMock(),
                SimpleNamespace(),  # type: ignore[arg-type]
                message,  # type: ignore[arg-type]
                context,
            )

        self.assertIsNotNone(outcome)
        interpret.assert_awaited_once()
        local_toggle.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
