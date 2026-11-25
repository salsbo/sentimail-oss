"""Ce qu'une réponse à MAIA décide, et ce qu'elle doit confirmer.

Une lettre ou un bouton sont des décisions écrites. Une phrase, une
explication après C ou un texte compris par le modèle sont des décisions
dérivées : sur un message dangereux, ou porteur d'une preuve matérielle, elles
ne livrent rien et ne posent aucune confiance sans un « A » explicite.
"""

from __future__ import annotations

import json
import unittest
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

from sentimail_v3.conversation import assistant
from sentimail_v3.conversation.assistant import (
    CONFIRM_PURPOSE,
    _apply_freeform_choice_guard,
    _ask_trust_confirmation,
    _choice_interpretation,
    _choice_list_action,
    _decision_plan,
    _interpret_inbound_directive,
    _phrase_choice,
    _preformatted_choice,
    _trust_check,
    _trust_confirmation_reason,
    _trust_guard_applies,
)
from sentimail_v3.conversation.choice_registry import (
    CHOICE_PRESENTATIONS,
    SIGNATURE_LIMIT,
    fold_lone_accented_a,
    prefilled_reply,
    response_body,
)
from sentimail_v3.conversation.directive_policy import (
    CHOICE_CONTEXT_LIMIT,
    apply_directive_gate,
    explicit_directive,
    short_enough,
)
from sentimail_v3.conversation.human_decision import (
    HumanDecision,
    apply_human_decision,
)

ORIGINAL = "44444444-4444-4444-4444-444444444444"
# Un texte long qui ne dit rien : ni lettre, ni verbe de consigne.
NEUTRE = ("Je regarde ça ce soir avec mon collègue du service comptable. " * 10)[:500]
# L'avis de M-d8df0e tel qu'il se lisait, aplati sur une ligne, sans les noms.
AVIS_APLATI = (
    "À Sent from my iPhone On 27 Sep 2026, at 18:02, MAIA <maia@example.org> "
    "wrote: Reçu le 27/09/2026 à 18:01 Message suspect 2 écarts relevés "
    "N'utilise aucun lien du message. Passe par le site ou l'application que "
    "tu utilises d'habitude. Informations du message Expéditeur "
    "offres@boutique.example.org Nom affiché Enseigne Sujet Une friteuse à "
    "gagner Adresse d’enveloppe différente de l’adresse affichée. Que veux-tu "
    "faire ? A - Livre-le, cet expéditeur est fiable B - Non merci C’est "
    "indésirable, bloque cet expéditeur C - Autre chose J’explique à MAIA "
    "En cas de doute, vérifie toujours par un autre canal. Si les boutons ne "
    "fonctionnent pas, réponds simplement A, B ou C à ce message."
)
SIGNATURES = (
    "Sent from my iPhone",
    "Envoyé de mon iPhone",
    "Sent from Outlook for iOS",
    "Envoyé à partir d'Outlook pour Mac",
)


def _corps(lettre: str) -> list[str]:
    return [
        response_body(choice.phrase)
        for presentations in CHOICE_PRESENTATIONS.values()
        for choice in presentations
        if choice.letter == lettre and choice.phrase is not None
    ]


def _plan(choice: str, delivery_status: str = "held"):
    result, gate = _choice_interpretation(choice)
    context = {"original_message_id": ORIGINAL, "delivery_status": delivery_status}
    return _decision_plan(result, gate, context)


def _llm_release(**extra: object) -> dict[str, object]:
    return {
        "domain_scope": "mail",
        "intent": "release_original",
        "classification": "legitimate",
        "requested_action": "release_original",
        "scope": "this_message",
        "confidence": 0.95,
        "explanation": "Tu connais cet expéditeur, je comprends qu'il faut livrer.",
        "clarification_question": None,
        "reasons": ["user_knows_sender"],
        "raw_response": {"llm": "brut"},
        "api_metadata": {"provider": "test", "model": "test", "usage": {}},
        **extra,
    }


class LettreAccentueeTests(unittest.TestCase):
    def test_a_accentue_seul_vaut_a(self) -> None:
        for texte in ("À", "à", "Á", "Â", "À.", "À\nEnvoyé de mon iPhone"):
            with self.subTest(texte=texte):
                self.assertEqual(_preformatted_choice(texte)[0], "A")
        self.assertEqual(fold_lone_accented_a("  à!  \nsuite"), "  A!  \nsuite")

    def test_a_accentue_dans_une_phrase_ne_decide_pas(self) -> None:
        for texte in ("À demain", "À toi de voir"):
            with self.subTest(texte=texte):
                self.assertIsNone(_preformatted_choice(texte)[0])
                self.assertIsNone(_phrase_choice(texte))
                self.assertEqual(fold_lone_accented_a(texte), texte)


class LongueurTests(unittest.TestCase):
    def test_la_limite_se_compte_blancs_reduits(self) -> None:
        self.assertEqual(CHOICE_CONTEXT_LIMIT, 400)
        self.assertTrue(short_enough("mot " * 80 + "\n\n\n" + " " * 300))
        self.assertFalse(short_enough("x" * 401))

    def test_lettre_noyee_ne_decide_nulle_part(self) -> None:
        texte = "A\n" + NEUTRE
        self.assertIsNone(_preformatted_choice(texte)[0])
        self.assertIsNone(_phrase_choice(texte))
        self.assertEqual(explicit_directive(texte), (None, None))

    def test_lettre_courte_decide_encore(self) -> None:
        self.assertEqual(explicit_directive("A\nmerci"), ("release_original", "legitimate"))

    def test_une_lettre_noyee_ne_force_plus_l_action_du_modele(self) -> None:
        # Le texte libre confié au modèle passe par la même lecture : une
        # lettre noyée n'y impose plus d'action.
        result = {
            "requested_action": "none",
            "classification": None,
            "confidence": 0.7,
            "reasons": [],
            "raw_response": {},
        }
        gate = apply_directive_gate("A\n" + NEUTRE, result)
        self.assertIsNone(gate["explicit_action"])
        self.assertEqual(result["requested_action"], "none")

    def test_avis_cite_sur_une_ligne_ne_decide_pas(self) -> None:
        self.assertGreater(len(AVIS_APLATI), CHOICE_CONTEXT_LIMIT)
        self.assertIn("A - Livre-le, cet expéditeur est fiable", AVIS_APLATI)
        self.assertIsNone(_preformatted_choice(AVIS_APLATI)[0])
        self.assertIsNone(_phrase_choice(AVIS_APLATI))

    def test_phrase_longue_ne_decide_pas_sans_modele(self) -> None:
        texte = "Livre-le, cet expéditeur est fiable. " + NEUTRE
        self.assertIsNone(_preformatted_choice(texte)[0])
        self.assertIsNone(_phrase_choice(texte))

    def test_phrase_courte_decide_encore(self) -> None:
        self.assertEqual(_phrase_choice("Livre-le, cet expéditeur est fiable"), "A")
        self.assertEqual(
            _phrase_choice("C'est du spam : ne le livre pas et bloque les prochains."),
            "B",
        )
        # La phrase n'est plus lue par la voie des lettres : elle y reste
        # sans décision, et c'est l'interprétation qui la reprend.
        self.assertIsNone(_preformatted_choice("Livre-le, cet expéditeur est fiable")[0])


class BoutonSigneTests(unittest.TestCase):
    def test_bouton_signe_reste_litteral(self) -> None:
        for lettre in ("A", "B"):
            for corps in _corps(lettre):
                for signature in SIGNATURES:
                    texte = corps.strip() + "\n\n" + signature
                    with self.subTest(lettre=lettre, corps=corps[:40], signature=signature):
                        self.assertEqual(_preformatted_choice(texte), (lettre, texte))
                        self.assertEqual(prefilled_reply(texte), (lettre, signature))

    def test_bouton_exact_rend_une_queue_vide(self) -> None:
        for lettre in ("A", "B"):
            for corps in _corps(lettre):
                with self.subTest(lettre=lettre, corps=corps[:40]):
                    self.assertEqual(prefilled_reply(corps), (lettre, ""))

    def test_bouton_aux_lignes_resserrees_reste_litteral(self) -> None:
        for lettre in ("A", "B"):
            for corps in _corps(lettre):
                serre = "\n".join(line for line in corps.splitlines() if line.strip())
                with self.subTest(lettre=lettre, corps=corps[:40]):
                    self.assertEqual(_preformatted_choice(serre)[0], lettre)

    def test_bouton_suivi_d_une_consigne_n_est_plus_le_bouton(self) -> None:
        texte = _corps("A")[0].strip() + "\nmais ne le livre pas"
        self.assertIsNone(prefilled_reply(texte)[0])
        self.assertIsNone(_preformatted_choice(texte)[0])
        self.assertIsNone(_phrase_choice(texte))

    def test_signature_trop_longue_n_est_plus_une_signature(self) -> None:
        signature = "s" * (SIGNATURE_LIMIT + 1)
        self.assertEqual(len(signature), 81)
        texte = _corps("A")[0].strip() + "\n" + signature
        self.assertIsNone(prefilled_reply(texte)[0])
        self.assertIsNone(_preformatted_choice(texte)[0])
        texte = _corps("A")[0].strip() + "\n" + "s" * SIGNATURE_LIMIT
        self.assertEqual(_preformatted_choice(texte)[0], "A")


class GardeDeConfianceTests(unittest.TestCase):
    def test_lettre_litterale_sur_message_retenu_passe(self) -> None:
        plan = _plan("A")
        self.assertTrue(plan.release_requested)
        self.assertFalse(
            _trust_guard_applies(plan, "A", derived=False, held=True, confirmed=False)
        )

    def test_phrase_sur_message_retenu_est_redemandee(self) -> None:
        self.assertTrue(
            _trust_guard_applies(_plan("A"), "A", derived=True, held=True, confirmed=False)
        )

    def test_voie_c_liberation_est_redemandee(self) -> None:
        result = _llm_release()
        gate = _apply_freeform_choice_guard(result)
        self.assertEqual(gate["status"], "allow_binding_freeform_choice")
        plan = _decision_plan(
            result, gate, {"original_message_id": ORIGINAL, "delivery_status": "held"}
        )
        self.assertTrue(plan.release_requested)
        self.assertTrue(
            _trust_guard_applies(plan, "C_TEXT", derived=True, held=True, confirmed=False)
        )

    def test_texte_libre_llm_liberation_est_redemandee(self) -> None:
        result = _llm_release()
        gate = apply_directive_gate("tu peux me le livrer", result)
        plan = _decision_plan(
            result, gate, {"original_message_id": ORIGINAL, "delivery_status": "held"}
        )
        self.assertTrue(plan.release_requested)
        self.assertTrue(
            _trust_guard_applies(plan, None, derived=True, held=True, confirmed=False)
        )

    def test_a_litteral_sur_avis_indesirable_est_redemande(self) -> None:
        plan = _plan("A", "delivered")
        self.assertFalse(plan.release_requested)
        self.assertTrue(
            _trust_guard_applies(plan, "A", derived=False, held=False, confirmed=False)
        )

    def test_a_litteral_repondu_a_la_question_confirme(self) -> None:
        self.assertFalse(
            _trust_guard_applies(
                _plan("A", "delivered"), "A", derived=False, held=False, confirmed=True
            )
        )

    def test_phrase_repondue_a_la_question_ne_confirme_pas(self) -> None:
        self.assertTrue(
            _trust_guard_applies(
                _plan("A", "delivered"), "A", derived=True, held=False, confirmed=True
            )
        )

    def test_b_n_est_jamais_redemande(self) -> None:
        for status in ("held", "delivered"):
            for derived in (True, False):
                with self.subTest(status=status, derived=derived):
                    self.assertFalse(
                        _trust_guard_applies(
                            _plan("B", status),
                            "B",
                            derived=derived,
                            held=status == "held",
                            confirmed=False,
                        )
                    )

    def test_redemande_n_ecrit_ni_label_ni_liste(self) -> None:
        result, gate = _choice_interpretation("A")
        result, gate = _ask_trust_confirmation(result, gate, "dangerous", held=True)
        plan = _decision_plan(
            result, gate, {"original_message_id": ORIGINAL, "delivery_status": "held"}
        )
        self.assertFalse(plan.release_requested)
        self.assertIsNone(plan.persistent_action)
        self.assertIsNone(plan.feedback_classification)
        self.assertFalse(plan.binding_feedback)
        self.assertFalse(plan.reject_current)
        self.assertIsNone(_choice_list_action(None))
        self.assertEqual(gate["status"], "blocked_needs_literal_confirmation")
        self.assertIn("trust_requires_confirmation_dangerous", gate["conflicts"])

    def test_redemande_conserve_intent_scope_et_explanation(self) -> None:
        for entree in (_choice_interpretation("A")[0], _llm_release()):
            with self.subTest(provider=entree["api_metadata"]["provider"]):
                gate = {"status": "allow_binding_choice", "conflicts": []}
                sortie, _ = _ask_trust_confirmation(
                    dict(entree), gate, "material_danger", held=False
                )
                for cle in ("intent", "scope", "explanation", "api_metadata"):
                    self.assertEqual(sortie[cle], entree[cle])
                self.assertEqual(sortie["requested_action"], "none")
                self.assertIsNone(sortie["classification"])
                self.assertLessEqual(sortie["confidence"], 0.49)
                self.assertIn("trust_confirmation_material_danger", sortie["reasons"])
                self.assertEqual(sortie["raw_response"]["previous"], entree["raw_response"])

    def test_la_question_nomme_la_preuve_ou_le_classement(self) -> None:
        result, gate = _choice_interpretation("A")
        retenu, _ = _ask_trust_confirmation(result, gate, "material_danger", held=True)
        livre, _ = _ask_trust_confirmation(result, gate, "dangerous", held=False)
        self.assertIn("preuve matérielle", retenu["clarification_question"])
        self.assertIn("pas livré", retenu["clarification_question"])
        self.assertIn("classe dangereux", livre["clarification_question"])
        self.assertIn("fiable", livre["clarification_question"])
        for question in (retenu["clarification_question"], livre["clarification_question"]):
            self.assertIn("« A »", question)
            self.assertNotIn("—", question)
        # L'entrée n'est jamais modifiée en place.
        self.assertEqual(result["requested_action"], "release_original")


class MotifTests(unittest.IsolatedAsyncioTestCase):
    async def test_motif_de_confirmation(self) -> None:
        pool = AsyncMock()
        pool.fetchval.return_value = True
        self.assertEqual(
            await _trust_confirmation_reason(pool, ORIGINAL, "dangerous"), "material_danger"
        )
        pool.fetchval.return_value = False
        self.assertEqual(
            await _trust_confirmation_reason(pool, ORIGINAL, "dangerous"), "dangerous"
        )
        for assessed in ("suspect", "spam", "undetermined", None):
            with self.subTest(assessed=assessed):
                self.assertIsNone(
                    await _trust_confirmation_reason(pool, ORIGINAL, assessed)
                )

    async def test_absence_de_dossier_ne_declenche_pas_la_garde(self) -> None:
        for original in (None, ""):
            with self.subTest(original=original):
                pool = AsyncMock()
                motif, confirmed = await _trust_check(
                    pool,
                    "reply-id",
                    {"original_message_id": original, "delivery_status": None},
                    _plan("A", "delivered"),
                    "A",
                    derived=False,
                )
                self.assertEqual((motif, confirmed), (None, False))
                pool.fetchval.assert_not_awaited()

    async def test_la_confirmation_n_est_cherchee_que_pour_un_a_ecrit(self) -> None:
        pool = AsyncMock()
        pool.fetchval.return_value = True
        context = {
            "original_message_id": ORIGINAL,
            "delivery_status": "delivered",
            "assessed_classification": "dangerous",
        }
        motif, confirmed = await _trust_check(
            pool, "reply-id", context, _plan("A", "delivered"), "A", derived=False
        )
        self.assertEqual((motif, confirmed), (None, True))
        sql, *args = pool.fetchval.await_args_list[0].args
        self.assertIn("confirm_original_message_id", sql)
        self.assertEqual(args, ["reply-id", CONFIRM_PURPOSE, ORIGINAL])

        pool = AsyncMock()
        pool.fetchval.return_value = False
        motif, confirmed = await _trust_check(
            pool, "reply-id", context, _plan("A", "delivered"), "A", derived=True
        )
        self.assertEqual((motif, confirmed), ("dangerous", False))
        self.assertNotIn(
            "confirm_original_message_id", pool.fetchval.await_args_list[0].args[0]
        )


class DecisionHumaineTests(unittest.IsolatedAsyncioTestCase):
    async def test_apply_human_decision_n_ecrit_rien_avec_classification_et_liste_none(
        self,
    ) -> None:
        connection = AsyncMock()
        with (
            patch(
                "sentimail_v3.conversation.human_decision.set_sender_list_policy",
                new=AsyncMock(),
            ) as liste,
            patch(
                "sentimail_v3.conversation.human_decision.block_proven_sender",
                new=AsyncMock(),
            ) as blocage,
            patch(
                "sentimail_v3.conversation.human_decision.store_ground_truth_sample",
                new=AsyncMock(),
            ) as verite,
        ):
            signals = await apply_human_decision(
                connection,
                HumanDecision(
                    message_id=ORIGINAL,
                    participant_email="personne@example.org",
                    sender="offres@boutique.example.org",
                    subject="Une friteuse à gagner",
                    classification=None,
                    list_action=None,
                    policy_source="authenticated_smtp_choice_none",
                    case_id="case-id",
                ),
            )
        self.assertEqual(signals, [])
        connection.execute.assert_not_awaited()
        liste.assert_not_awaited()
        blocage.assert_not_awaited()
        verite.assert_not_awaited()


class InterpretationTests(unittest.IsolatedAsyncioTestCase):
    async def _interpreter(self, texte: str, llm: dict[str, object] | None = None):
        message = {"id": 1, "conversation_id": "conversation-id", "user_text": texte}
        context = {
            "participant_email": "personne@example.org",
            "original_message_id": ORIGINAL,
        }
        with (
            patch.object(
                assistant, "_reserve_llm_call", new=AsyncMock(return_value=(9, None))
            ),
            patch.object(
                assistant, "_interpret", new=AsyncMock(return_value=llm or _llm_release())
            ) as interpret,
        ):
            outcome = await _interpret_inbound_directive(
                AsyncMock(),
                AsyncMock(),
                SimpleNamespace(),  # type: ignore[arg-type]
                message,  # type: ignore[arg-type]
                context,
            )
        return outcome, interpret

    async def test_interpretation_marque_les_decisions_derivees(self) -> None:
        lettre, modele = await self._interpreter("A")
        self.assertEqual((lettre.choice, lettre.derived), ("A", False))
        modele.assert_not_awaited()

        phrase, modele = await self._interpreter("Livre-le, cet expéditeur est fiable")
        self.assertEqual((phrase.choice, phrase.derived), ("A", True))
        self.assertEqual(phrase.policy_gate["origin"], "phrase")
        self.assertIn("phrase_choice_without_letter", phrase.result["reasons"])
        modele.assert_not_awaited()

        c, modele = await self._interpreter("C : je le connais, livre-le")
        self.assertEqual((c.choice, c.derived), ("C_TEXT", True))
        modele.assert_awaited_once()

        libre, modele = await self._interpreter("Je crois que tu peux me le livrer")
        self.assertIsNone(libre.choice)
        self.assertTrue(libre.derived)
        modele.assert_awaited_once()

    async def test_un_bouton_signe_garde_la_trace_de_sa_signature(self) -> None:
        texte = _corps("A")[0].strip() + "\n\nSent from my iPhone"
        outcome, modele = await self._interpreter(texte)
        self.assertEqual((outcome.choice, outcome.derived), ("A", False))
        self.assertIn("prefilled_reply_with_trailer", outcome.result["reasons"])
        modele.assert_not_awaited()


# Le chemin complet d'une réponse individuelle, sur une base simulée.


class _Connexion:
    def __init__(self, journal: list[tuple[str, tuple[Any, ...]]]) -> None:
        self.journal = journal

    def transaction(self) -> "_Async":
        return _Async(None)

    async def execute(self, sql: str, *args: Any) -> None:
        self.journal.append((sql, args))

    async def fetch(self, sql: str, *args: Any) -> list[Any]:
        return []

    async def fetchval(self, sql: str, *args: Any) -> Any:
        return None

    async def fetchrow(self, sql: str, *args: Any) -> Any:
        return None


class _Async:
    def __init__(self, value: Any) -> None:
        self._value = value

    async def __aenter__(self) -> Any:
        return self._value

    async def __aexit__(self, *_: Any) -> bool:
        return False


class _Base:
    def __init__(self, *, materiel: bool = False, confirme: bool = False) -> None:
        self.materiel = materiel
        self.confirme = confirme
        self.journal: list[tuple[str, tuple[Any, ...]]] = []

    async def fetchval(self, sql: str, *args: Any) -> Any:
        if "delivery_barrier" in sql:
            return self.materiel
        if "confirm_original_message_id" in sql:
            return self.confirme
        return None

    async def execute(self, sql: str, *args: Any) -> None:
        self.journal.append((sql, args))

    def acquire(self) -> _Async:
        return _Async(_Connexion(self.journal))

    def audits(self) -> dict[str, dict[str, Any]]:
        found: dict[str, dict[str, Any]] = {}
        for sql, args in self.journal:
            if "INSERT INTO audit_log" in sql and args and "directive.trust" in str(args[0]):
                found[str(args[0])] = json.loads(args[1])
        return found


class CheminCompletTests(unittest.IsolatedAsyncioTestCase):
    async def _traiter(
        self,
        texte: str,
        *,
        delivery_status: str,
        assessed: str | None,
        base: _Base,
    ) -> tuple[AsyncMock, AsyncMock, list[dict[str, Any]], AsyncMock]:
        message = {
            "id": 7,
            "conversation_id": "22222222-2222-2222-2222-222222222222",
            "message_id": "55555555-5555-5555-5555-555555555555",
            "subject": "Re: Ton avis",
            "user_text": texte,
        }
        context = {
            "case_id": "33333333-3333-3333-3333-333333333333",
            "participant_email": "personne@example.org",
            "original_message_id": ORIGINAL,
            "subject": "Une friteuse à gagner",
            "from_header": "Enseigne <offres@boutique.example.org>",
            "envelope_from": "rebond@boutique.example.org",
            "delivery_status": delivery_status,
            "assessed_classification": assessed,
            "clues": [],
        }
        envois: list[dict[str, Any]] = []

        async def _queue(connection, *args, **kwargs):
            envois.append({"args": args, **kwargs})

        identite = SimpleNamespace(
            assistant_sender="MAIA <maia@example.org>",
            action_address="maia@action.example.org",
        )
        with (
            patch.object(assistant, "_claim_inbound", new=AsyncMock(return_value=message)),
            patch.object(assistant, "instance_identity", new=AsyncMock(return_value=identite)),
            patch.object(assistant, "mapping_for_reply", new=AsyncMock(return_value=({}, ""))),
            patch.object(assistant, "_context", new=AsyncMock(return_value=context)),
            patch.object(assistant, "get_receipt_enabled", new=AsyncMock(return_value=False)),
            patch.object(assistant, "release_original", new=AsyncMock(return_value="released")) as livraison,
            patch.object(assistant, "queue_response", _queue),
            patch.object(assistant, "_interpret", new=AsyncMock(return_value=_llm_release())),
            patch.object(assistant, "_reserve_llm_call", new=AsyncMock(return_value=(3, None))),
            patch(
                "sentimail_v3.conversation.human_decision.set_sender_list_policy",
                new=AsyncMock(),
            ) as liste,
            patch(
                "sentimail_v3.conversation.human_decision.store_ground_truth_sample",
                new=AsyncMock(),
            ) as verite,
        ):
            await assistant._process_inbound(
                base, AsyncMock(), SimpleNamespace(deepseek_assistant_model="test")
            )
        erreurs = [
            args for sql, args in base.journal if "processing_status='error'" in sql
        ]
        self.assertEqual(erreurs, [])
        return livraison, liste, envois, verite

    def _labels(self, base: _Base) -> list[tuple[str, tuple[Any, ...]]]:
        return [entry for entry in base.journal if "INSERT INTO labels" in entry[0]]

    async def test_une_phrase_sur_un_message_dangereux_retenu_est_redemandee(self) -> None:
        base = _Base()
        livraison, liste, envois, verite = await self._traiter(
            "Livre-le, cet expéditeur est fiable",
            delivery_status="held",
            assessed="dangerous",
            base=base,
        )
        livraison.assert_not_awaited()
        liste.assert_not_awaited()
        verite.assert_not_awaited()
        self.assertEqual(self._labels(base), [])
        self.assertEqual(len(envois), 1)
        self.assertEqual(envois[0]["purpose"], CONFIRM_PURPOSE)
        self.assertEqual(
            envois[0]["context_extra"],
            {"confirm_original_message_id": ORIGINAL, "motif": "dangerous"},
        )
        corps = envois[0]["args"][6]
        self.assertIn("classe dangereux", corps)
        self.assertIn("rien n’a été livré", corps)
        audit = base.audits()["directive.trust_confirmation_requested"]
        self.assertEqual(
            (audit["message_id"], audit["motif"], audit["path"], audit["surface"]),
            (ORIGINAL, "dangerous", "phrase", "held"),
        )

    async def test_la_voie_c_sur_une_preuve_materielle_est_redemandee(self) -> None:
        base = _Base(materiel=True)
        livraison, _, envois, _ = await self._traiter(
            "C : je le connais, livre-le",
            delivery_status="held",
            assessed="suspect",
            base=base,
        )
        livraison.assert_not_awaited()
        self.assertIn("preuve matérielle", envois[0]["args"][6])
        audit = base.audits()["directive.trust_confirmation_requested"]
        self.assertEqual((audit["motif"], audit["path"]), ("material_danger", "c_text"))

    async def test_une_lettre_sur_un_message_dangereux_retenu_livre(self) -> None:
        base = _Base(materiel=True)
        livraison, _, envois, _ = await self._traiter(
            "A", delivery_status="held", assessed="dangerous", base=base
        )
        livraison.assert_awaited_once()
        self.assertEqual(envois, [])
        self.assertEqual(base.audits(), {})

    async def test_une_phrase_sur_un_message_suspect_livre_sans_question(self) -> None:
        base = _Base()
        livraison, _, _, _ = await self._traiter(
            "Livre-le, cet expéditeur est fiable",
            delivery_status="held",
            assessed="suspect",
            base=base,
        )
        livraison.assert_awaited_once()
        self.assertEqual(base.audits(), {})

    async def test_un_a_sur_un_avis_indesirable_dangereux_est_redemande(self) -> None:
        base = _Base()
        livraison, liste, envois, _ = await self._traiter(
            "A", delivery_status="delivered", assessed="dangerous", base=base
        )
        livraison.assert_not_awaited()
        liste.assert_not_awaited()
        self.assertEqual(self._labels(base), [])
        corps = envois[0]["args"][6]
        self.assertIn("Je n’ai rien changé.", corps)
        audit = base.audits()["directive.trust_confirmation_requested"]
        self.assertEqual((audit["path"], audit["surface"]), ("literal", "delivered"))

    async def test_un_a_repondu_a_la_question_pose_la_confiance(self) -> None:
        base = _Base(confirme=True)
        livraison, liste, envois, _ = await self._traiter(
            "A", delivery_status="delivered", assessed="dangerous", base=base
        )
        livraison.assert_not_awaited()
        liste.assert_awaited_once()
        self.assertEqual(liste.await_args.args[3], "allow")
        self.assertEqual(len(self._labels(base)), 1)
        self.assertEqual(envois, [])
        self.assertIn("directive.trust_confirmed", base.audits())

    async def test_un_a_sur_un_avis_indesirable_de_spam_reste_immediat(self) -> None:
        # Limite assumée : seul le cas mesuré comme risqué est redemandé.
        base = _Base()
        _, liste, envois, _ = await self._traiter(
            "A", delivery_status="delivered", assessed="spam", base=base
        )
        liste.assert_awaited_once()
        self.assertEqual(envois, [])
        self.assertEqual(base.audits(), {})


if __name__ == "__main__":
    unittest.main()
