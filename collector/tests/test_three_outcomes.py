from __future__ import annotations

import unittest

from sentimail_v3.execution.delivery import classify_header
from sentimail_v3.judgment.verdict_engine import (
    FILED_AS_JUNK,
    JudgmentContradiction,
    _judgment_execution,
    _authenticated_suppression,
    _validate_final_judgment,
)

RULES = {
    "verdict_is_final": True,
    "confidence_required": 0.90,
    "deep_execution_complete": True,
    "static_investigation_complete": True,
    "material_danger_evidence": [],
    "authenticated_sender_policy": "none",
}


def _verdict(classification: str, decision: str, confidence: float = 0.95) -> dict:
    return {
        "classification": classification,
        "delivery_decision": decision,
        "confidence": confidence,
        "verdict_doubt": classification != "legitimate",
    }


class PolitiqueTests(unittest.TestCase):
    def _valide(self, verdict: dict, **regles: object) -> None:
        _validate_final_judgment(verdict, {"judgment_rules": {**RULES, **regles}})

    def test_un_indesirable_certain_part_en_junk_sans_deranger(self) -> None:
        for classification in ("spam", "dangerous"):
            self._valide(_verdict(classification, "junk"))

    def test_le_doute_ne_se_classe_jamais_en_junk(self) -> None:
        # C'est la garantie centrale : suspect veut dire « je ne sais pas ».
        for classification in ("suspect", "undetermined"):
            with self.assertRaises(JudgmentContradiction) as leve:
                self._valide(_verdict(classification, "junk"))
            self.assertIn(
                "junk_requires_spam_or_dangerous", leve.exception.contradictions
            )

    def test_une_certitude_faible_ne_suffit_pas_a_classer(self) -> None:
        with self.assertRaises(JudgmentContradiction) as leve:
            self._valide(_verdict("spam", "junk", confidence=0.60))
        self.assertIn(
            "confidence_below_judicial_threshold", leve.exception.contradictions
        )

    def test_une_analyse_incomplete_n_autorise_pas_a_livrer(self) -> None:
        verdict = _verdict("legitimate", "deliver")
        verdict["verdict_doubt"] = False
        with self.assertRaises(JudgmentContradiction) as leve:
            self._valide(verdict, deep_execution_complete=False)
        self.assertIn("deep_execution_incomplete", leve.exception.contradictions)

    def test_un_spam_certain_se_classe_meme_sans_analyse_profonde(self) -> None:
        # Le bac à sable n'aboutit pas toujours. Redemander un avis pour chaque
        # prospection manifeste rendait la question banale ; le pire qu'un
        # classement errone puisse coûter ici reste un message récupérable.
        self._valide(_verdict("spam", "junk"), deep_execution_complete=False)

    def test_un_danger_exige_toujours_une_analyse_profonde_aboutie(self) -> None:
        # Sans indicateur de pièce jointe distinct, l'analyse profonde
        # incomplète reste bloquante pour un verdict dangereux.
        with self.assertRaises(JudgmentContradiction) as leve:
            self._valide(_verdict("dangerous", "junk"), deep_execution_complete=False)
        self.assertIn("deep_execution_incomplete", leve.exception.contradictions)

    def test_un_danger_se_classe_en_junk_si_seul_un_lien_a_echoue(self) -> None:
        # Une URL morte ou lente ne force plus une demande d'avis si les pièces
        # jointes ont été inspectées et que le juge est certain du danger.
        self._valide(
            _verdict("dangerous", "junk", confidence=0.90),
            attachment_analysis_complete=True,
            deep_execution_complete=False,
        )

    def test_un_danger_avec_piece_jointe_non_inspectee_reste_bloque(self) -> None:
        with self.assertRaises(JudgmentContradiction) as leve:
            self._valide(
                _verdict("dangerous", "junk", confidence=0.95),
                attachment_analysis_complete=False,
                deep_execution_complete=False,
            )
        self.assertIn("deep_execution_incomplete", leve.exception.contradictions)

    def test_conflit_destination_bloque_livraison_mais_autorise_junk(self) -> None:
        verdict_legitime = _verdict("legitimate", "deliver")
        verdict_legitime["verdict_doubt"] = False
        with self.assertRaises(JudgmentContradiction) as leve:
            self._valide(verdict_legitime, identity_destination_conflict=True)
        self.assertIn(
            "identity_destination_conflict_unresolved", leve.exception.contradictions
        )
        for classification in ("spam", "dangerous"):
            self._valide(
                _verdict(classification, "junk", confidence=0.90),
                identity_destination_conflict=True,
                material_danger_evidence=[],
            )

    def test_une_investigation_statique_incomplete_interdit_de_classer(self) -> None:
        # Sans même les vérifications de base, il n'y a rien sur quoi trancher.
        with self.assertRaises(JudgmentContradiction) as leve:
            self._valide(_verdict("spam", "junk"), static_investigation_complete=False)
        self.assertIn(
            "static_investigation_incomplete", leve.exception.contradictions
        )

    def test_une_consigne_de_retenue_interdit_la_boite_de_reception(self) -> None:
        # « Retiens les prochains » veut dire : ne le livre jamais en silence.
        verdict = _verdict("legitimate", "deliver")
        verdict["verdict_doubt"] = False
        with self.assertRaises(JudgmentContradiction) as leve:
            self._valide(verdict, authenticated_sender_policy="hold")
        self.assertIn("authenticated_hold_ignored", leve.exception.contradictions)

    def test_une_consigne_de_retenue_n_empeche_pas_de_classer_un_indesirable(
        self,
    ) -> None:
        # Répondre « retiens les prochains » puis recevoir la même question à
        # chaque message du même expéditeur vidait la consigne de son sens.
        for classification in ("spam", "dangerous"):
            self._valide(
                _verdict(classification, "junk"), authenticated_sender_policy="hold"
            )

    def test_une_preuve_materielle_interdit_la_boite_de_reception(self) -> None:
        verdict = _verdict("legitimate", "deliver")
        verdict["verdict_doubt"] = False
        with self.assertRaises(JudgmentContradiction) as leve:
            self._valide(verdict, material_danger_evidence=["ATT-001"])
        self.assertIn("material_danger_unresolved", leve.exception.contradictions)

    def test_un_danger_materiel_peut_en_revanche_etre_classe(self) -> None:
        # C'est tout l'intérêt du changement : un hameçonnage établi n'a pas
        # besoin d'un arbitrage humain pour finir dans les indésirables.
        self._valide(_verdict("dangerous", "junk"), material_danger_evidence=["ATT-001"])


class ExecutionTests(unittest.TestCase):
    def test_une_regle_b_produit_une_suppression_locale(self) -> None:
        verdict = _authenticated_suppression(
            {"judgment_rules": {"authenticated_sender_policy": "hold"}}
        )
        self.assertIsNotNone(verdict)
        ordre = _judgment_execution(verdict or {})
        self.assertEqual(ordre["delivery_decision"], "suppress")
        self.assertTrue(ordre["policy_suppressed"])
        self.assertFalse(ordre["original_delivery_allowed"])

    def test_sans_regle_b_le_modele_reste_decisionnaire(self) -> None:
        self.assertIsNone(
            _authenticated_suppression(
                {"judgment_rules": {"authenticated_sender_policy": "allow"}}
            )
        )

    def test_un_message_classe_est_livre_mais_marque(self) -> None:
        ordre = _judgment_execution(
            {"delivery_decision": "junk", "classification": "spam", "confidence": 0.95}
        )
        self.assertTrue(ordre["original_delivery_allowed"])
        self.assertEqual(ordre["filed_as_junk"], "spam")

    def test_un_message_dangereux_est_marque_comme_tel(self) -> None:
        ordre = _judgment_execution(
            {"delivery_decision": "junk", "classification": "dangerous", "confidence": 0.99}
        )
        self.assertEqual(ordre["filed_as_junk"], "malicious")

    def test_une_livraison_ordinaire_ne_porte_aucune_marque(self) -> None:
        ordre = _judgment_execution(
            {"delivery_decision": "deliver", "classification": "legitimate", "confidence": 0.95}
        )
        self.assertIsNone(ordre["filed_as_junk"])

    def test_une_demande_d_avis_ne_livre_rien(self) -> None:
        ordre = _judgment_execution(
            {"delivery_decision": "ask_user", "classification": "suspect", "confidence": 0.7}
        )
        self.assertFalse(ordre["original_delivery_allowed"])

    def test_les_valeurs_marquees_sont_celles_que_dovecot_trie(self) -> None:
        # Le tri Dovecot ne connaît que ces mots : en inventer un autre
        # livrerait le message en boîte de réception sans que rien n'alerte.
        self.assertLessEqual(
            set(FILED_AS_JUNK.values()), {"suspect", "spam", "phishing", "malicious"}
        )


class EnteteTests(unittest.TestCase):
    def test_l_entete_precede_le_message_sans_l_alterer(self) -> None:
        brut = b"From: a@b.test\r\nSubject: bonjour\r\n\r\nCorps du message.\r\n"
        marque = classify_header(brut, "spam")
        self.assertTrue(marque.startswith(b"X-Sentimail-Verdict: spam\r\n"))
        self.assertIn(b"Corps du message.", marque)
        self.assertIn(b"Subject: bonjour", marque)

    def test_un_message_en_sauts_de_ligne_simples_reste_valide(self) -> None:
        brut = b"From: a@b.test\nSubject: bonjour\n\nCorps.\n"
        marque = classify_header(brut, "malicious")
        self.assertTrue(marque.startswith(b"X-Sentimail-Verdict: malicious\n"))
        self.assertIn(b"\n\nCorps.", marque)


if __name__ == "__main__":
    unittest.main()


class RepriseTests(unittest.TestCase):
    def test_la_reprise_relit_le_classement_dans_le_dossier(self) -> None:
        # Le classement doit survivre à un échec d'envoi : il est écrit dans
        # le dossier, la reprise le relit et renvoie le message marqué.
        import inspect

        from sentimail_v3.execution import delivery

        source = inspect.getsource(delivery.retry_one_release)
        self.assertIn("filed_as_junk", source)
        self.assertIn("classify_as=", source)


class AnalyseIncompleteTests(unittest.TestCase):
    def _valide(self, verdict: dict, **regles: object) -> None:
        _validate_final_judgment(verdict, {"judgment_rules": {**RULES, **regles}})

    def test_une_verification_inachevee_ne_derange_pas_sans_raison(self) -> None:
        # Identité authentifiée, rien de défavorable : un lien qui refuse le
        # bac à sable ne justifie pas de demander un avis.
        verdict = _verdict("legitimate", "deliver")
        verdict["verdict_doubt"] = False
        self._valide(
            verdict,
            deep_execution_complete=False,
            incomplete_analysis_is_decisive=False,
        )

    def test_elle_redevient_bloquante_des_qu_il_y_a_un_doute(self) -> None:
        verdict = _verdict("legitimate", "deliver")
        verdict["verdict_doubt"] = False
        with self.assertRaises(JudgmentContradiction) as leve:
            self._valide(
                verdict,
                deep_execution_complete=False,
                incomplete_analysis_is_decisive=True,
            )
        self.assertIn("deep_execution_incomplete", leve.exception.contradictions)

    def test_une_preuve_materielle_bloque_meme_sans_analyse_decisive(self) -> None:
        verdict = _verdict("legitimate", "deliver")
        verdict["verdict_doubt"] = False
        with self.assertRaises(JudgmentContradiction) as leve:
            self._valide(
                verdict,
                deep_execution_complete=False,
                incomplete_analysis_is_decisive=False,
                material_danger_evidence=["ATT-001"],
            )
        self.assertIn("material_danger_unresolved", leve.exception.contradictions)

    def test_classer_un_indesirable_ne_depend_pas_de_l_analyse_profonde(self) -> None:
        # Un classement se relit dans les indésirables : l'erreur y coûte moins
        # cher qu'une question posée sur chaque envoi de masse.
        self._valide(
            _verdict("spam", "junk"),
            deep_execution_complete=False,
            incomplete_analysis_is_decisive=False,
        )

    def test_classer_un_danger_exige_encore_une_analyse_complete(self) -> None:
        with self.assertRaises(JudgmentContradiction) as leve:
            self._valide(
                _verdict("dangerous", "junk"),
                deep_execution_complete=False,
                incomplete_analysis_is_decisive=False,
            )
        self.assertIn("deep_execution_incomplete", leve.exception.contradictions)


class MotivationRetourneeTests(unittest.TestCase):
    def test_un_avis_force_explique_ce_qui_a_bloque(self) -> None:
        from sentimail_v3.judgment.verdict_engine import waiting_judgment

        contradiction = JudgmentContradiction(
            ["deep_execution_incomplete"],
            {
                "classification": "legitimate",
                "delivery_decision": "deliver",
                "rationale": "La confiance dépasse le seuil requis.",
                "uncertainties": [],
            },
        )
        attente = waiting_judgment(contradiction)
        self.assertEqual(attente["delivery_decision"], "ask_user")
        self.assertEqual(attente["classification"], "undetermined")
        # L'avis ne doit plus affirmer la livraison qu'il vient de refuser.
        self.assertIn("n’a pas pu être menée à son terme", str(attente["rationale"]))


class AnnotationJunkTests(unittest.TestCase):
    def test_les_entetes_expliquent_le_classement(self) -> None:
        from sentimail_v3.execution.delivery import classify_header

        brut = b"From: a@b.test\r\nSubject: promo\r\n\r\nCorps.\r\n"
        marque = classify_header(
            brut,
            "spam",
            reasons=["Authentification en échec"],
            techniques=["Usurpation de marque"],
        )
        self.assertIn(b"X-Sentimail-Verdict: spam", marque)
        self.assertIn(b"X-Sentimail-Classification-Reason:", marque)
        self.assertIn(b"Usurpation", marque)
        self.assertIn(b"Corps.", marque)

    def test_une_valeur_hostile_n_injecte_pas_d_entete(self) -> None:
        from sentimail_v3.execution.delivery import classify_header

        # Une raison qui contient un saut de ligne ne doit pas fabriquer un
        # second en-tête falsifié.
        marque = classify_header(
            b"Subject: x\r\n\r\nc",
            "malicious",
            reasons=["ok\r\nX-Evil: injecte"],
        )
        # Pas d'en-tête X-Evil en début de ligne : le saut a été neutralisé,
        # la chaîne ne survit que dans la valeur d'un en-tête légitime.
        self.assertNotIn(b"\nX-Evil:", marque)
        self.assertNotIn(b"\r\nX-Evil:", marque)

    def test_le_bandeau_apparait_dans_le_corps_texte(self) -> None:
        from sentimail_v3.execution.delivery import annotate_classified

        brut = (
            b"From: a@b.test\r\nSubject: promo\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Achetez maintenant.\r\n"
        )
        annote = annotate_classified(
            brut,
            "spam",
            reasons=["Publipostage non sollicité"],
            lessons=[{"name": "Pression par l'urgence", "description": "explication"}],
        )
        from email import policy
        from email.parser import BytesParser

        message = BytesParser(policy=policy.default).parsebytes(annote)
        corps = "".join(
            str(part.get_content())
            for part in message.walk()
            if part.get_content_type() == "text/plain"
        )
        self.assertIn("classé ce message en indésirable", corps)
        self.assertIn("Publipostage non sollicité", corps)
        self.assertIn("Pression", corps)
        self.assertIn("Achetez maintenant", corps)

    def test_un_message_malforme_retombe_sur_les_entetes(self) -> None:
        from sentimail_v3.execution.delivery import annotate_classified

        # Octets non-MIME : l'annotation du corps échoue, les en-têtes restent.
        annote = annotate_classified(
            b"\xff\xfe pas un message",
            "malicious",
            reasons=["Chantage"],
            lessons=[],
        )
        self.assertIn(b"X-Sentimail-Verdict: malicious", annote)
