"""Une identité démentie sur pièces ne se pose pas en question.

M-490357 (6 septembre 2026) : « C I C » depuis un domaine étranger, pas
d'authentification, un lien à cliquer. Le juge : « aucune preuve matérielle de
dommage », et une question à l'utilisateur. L'usurpation était pourtant
établie : la recherche avait rendu les domaines de la banque.
"""

from __future__ import annotations

import json
import unittest

from sentimail_v3.code.correlation import correlations
from sentimail_v3.judgment.verdict_engine import (
    _material_impersonation_profile,
    _parse_verdict,
)

PROFIL = {
    "CORRELATION_BRAND_SPOOFING",
    "IDENTITY_CLAIMED_ORGANISATION_REFUTED",
    "HISTORY_FIRST_OBSERVATION",
    "ACTION_CLICK_LINK",
}


def _codes(observed: set[str]) -> set[str]:
    return {value["clue_code"] for value in correlations(observed)}


class ConvergenceTests(unittest.TestCase):
    def test_le_dementi_par_recherche_converge_avec_le_defaut_d_authentification(self) -> None:
        for auth in ("AUTH_DMARC_FAIL", "AUTH_DMARC_INCONCLUSIVE"):
            with self.subTest(auth=auth):
                self.assertIn(
                    "CORRELATION_BRAND_SPOOFING",
                    _codes({"IDENTITY_CLAIMED_ORGANISATION_REFUTED", auth}),
                )

    def test_le_dementi_par_recherche_converge_en_premier_contact(self) -> None:
        self.assertIn(
            "CORRELATION_BRAND_FIRST_CONTACT",
            _codes({"IDENTITY_CLAIMED_ORGANISATION_REFUTED", "HISTORY_FIRST_OBSERVATION"}),
        )

    def test_l_impression_du_modele_seule_ne_converge_pas(self) -> None:
        # DEEP-021 repose sur la lecture du modèle, sans domaine officiel : il
        # s'est déjà trompé, il ne fonde pas un faisceau.
        self.assertNotIn(
            "CORRELATION_BRAND_SPOOFING",
            _codes({"IDENTITY_CLAIMED_ORGANISATION_UNRELATED", "AUTH_DMARC_FAIL"}),
        )


def _clues(codes: set[str], constat: str | None = "domaine_officiel_avec_mot_en_plus") -> list[dict[str, object]]:
    clues: list[dict[str, object]] = []
    for code in sorted(codes):
        facts = {"constat": constat} if code == "IDENTITY_CLAIMED_ORGANISATION_REFUTED" and constat else {}
        clues.append({"clue_code": code, "direction": "adverse", "facts": json.dumps(facts)})
    return clues


class ProfilTests(unittest.TestCase):
    def test_le_profil_complet_est_reconnu(self) -> None:
        self.assertTrue(_material_impersonation_profile(_clues(PROFIL)))

    def test_chaque_pied_manquant_defait_le_profil(self) -> None:
        for retire in PROFIL:
            with self.subTest(sans=retire):
                self.assertFalse(_material_impersonation_profile(_clues(PROFIL - {retire})))

    def test_une_marque_mal_lue_sans_demande_reste_un_doute(self) -> None:
        self.assertFalse(
            _material_impersonation_profile(
                _clues(PROFIL - {"ACTION_CLICK_LINK"} | {"ACTION_REPLY_MESSAGE"})
            )
        )

    def test_la_lecture_du_modele_ne_condamne_pas_seule(self) -> None:
        # Même code, mais posé par le modèle sur deux recherches : il a déjà
        # tenu un routeur d'emailing pour une usurpation. Il converge, il
        # informe, il ne classe pas.
        self.assertFalse(_material_impersonation_profile(_clues(PROFIL, constat=None)))

    def test_un_constat_neutralise_ne_condamne_pas(self) -> None:
        clues = _clues(PROFIL)
        for clue in clues:
            if clue["clue_code"] == "IDENTITY_CLAIMED_ORGANISATION_REFUTED":
                clue["direction"] = "neutral"
        self.assertFalse(_material_impersonation_profile(clues))


class RemonteeTests(unittest.TestCase):
    @staticmethod
    def _dossier(*, deep_complete: bool, profil: bool = True) -> dict[str, object]:
        return {
            "clues": [{"id": i, "clue_code": code, "direction": "adverse"} for i, code in enumerate(sorted(PROFIL), 1)],
            "material_spam_profile": False,
            "material_impersonation_profile": profil,
            "judgment_rules": {
                "verdict_is_final": True,
                "confidence_required": 0.90,
                "deep_execution_complete": deep_complete,
                "static_investigation_complete": True,
                "material_danger_evidence": [],
                "authenticated_sender_policy": "none",
            },
        }

    @staticmethod
    def _verdict(classification: str, decision: str, confidence: float = 0.75) -> str:
        return json.dumps({"final_verdict": {"classification": classification, "confidence": confidence, "delivery_decision": decision, "rationale": "x"}})

    def test_le_doute_devient_dangereux_quand_l_analyse_est_complete(self) -> None:
        parsed = _parse_verdict(self._verdict("suspect", "ask_user"), self._dossier(deep_complete=True))
        self.assertEqual(parsed["classification"], "dangerous")
        self.assertEqual(parsed["delivery_decision"], "junk")
        self.assertGreaterEqual(parsed["confidence"], 0.90)

    def test_le_doute_devient_indesirable_quand_le_lien_n_a_pas_repondu(self) -> None:
        # L'attaquant tient le lien : faire échouer le bac à sable lui
        # suffisait pour rester en doute. Le Code autorise le classement
        # indésirable sur une analyse partielle, pas le verdict dangereux.
        parsed = _parse_verdict(self._verdict("suspect", "ask_user"), self._dossier(deep_complete=False))
        self.assertEqual(parsed["classification"], "spam")
        self.assertEqual(parsed["delivery_decision"], "junk")

    def test_un_legitime_n_est_jamais_touche(self) -> None:
        parsed = _parse_verdict(self._verdict("legitimate", "deliver", 0.95), self._dossier(deep_complete=True))
        self.assertEqual(parsed["classification"], "legitimate")
        self.assertEqual(parsed["delivery_decision"], "deliver")

    def test_sans_profil_le_doute_reste_une_question(self) -> None:
        parsed = _parse_verdict(self._verdict("suspect", "ask_user"), self._dossier(deep_complete=True, profil=False))
        self.assertEqual(parsed["classification"], "suspect")
        self.assertEqual(parsed["delivery_decision"], "ask_user")
