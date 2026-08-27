from __future__ import annotations

import unittest

from sentimail_v3.code.families import FAMILIES
from sentimail_v3.supervision.training import compact_dossier


def _clue(article: str, code: str, direction: str = "adverse", strength: int = 70):
    return {
        "clue_code": code,
        "article_code": article,
        "direction": direction,
        "strength": strength,
        "confidence": 0.9,
        "statement": "peu importe",
    }


def _dossier(clues: list[dict[str, object]]) -> dict[str, object]:
    return {
        "clues": clues,
        "message": {"investigation_status": "complete"},
        "judgment_rules": {"confidence_required": 0.9},
    }


class VocabulaireUniqueTests(unittest.TestCase):
    """Deux définitions de « famille » dans le même produit se contredisent.

    Le jugement range les preuves par article ; l'apprentissage les rangeait par
    préfixe du code d'indice. Le même message produisait donc deux découpages
    différents, et ce qui était appris ne correspondait pas à ce qui avait été
    jugé.
    """

    def test_l_apprentissage_emploie_les_familles_du_jugement(self) -> None:
        compact = compact_dossier(
            _dossier([_clue("AUTH-001", "AUTH_DMARC_FAIL")])
        )
        self.assertEqual(compact["evidence_families"], ["identite"])

    def test_un_constat_profond_est_range_par_sujet_pas_par_etage(self) -> None:
        # ATTACHMENT_SANDBOX_MATERIAL et URL_SANDBOX_FORM commencent tous deux
        # par un préfixe qui ne dit pas leur sujet : c'est l'article qui le dit.
        compact = compact_dossier(
            _dossier(
                [
                    _clue("DEEP-004", "ATTACHMENT_SANDBOX_MATERIAL"),
                    _clue("DEEP-002", "URL_SANDBOX_FORM"),
                ]
            )
        )
        self.assertEqual(
            sorted(compact["evidence_families"]), ["liens", "pieces_jointes"]
        )

    def test_les_familles_restent_dans_le_registre_connu(self) -> None:
        compact = compact_dossier(
            _dossier(
                [
                    _clue("ACT-001", "ACTION_PAYMENT_TRANSFER"),
                    _clue("RSPAMD-002", "RSPAMD_MATERIAL"),
                    _clue("HEADER-002", "HEADERS_REPLY_TO"),
                ]
            )
        )
        for famille in compact["evidence_families"]:
            self.assertIn(famille, FAMILIES)


class TracabiliteTests(unittest.TestCase):
    def test_la_vue_conservee_ne_recopie_pas_la_couverture_detaillee(self) -> None:
        # Elle se redérive entièrement des indices, qui sont déjà là. L'écrire
        # doublerait le volume d'une vue archivée pour chaque message.
        compact = compact_dossier(_dossier([_clue("AUTH-001", "AUTH_DMARC_FAIL")]))
        self.assertNotIn("family_coverage", compact)

    def test_la_vue_conservee_porte_les_familles_convergentes(self) -> None:
        compact = compact_dossier(
            _dossier(
                [
                    _clue("AUTH-001", "AUTH_DMARC_FAIL"),
                    _clue("ATT-010", "ATTACHMENT_MACRO_SHELL", strength=95),
                ]
            )
        )
        self.assertEqual(
            set(compact["converging_families"]), {"identite", "pieces_jointes"}
        )

    def test_un_dossier_sans_indice_reste_lisible(self) -> None:
        compact = compact_dossier(_dossier([]))
        self.assertEqual(compact["evidence_families"], [])
        self.assertEqual(compact["converging_families"], [])

    def test_le_jugement_voit_les_familles_muettes_lui(self) -> None:
        # L'archive peut déduire le silence ; le modèle, lui, doit le lire
        # noir sur blanc, sinon il comble le vide.
        from sentimail_v3.code.families import family_coverage

        self.assertEqual(len(family_coverage([])), len(FAMILIES))


if __name__ == "__main__":
    unittest.main()
