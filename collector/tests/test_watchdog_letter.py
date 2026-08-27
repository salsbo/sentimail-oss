"""L'alerte du superviseur se lit, elle ne se décode pas.

Le courrier d'état partait en JSON brut : « État : OK » suivi de trente
compteurs. Lire « verdict_execution_mismatches:0 » suppose de savoir ce que
mesure ce compteur et pourquoi zéro rassure. Comme le rapport d'entretien,
l'alerte se traduit en phrases, avec la charte des autres surfaces - bandeau
coloré, sections, signature - et l'état brut conservé en fin pour l'audit.
"""

from __future__ import annotations

import unittest

from sentimail_v3.supervision.watchdog_letter import lettre

DETAILS_OK = {
    "mail_e2e": {"status": "ok", "latency_ms": 96.3},
    "analysis_backlog": 0,
    "verdict_execution_mismatches": 0,
    "reasons": [],
    "observed_reasons": [],
}

DETAILS_DEGRADE = dict(
    DETAILS_OK,
    verdict_execution_mismatches=2,
    reasons=["verdict_execution_mismatches", "backup_stale"],
)

DETAILS_PANNE = dict(DETAILS_OK, reasons=["mail_e2e_capture"])


class TexteTests(unittest.TestCase):
    def test_le_retour_a_la_normale_se_dit_en_francais(self) -> None:
        rendu = lettre("ok", DETAILS_OK)
        self.assertIn("opérationnelle", rendu.subject)
        premiere = rendu.text.splitlines()[0]
        self.assertNotIn("État :", premiere)
        self.assertIn("normalement", premiere)

    def test_le_temoin_de_bout_en_bout_est_raconte(self) -> None:
        rendu = lettre("ok", DETAILS_OK)
        self.assertIn("témoin", rendu.text)
        self.assertIn("96", rendu.text)

    def test_les_raisons_sont_traduites(self) -> None:
        rendu = lettre("degraded", DETAILS_DEGRADE)
        self.assertNotIn("verdict_execution_mismatches", rendu.text)
        self.assertNotIn("backup_stale", rendu.text)
        self.assertIn("verdict", rendu.text.casefold())
        self.assertIn("sauvegarde", rendu.text.casefold())

    def test_un_code_inconnu_reste_montre_sans_planter(self) -> None:
        rendu = lettre("degraded", dict(DETAILS_OK, reasons=["signal_futur"]))
        self.assertIn("signal_futur", rendu.text)

    def test_les_messages_concernes_sont_nommes(self) -> None:
        # « des verdicts n'ont pas été exécutés conformément » ne s'exploite
        # pas sans savoir DE QUEL message il s'agit : le sujet le dit, jamais
        # l'identifiant interne.
        details = dict(
            DETAILS_DEGRADE,
            soft_failure_examples=[
                {
                    "kind": "verdict_execution",
                    "message_id": "61d83196-57d0-4252-bbf0-e6edf97e6ef6",
                    "component": "final_judgment",
                    "subject": "Votre code de vérification",
                }
            ],
        )
        rendu = lettre("degraded", details)
        self.assertIn("Votre code de vérification", rendu.text)
        self.assertNotIn("61d83196", rendu.text)
        self.assertIn("Votre code de vérification", rendu.html)

    def test_aucun_etat_brut_dans_le_courrier(self) -> None:
        # L'état complet vit dans operational_status et les journaux du
        # superviseur : le courrier reste entièrement rédigé.
        for status, details in (
            ("ok", DETAILS_OK),
            ("degraded", DETAILS_DEGRADE),
            ("down", DETAILS_PANNE),
        ):
            rendu = lettre(status, details)
            self.assertNotIn("Détail technique", rendu.text)
            self.assertNotIn("{", rendu.text)
            self.assertNotIn('"mail_e2e"', rendu.html)


class CharteTests(unittest.TestCase):
    def test_le_bandeau_porte_la_couleur_de_l_etat(self) -> None:
        for status, couleur in (
            ("ok", "#15803d"),
            ("degraded", "#b45309"),
            ("down", "#b91c1c"),
        ):
            with self.subTest(status=status):
                details = {
                    "ok": DETAILS_OK,
                    "degraded": DETAILS_DEGRADE,
                    "down": DETAILS_PANNE,
                }[status]
                self.assertIn(f"background:{couleur}", lettre(status, details).html)

    def test_la_page_suit_la_charte_des_avis(self) -> None:
        html = lettre("ok", DETAILS_OK).html
        self.assertIn("max-width:640px", html)
        self.assertIn("Arial", html)
        self.assertIn("MAIA, ton assistante SentiMail", html)

    def test_une_panne_franche_se_nomme(self) -> None:
        rendu = lettre("down", DETAILS_PANNE)
        self.assertIn("Alerte technique", rendu.subject)
        self.assertIn("témoin", rendu.text.casefold())


if __name__ == "__main__":
    unittest.main()
