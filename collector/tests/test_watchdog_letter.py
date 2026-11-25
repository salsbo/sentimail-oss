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

    def test_un_credit_epuise_est_annonce_sans_jargon(self) -> None:
        rendu = lettre(
            "degraded",
            dict(
                DETAILS_OK,
                reasons=["verdict_provider_credit_exhausted"],
                verdict_provider_credit_exhausted=1,
            ),
        )
        self.assertIn("crédit", rendu.subject.casefold())
        self.assertIn("solde", rendu.text.casefold())
        self.assertIn("épuisé", rendu.text.casefold())
        self.assertNotIn("verdict_provider_credit_exhausted", rendu.text)

    def test_un_retour_non_applique_est_annonce_sans_code_interne(self) -> None:
        rendu = lettre(
            "degraded",
            dict(
                DETAILS_OK,
                reasons=["feedback_application_mismatches"],
                feedback_application_mismatches=1,
            ),
        )
        self.assertIn("retours utilisateur", rendu.text.casefold())
        self.assertNotIn("feedback_application_mismatches", rendu.text)

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


class MessagesEnAttenteTests(unittest.TestCase):
    """L'alerte du 14 septembre disait « des messages attendent leur analyse »
    sans dire lequel, depuis quand ni où il bloquait. Le lecteur a demandé ce
    qu'il était censé faire. La lettre doit nommer le message, son attente et
    l'étape en cours, puis dire quoi faire.
    """

    EN_ATTENTE = dict(
        DETAILS_OK,
        analysis_backlog=1,
        accepted_without_terminal_outcome=1,
        reasons=["accepted_without_terminal_outcome", "analysis_backlog"],
        stalled_messages=[
            {
                "message_id": "28f2c85e-fc76-4851-abac-654c07d55ebf",
                "subject": "Your Gaia membership has been canceled.",
                "delivery_status": "analyzing",
                "waiting_seconds": 671,
                "run_status": "running",
                "run_attempts": 1,
                "run_error_type": None,
                "llm_model": "deepseek-v4-flash",
                "llm_stage": "economy",
                "llm_since_seconds": 610,
            }
        ],
    )

    def test_le_message_en_attente_est_nomme_avec_son_attente(self) -> None:
        rendu = lettre("degraded", self.EN_ATTENTE)
        self.assertIn("Your Gaia membership has been canceled.", rendu.text)
        self.assertIn("11 min", rendu.text)
        self.assertNotIn("28f2c85e", rendu.text)
        self.assertIn("Your Gaia membership has been canceled.", rendu.html)

    def test_l_etape_qui_bloque_est_dite(self) -> None:
        rendu = lettre("degraded", self.EN_ATTENTE)
        self.assertIn("deepseek-v4-flash", rendu.text)
        self.assertIn("économique", rendu.text)
        self.assertIn("10 min", rendu.text)

    def test_un_juge_en_echec_qui_reessaie_est_dit(self) -> None:
        details = dict(self.EN_ATTENTE)
        details["stalled_messages"] = [
            dict(
                self.EN_ATTENTE["stalled_messages"][0],
                run_status="error", run_attempts=2, run_error_type="LlmError",
                llm_model=None, llm_stage=None, llm_since_seconds=None,
            )
        ]
        rendu = lettre("degraded", details)
        self.assertIn("2 fois", rendu.text)
        self.assertIn("LlmError", rendu.text)

    def test_un_message_sans_juge_attend_un_juge_libre(self) -> None:
        details = dict(self.EN_ATTENTE)
        details["stalled_messages"] = [
            dict(
                self.EN_ATTENTE["stalled_messages"][0],
                run_status=None, run_attempts=None, run_error_type=None,
                llm_model=None, llm_stage=None, llm_since_seconds=None,
            )
        ]
        rendu = lettre("degraded", details)
        self.assertIn("juge libre", rendu.text)

    def test_les_raisons_portent_leur_seuil(self) -> None:
        rendu = lettre("degraded", self.EN_ATTENTE)
        self.assertIn("10 minutes", rendu.text)

    def test_la_lettre_dit_quoi_faire(self) -> None:
        rendu = lettre("degraded", self.EN_ATTENTE)
        self.assertIn("À faire", rendu.text)
        self.assertIn("30 minutes", rendu.text)
        self.assertIn("verdict", rendu.text)

    def test_un_credit_epuise_demande_de_recrediter(self) -> None:
        rendu = lettre(
            "degraded",
            dict(
                DETAILS_OK,
                reasons=["verdict_provider_credit_exhausted"],
                verdict_provider_credit_exhausted=1,
            ),
        )
        self.assertIn("À faire", rendu.text)
        self.assertIn("recréditer", rendu.text.casefold())

    def test_le_retour_a_la_normale_ne_dit_rien_a_faire(self) -> None:
        rendu = lettre("ok", DETAILS_OK)
        self.assertNotIn("À faire", rendu.text)


class TemoinSincereTests(unittest.TestCase):
    """La sonde envoie un message, vérifie sa capture, puis l'efface. Elle ne
    le fait jamais juger. Le 14 septembre, la lettre affirmait que la chaîne
    était traversée « envoi, capture, verdict » pendant que le juge était
    suspendu : le mot verdict promettait ce que la sonde ne vérifie pas.
    """

    def test_le_temoin_ne_promet_pas_de_verdict(self) -> None:
        rendu = lettre("ok", DETAILS_OK)
        ligne = next(l for l in rendu.text.splitlines() if "témoin" in l)
        self.assertNotIn("verdict", ligne)
        self.assertIn("capturé", ligne)
        self.assertIn("96", ligne)

    def test_le_temoin_dit_qu_il_ne_passe_pas_devant_le_juge(self) -> None:
        rendu = lettre("ok", DETAILS_OK)
        self.assertIn("juge", next(l for l in rendu.text.splitlines() if "témoin" in l))

    def test_une_etape_de_sonde_en_echec_est_dite_en_francais(self) -> None:
        rendu = lettre("down", dict(DETAILS_OK, reasons=["mail_e2e_send"]))
        self.assertIn("envoi", rendu.text)
        self.assertNotIn("« send »", rendu.text)


class RemissionTests(unittest.TestCase):
    """Le mail « c'est reparti » disait tout est reparti, rien d'autre. Le
    lecteur ne savait ni combien de temps ça avait duré, ni si le message
    bloqué avait fini par arriver.
    """

    EPISODE = dict(
        DETAILS_OK,
        episode={
            "duration_seconds": 304,
            "messages": [
                {
                    "message_id": "28f2c85e-fc76-4851-abac-654c07d55ebf",
                    "subject": "Your Gaia membership has been canceled.",
                    "delivery_status": "delivered",
                    "waited_seconds": 953,
                }
            ],
        },
    )

    def test_la_remission_dit_la_duree_de_l_episode(self) -> None:
        rendu = lettre("ok", self.EPISODE)
        self.assertIn("5 min", rendu.text)

    def test_la_remission_dit_le_sort_du_message_bloque(self) -> None:
        rendu = lettre("ok", self.EPISODE)
        self.assertIn("Your Gaia membership has been canceled.", rendu.text)
        self.assertIn("livré", rendu.text)
        self.assertIn("16 min", rendu.text)
        self.assertNotIn("28f2c85e", rendu.text)
        self.assertIn("Your Gaia membership has been canceled.", rendu.html)

    def test_un_message_retenu_est_dit_retenu(self) -> None:
        details = dict(self.EPISODE)
        details["episode"] = dict(
            self.EPISODE["episode"],
            messages=[dict(self.EPISODE["episode"]["messages"][0], delivery_status="held")],
        )
        rendu = lettre("ok", details)
        self.assertIn("retenu", rendu.text)

    def test_sans_episode_la_remission_reste_courte(self) -> None:
        rendu = lettre("ok", DETAILS_OK)
        self.assertNotIn("épisode", rendu.text.casefold())


class CheminsDEchecTests(unittest.TestCase):
    """Les secours se lisent en phrases, avec le geste à faire."""

    @staticmethod
    def _rendu(code: str):
        return lettre("degraded", dict(DETAILS_OK, reasons=[code], **{code: 1}))

    def test_une_retenue_fermee_se_dit_sans_code_interne(self) -> None:
        rendu = self._rendu("fail_closed_holds")
        self.assertNotIn("fail_closed_holds", rendu.text)
        self.assertIn("pas livrés en clair", rendu.text)
        self.assertIn("ne pas livrer", rendu.text.casefold())
        # Le motif hérité du fail-open est annoncé, pour ne pas s'y tromper.
        self.assertIn("nom hérité", rendu.text)

    def test_un_secours_de_retenue_se_dit_sans_code_interne(self) -> None:
        rendu = self._rendu("review_fail_open_last_hour")
        self.assertNotIn("review_fail_open_last_hour", rendu.text)
        self.assertIn("mode de secours", rendu.text)
        self.assertIn("assistant", rendu.text)

    def test_un_repli_d_enveloppe_se_dit_sans_code_interne(self) -> None:
        rendu = self._rendu("junk_envelope_fallbacks_last_hour")
        self.assertNotIn("junk_envelope_fallbacks_last_hour", rendu.text)
        self.assertIn("annotés", rendu.text)
        self.assertIn("delivery.junk_envelope_fallback", rendu.text)

    def test_les_phrases_du_secours_n_ont_pas_de_tiret_cadratin(self) -> None:
        from sentimail_v3.supervision.watchdog_letter import _CONSIGNES, _RAISONS

        cadratin = chr(0x2014)
        for code in (
            "fail_closed_holds",
            "review_fail_open_last_hour",
            "junk_envelope_fallbacks_last_hour",
        ):
            with self.subTest(code=code):
                self.assertNotIn(cadratin, _RAISONS[code])
                self.assertNotIn(cadratin, _CONSIGNES[code])

