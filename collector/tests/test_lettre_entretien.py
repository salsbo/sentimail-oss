from __future__ import annotations

import unittest

from sentimail_v3.supervision.caretaker_letter import lettre

CALME = {
    "verdicts_en_erreur_24h": 0,
    "livraisons_differees": 0,
    "dossiers_coinces": 0,
    "retenues_sans_avis": 0,
    "alertes_amorties_24h": 0,
    "prompt_actif": "code-sentinel-verdict-v18-family-coverage",
    "desaccords_humain_modele_7j": [],
    "sens_des_desaccords_7j": {
        "demande_au_lieu_de_classer": 0,
        "demande_au_lieu_de_livrer": 0,
        "erreur_de_qualification": 0,
        "laisse_passer": 0,
    },
    "erreurs_de_verdict_24h": [],
}

REFUS_DEFINITIF = dict(
    CALME,
    verdicts_en_erreur_24h=1,
    erreurs_de_verdict_24h=[
        {
            "error_type": "SMTPRecipientsRefused",
            "detail": "[SMTPRecipientRefused(550, '5.1.1 "
            "<operateur+parcours20260818@mondomaine.example>: Recipient address rejected: "
            "User unknown in virt",
            "count": 1,
        }
    ],
    sens_des_desaccords_7j={
        "demande_au_lieu_de_classer": 1,
        "demande_au_lieu_de_livrer": 2,
        "erreur_de_qualification": 0,
        "laisse_passer": 0,
    },
)

BLOQUE = dict(CALME, dossiers_coinces=3, livraisons_differees=2)

# Une vraie panne d'analyse, réparable : le rapport du 20/08 la signalait dans
# le corps sous un objet qui disait « rien à signaler ».
PANNE_REPARABLE = dict(
    CALME,
    verdicts_en_erreur_24h=2,
    erreurs_de_verdict_24h=[
        {"error_type": "KeyError", "detail": "'clues'", "count": 2}
    ],
)

DIAGNOSTIC = {"diagnosis": "Rien qui appelle une correction."}


class LisibiliteTests(unittest.TestCase):
    """Le rapport doit se lire, pas se décoder.

    Il sortait en JSON brut : lire « retenues_sans_avis:0 » demande de savoir
    ce qu'est une retenue et pourquoi zéro est une bonne nouvelle. Un rapport
    qu'on ne lit pas ne supervise rien.
    """

    def test_aucune_cle_technique_dans_le_texte_lisible(self) -> None:
        rendu = lettre(CALME, DIAGNOSTIC, {})
        for cle in ("retenues_sans_avis", "dossiers_coinces", "prompt_actif",
                    "desaccords_humain_modele_7j", "verdicts_en_erreur_24h"):
            with self.subTest(cle=cle):
                self.assertNotIn(cle, rendu.text.split("Détail technique")[0])

    def test_le_texte_nomme_les_choses_en_francais(self) -> None:
        rendu = lettre(BLOQUE, DIAGNOSTIC, {})
        self.assertIn("immobilisés", rendu.text)
        self.assertIn("3", rendu.text)

    def test_les_deux_versions_disent_la_meme_chose(self) -> None:
        rendu = lettre(BLOQUE, DIAGNOSTIC, {})
        self.assertIn("immobilisés", rendu.html)
        self.assertTrue(rendu.html.startswith("<div"))


class ObjetTests(unittest.TestCase):
    """L'objet dit la situation et son niveau, avant même d'ouvrir.

    Trois niveaux : grave (une erreur de jugement, un compteur d'anomalie),
    modéré (des analyses en échec à réparer), faible (des faits notés qui ne
    demandent rien - refus définitifs, désaccords de prudence). Sans rien de
    tout cela, l'objet reste « rien à signaler ».
    """

    def test_rien_a_signaler_se_lit_dans_l_objet(self) -> None:
        self.assertIn("rien à signaler", lettre(CALME, DIAGNOSTIC, {}).subject)

    def test_un_compteur_d_anomalie_est_un_signalement_grave(self) -> None:
        sujet = lettre(BLOQUE, DIAGNOSTIC, {}).subject
        self.assertIn("signalement grave", sujet)
        self.assertIn("3 dossiers immobilisés", sujet)

    def test_une_erreur_corrigee_par_l_humain_n_est_qu_un_fait_note(self) -> None:
        erreur = dict(
            CALME,
            sens_des_desaccords_7j=dict(
                CALME["sens_des_desaccords_7j"], laisse_passer=1
            ),
        )
        sujet = lettre(erreur, DIAGNOSTIC, {}).subject
        self.assertIn("signalement faible", sujet)
        self.assertNotIn("intervention requise", sujet)

    def test_une_panne_reparable_est_un_signalement_modere(self) -> None:
        sujet = lettre(PANNE_REPARABLE, DIAGNOSTIC, {}).subject
        self.assertIn("signalement modéré", sujet)

    def test_un_refus_definitif_est_un_signalement_faible(self) -> None:
        # Une boîte qui n'existe pas n'appelle aucune correction : l'objet le
        # dit sans alarmer, mais sans prétendre qu'il n'y a rien à lire.
        sujet = lettre(REFUS_DEFINITIF, DIAGNOSTIC, {}).subject
        self.assertIn("signalement faible", sujet)
        self.assertNotIn("grave", sujet)
        self.assertNotIn("modéré", sujet)


class ObjetCoherentTests(unittest.TestCase):
    """L'objet ne peut pas dire « rien à signaler » quand le corps signale.

    Le rapport du 20/08 ouvrait sur « J'ai trouvé quelque chose à te
    signaler » - deux analyses en échec sur KeyError - sous un objet
    « rien à signaler » : l'en-tête regardait les échecs réparables, l'objet
    ne regardait que les erreurs de jugement et les compteurs d'anomalie.
    """

    def test_une_panne_reparable_se_lit_dans_l_objet(self) -> None:
        rendu = lettre(PANNE_REPARABLE, DIAGNOSTIC, {})
        self.assertNotIn("rien à signaler", rendu.subject)
        self.assertIn("analyse", rendu.subject.casefold())

    def test_l_objet_et_l_entete_disent_la_meme_chose(self) -> None:
        rendu = lettre(PANNE_REPARABLE, DIAGNOSTIC, {})
        self.assertIn("intervention est requise", rendu.text.splitlines()[0])
        self.assertNotIn("rien à signaler", rendu.subject)

    def test_un_signalement_faible_garde_une_entete_calme(self) -> None:
        # Un fait qui ne demande rien ne doit pas ouvrir sur une alerte.
        rendu = lettre(REFUS_DEFINITIF, DIAGNOSTIC, {})
        self.assertIn("signalement faible", rendu.subject)
        self.assertIn("Aucune action", rendu.text.splitlines()[0])

    def test_une_analyse_rejouee_ne_demande_plus_de_la_regarder(self) -> None:
        rendu = lettre(PANNE_REPARABLE, DIAGNOSTIC, {"replay_errored_verdicts": 2})
        self.assertIn("aucune action requise", rendu.subject)
        self.assertIn("Aucune action", rendu.text.splitlines()[0])
        self.assertNotIn("à regarder", rendu.subject)


class RefusSmtpTests(unittest.TestCase):
    """Une erreur SMTP se raconte, elle ne se recopie pas."""

    def test_l_adresse_refusee_est_nommee(self) -> None:
        rendu = lettre(REFUS_DEFINITIF, DIAGNOSTIC, {})
        self.assertIn("operateur+parcours20260818@mondomaine.example", rendu.text)

    def test_le_caractere_definitif_est_explique(self) -> None:
        rendu = lettre(REFUS_DEFINITIF, DIAGNOSTIC, {})
        self.assertIn("n’existe pas", rendu.text)
        self.assertIn("rien à réparer", rendu.text)

    def test_le_jargon_smtp_reste_hors_du_corps(self) -> None:
        rendu = lettre(REFUS_DEFINITIF, DIAGNOSTIC, {})
        lisible = rendu.text.split("Détail technique")[0]
        self.assertNotIn("SMTPRecipientRefused", lisible)
        self.assertNotIn("5.1.1", lisible)


class DesaccordsTests(unittest.TestCase):
    """Les deux sens ne se confondent pas, et zéro erreur se dit."""

    def test_prudence_et_erreur_sont_distinguees(self) -> None:
        rendu = lettre(REFUS_DEFINITIF, DIAGNOSTIC, {})
        self.assertIn("demandé leur avis", rendu.text)
        self.assertIn("aucune erreur", rendu.text.casefold())

    def test_une_vraie_erreur_est_annoncee_comme_telle(self) -> None:
        etat = dict(CALME, sens_des_desaccords_7j={
            "demande_au_lieu_de_classer": 0,
            "demande_au_lieu_de_livrer": 0,
            "erreur_de_qualification": 2,
            "laisse_passer": 1,
        })
        rendu = lettre(etat, DIAGNOSTIC, {})
        self.assertIn("écarté", rendu.text)
        self.assertIn("livré", rendu.text)
        self.assertIn("C’est une erreur de ma part", rendu.text)
        # Le verdict humain s'est appliqué : l'erreur est un fait, pas une tâche.
        self.assertNotIn("intervention requise", rendu.subject)

    def test_au_singulier_le_nombre_ne_double_pas(self) -> None:
        # « 1 j'ai demandé son avis » : la phrase se suffit au singulier.
        etat = dict(CALME, sens_des_desaccords_7j={
            "demande_au_lieu_de_classer": 1,
            "demande_au_lieu_de_livrer": 0,
            "erreur_de_qualification": 0,
            "laisse_passer": 0,
        })
        rendu = lettre(etat, DIAGNOSTIC, {})
        self.assertNotIn("1 j’ai", rendu.text)
        self.assertIn("J’ai demandé son avis au destinataire d’un message", rendu.text)

    def test_au_pluriel_le_nombre_est_dans_la_phrase(self) -> None:
        etat = dict(CALME, sens_des_desaccords_7j={
            "demande_au_lieu_de_classer": 0,
            "demande_au_lieu_de_livrer": 4,
            "erreur_de_qualification": 0,
            "laisse_passer": 0,
        })
        self.assertIn("de 4 messages ordinaires", lettre(etat, DIAGNOSTIC, {}).text)

    def test_sans_desaccord_la_section_disparait(self) -> None:
        self.assertNotIn("demandé leur avis", lettre(CALME, DIAGNOSTIC, {}).text)

    def test_les_jugements_ne_sont_pas_attribues_au_lecteur(self) -> None:
        # La lettre part à chaque exploitant mais agrège les avis de tous les
        # destinataires : « tu as jugé » attribuait au lecteur les avis des
        # autres. Les jugements se disent à la troisième personne.
        etat = dict(CALME, sens_des_desaccords_7j={
            "demande_au_lieu_de_classer": 3,
            "demande_au_lieu_de_livrer": 12,
            "erreur_de_qualification": 2,
            "laisse_passer": 1,
        })
        rendu = lettre(etat, DIAGNOSTIC, {})
        for interdit in ("tu as jugé", "tu as jugés", "ton avis"):
            self.assertNotIn(interdit, rendu.text)
            self.assertNotIn(interdit, rendu.html)
        self.assertIn("destinataire", rendu.text)


class ActionsTests(unittest.TestCase):
    """Ce qui a été fait se dit en verbe, pas en identifiant."""

    def test_une_action_executee_se_raconte(self) -> None:
        rendu = lettre(BLOQUE, DIAGNOSTIC, {"retry_deferred_deliveries": 2})
        self.assertIn("j’ai retenté 2 livraisons", rendu.text.casefold())
        self.assertNotIn("retry_deferred_deliveries", rendu.text)

    def test_une_seule_action_ne_double_pas_son_nombre(self) -> None:
        rendu = lettre(BLOQUE, DIAGNOSTIC, {"retry_deferred_deliveries": 1})
        self.assertNotIn("1 j’ai", rendu.text)
        self.assertIn("J’ai retenté une livraison", rendu.text)

    def test_sans_action_le_rapport_le_dit(self) -> None:
        self.assertIn("Je n’ai rien eu à faire", lettre(CALME, DIAGNOSTIC, {}).text)

    def test_le_rapport_dit_exactement_ce_que_l_exploitant_doit_faire(self) -> None:
        etat = dict(
            CALME,
            alertes_amorties_24h=9,
            erreurs_de_verdict_24h=[
                {
                    "error_type": "JudgmentContradiction",
                    "detail": "sortie incohérente",
                    "count": 1,
                },
                {
                    "error_type": "SMTPRecipientsRefused",
                    "detail": "550 5.1.1 <info@agence.example>: user unknown",
                    "count": 1,
                },
            ],
            sens_des_desaccords_7j={
                **CALME["sens_des_desaccords_7j"],
                "laisse_passer": 1,
                "demande_au_lieu_de_classer": 8,
                "demande_au_lieu_de_livrer": 14,
            },
            ecarts_non_traites={"laisse_passer": 1},
        )
        rendu = lettre(
            etat,
            {"diagnosis": "Un écart réel reste à examiner."},
            {"replay_errored_verdicts": 1},
            ecarts_url="https://sentimail.example/ecarts",
        )
        self.assertIn("Ce que tu dois faire", rendu.text)
        self.assertNotIn("le message livré mais jugé indésirable", rendu.text)
        self.assertNotIn("acquitte", rendu.text)
        self.assertIn("Informations, sans action requise", rendu.text)
        self.assertIn("9 alertes techniques ont été regroupées", rendu.text)
        self.assertIn("déjà tranchés par les destinataires", rendu.text)
        self.assertNotIn("alertes techniques étouffées", rendu.text)


class TraceTechniqueTests(unittest.TestCase):
    """L'état brut ne part plus par courrier : il vit dans audit_log.

    Le bloc « Détail technique » recopiait trente compteurs dans chaque
    lettre, que personne ne lisait et que caretaker.run journalise déjà
    intégralement en base avant l'envoi. Le courrier reste entièrement
    rédigé ; l'audit se consulte là où il vit.
    """

    def test_aucun_etat_brut_dans_le_courrier(self) -> None:
        for state in (CALME, BLOQUE, REFUS_DEFINITIF, PANNE_REPARABLE):
            rendu = lettre(state, DIAGNOSTIC, {})
            self.assertNotIn("Détail technique", rendu.text)
            self.assertNotIn("{", rendu.text)
            self.assertNotIn("retenues_sans_avis", rendu.text)
            self.assertNotIn("Détail technique", rendu.html)
            self.assertNotIn("retenues_sans_avis", rendu.html)


if __name__ == "__main__":
    unittest.main()
