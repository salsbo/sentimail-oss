from __future__ import annotations

import unittest

from sentimail_v3.supervision.caretaker import (
    disagreement_directions,
    worth_reporting,
)


class DisagreementDirectionTests(unittest.TestCase):
    """Deux désaccords de sens contraire ne s'additionnent pas."""

    def test_un_indesirable_soumis_a_l_humain_est_un_exces_de_prudence(self) -> None:
        lecture = disagreement_directions(
            [{"humain": "spam", "modele": "suspect", "count": 14}]
        )
        self.assertEqual(lecture["demande_au_lieu_de_classer"], 14)
        self.assertEqual(lecture["demande_au_lieu_de_livrer"], 0)

    def test_un_legitime_soumis_a_l_humain_est_un_exces_de_zele(self) -> None:
        lecture = disagreement_directions(
            [{"humain": "legitimate", "modele": "suspect", "count": 12}]
        )
        self.assertEqual(lecture["demande_au_lieu_de_livrer"], 12)
        self.assertEqual(lecture["demande_au_lieu_de_classer"], 0)

    def test_les_deux_sens_restent_separes(self) -> None:
        # C'est tout l'enjeu : additionner les deux ferait recommander un
        # reglage de seuil qui aggraverait forcement l'un des deux.
        lecture = disagreement_directions(
            [
                {"humain": "spam", "modele": "suspect", "count": 14},
                {"humain": "legitimate", "modele": "suspect", "count": 12},
                {"humain": "legitimate", "modele": "undetermined", "count": 7},
            ]
        )
        self.assertEqual(lecture["demande_au_lieu_de_classer"], 14)
        self.assertEqual(lecture["demande_au_lieu_de_livrer"], 19)

    def test_un_legitime_juge_dangereux_est_une_erreur_de_detection(self) -> None:
        lecture = disagreement_directions(
            [{"humain": "legitimate", "modele": "dangerous", "count": 1}]
        )
        self.assertEqual(lecture["erreur_de_qualification"], 1)

    def test_un_indesirable_juge_legitime_est_un_manque(self) -> None:
        lecture = disagreement_directions(
            [{"humain": "spam", "modele": "legitimate", "count": 3}]
        )
        self.assertEqual(lecture["laisse_passer"], 3)

    def test_sans_desaccord_toutes_les_directions_sont_nulles(self) -> None:
        self.assertEqual(
            set(disagreement_directions([]).values()),
            {0},
        )


class ReportingScopeTests(unittest.TestCase):
    def test_un_destinataire_inexistant_ne_vaut_pas_rapport(self) -> None:
        """Un spam adresse a une boite qui n'existe pas est un non-evenement.

        Le systeme a conclu le dossier ; rapporter cela ferait croire a une
        anomalie a corriger, et la seule « correction » possible serait de
        creer la boite - c'est-a-dire d'ouvrir une porte au spammeur.
        """
        etat = {
            "verdicts_en_erreur_24h": 1,
            "livraisons_differees": 0,
            "dossiers_coinces": 0,
            "retenues_sans_avis": 0,
            "erreurs_de_verdict_24h": [
                {
                    "error_type": "SMTPRecipientsRefused",
                    "detail": "550 5.1.1 Recipient address rejected: User unknown",
                    "count": 1,
                }
            ],
            "desaccords_humain_modele_7j": [],
        }
        self.assertFalse(worth_reporting(etat))

    def test_une_vraie_panne_de_verdict_vaut_toujours_rapport(self) -> None:
        etat = {
            "verdicts_en_erreur_24h": 3,
            "livraisons_differees": 0,
            "dossiers_coinces": 0,
            "retenues_sans_avis": 0,
            "erreurs_de_verdict_24h": [
                {"error_type": "TimeoutError", "detail": "modele injoignable", "count": 3}
            ],
            "desaccords_humain_modele_7j": [],
        }
        self.assertTrue(worth_reporting(etat))

    def test_un_dossier_coince_vaut_toujours_rapport(self) -> None:
        self.assertTrue(
            worth_reporting(
                {
                    "verdicts_en_erreur_24h": 0,
                    "livraisons_differees": 0,
                    "dossiers_coinces": 2,
                    "retenues_sans_avis": 0,
                }
            )
        )


if __name__ == "__main__":
    unittest.main()


class PromptScopeTests(unittest.TestCase):
    """Un désaccord produit par une version retirée ne décrit plus le système."""

    def test_la_requete_ne_regarde_que_le_prompt_actif(self) -> None:
        from sentimail_v3.supervision.caretaker import collect
        import inspect

        source = inspect.getsource(collect)
        self.assertIn("prompt_version", source)
        self.assertIn("PROMPT_VERSION", source)


class EmpreinteDuRapportTests(unittest.TestCase):
    """Un état inchangé ne mérite pas un second courrier.

    Le 20/08 au soir, six déploiements successifs ont redémarré l'entretien,
    et chaque démarrage a renvoyé le même rapport « signalement faible » -
    deux fois à la même heure. L'empreinte de l'état signalé permet de se
    taire tant que rien n'a changé.
    """

    def test_le_meme_etat_donne_la_meme_empreinte(self) -> None:
        from sentimail_v3.supervision.caretaker import report_fingerprint

        etat = {
            "verdicts_en_erreur_24h": 4,
            "erreurs_de_verdict_24h": [{"error_type": "X", "count": 4}],
            "sens_des_desaccords_7j": {"demande_au_lieu_de_livrer": 7},
            "dossiers_coinces": 0,
        }
        self.assertEqual(report_fingerprint(etat), report_fingerprint(dict(etat)))

    def test_un_compteur_change_change_l_empreinte(self) -> None:
        from sentimail_v3.supervision.caretaker import report_fingerprint

        etat = {"verdicts_en_erreur_24h": 4, "dossiers_coinces": 0}
        autre = dict(etat, dossiers_coinces=2)
        self.assertNotEqual(report_fingerprint(etat), report_fingerprint(autre))

    def test_une_nouvelle_erreur_change_l_empreinte(self) -> None:
        from sentimail_v3.supervision.caretaker import report_fingerprint

        etat = {"erreurs_de_verdict_24h": [{"error_type": "KeyError", "count": 2}]}
        autre = {"erreurs_de_verdict_24h": [{"error_type": "KeyError", "count": 3}]}
        self.assertNotEqual(report_fingerprint(etat), report_fingerprint(autre))


class ClientSansTimeoutTests(unittest.TestCase):
    """Le client HTTP du diagnostic doit porter un timeout explicite.

    Le défaut httpx (5 s) coupait la lecture du corps pendant que le modèle
    répondait : les en-têtes arrivaient, le rapport concluait « aucun modèle
    joignable ». Un client nu dans ce module est donc une régression.
    """

    def test_aucun_client_httpx_sans_timeout(self) -> None:
        import inspect

        from sentimail_v3.supervision import caretaker

        source = inspect.getsource(caretaker)
        self.assertNotIn("httpx.AsyncClient()", source)


class RejeuAvecCleTests(unittest.IsolatedAsyncioTestCase):
    """Le rejeu automatisé doit transmettre la clé de déchiffrement.

    La CLI la passait, l'agent non : un message chiffré au repos était
    rejouable à la main mais jamais par l'entretien, qui échouait en
    DecryptionError à chaque cycle.
    """

    async def test_le_rejeu_transmet_la_cle(self) -> None:
        import tempfile
        from types import SimpleNamespace
        from unittest.mock import AsyncMock, patch

        from sentimail_v3.supervision import caretaker

        class _Pool:
            async def fetch(self, query, *args):
                return [{"message_id": "11111111-1111-1111-1111-111111111111"}]

        with tempfile.NamedTemporaryFile(suffix=".key", delete=False) as f:
            f.write(b"a" * 64)  # 32 octets encodés hex
            chemin = f.name
        settings = SimpleNamespace(raw_eml_key_file=chemin)
        rejoue = AsyncMock()
        with patch("sentimail_v3.supervision.replay.replay_case", rejoue):
            await caretaker._replay_errored(_Pool(), settings)  # type: ignore[arg-type]
        self.assertTrue(rejoue.await_count == 1)
        cle = rejoue.await_args.kwargs.get("encryption_key")
        self.assertIsInstance(cle, bytes)
        self.assertEqual(len(cle), 32)
