from __future__ import annotations

import unittest

from sentimail_v3.code.one_time_code import excusable_static_risk


class RaccourcisseurDeLExpediteurTests(unittest.TestCase):
    """Un raccourcisseur ne masque rien quand il appartient à celui qui écrit.

    « raccourcisseur masquant la destination » est un motif juste : bit.ly
    peut mener n'importe où, et c'est bien le problème. Mais t.co appartient à
    X, et un lien t.co dans un message de X ne dissimule pas plus que x.com.

    L'assouplissement est étroit à dessein. Il exige trois choses ensemble :
    que le raccourcisseur soit le seul motif de risque, qu'il relève du même
    maître que l'expéditeur, et que cette appartenance soit attestée - par la
    délégation DNS ou par un titulaire déclaré, jamais supposée.
    """

    def _facts(self, apex: str, reasons: list[str]) -> dict[str, object]:
        return {"apex": apex, "reasons": reasons, "reason_count": len(reasons)}

    def test_le_raccourcisseur_du_meme_maitre_est_excuse(self) -> None:
        self.assertTrue(
            excusable_static_risk(
                [self._facts("t.co", ["raccourcisseur masquant la destination"])],
                sender_apex="x.com",
                organisations={
                    "x.com": {"ns:twtrdns.net"},
                    "t.co": {"ns:twtrdns.net"},
                },
            )
        )

    def test_un_raccourcisseur_tiers_n_est_jamais_excuse(self) -> None:
        self.assertFalse(
            excusable_static_risk(
                [self._facts("bit.ly", ["raccourcisseur masquant la destination"])],
                sender_apex="x.com",
                organisations={"x.com": {"ns:twtrdns.net"}},
            )
        )

    def test_sans_appartenance_attestee_rien_n_est_excuse(self) -> None:
        # L'absence de preuve n'est pas une preuve d'appartenance.
        self.assertFalse(
            excusable_static_risk(
                [self._facts("t.co", ["raccourcisseur masquant la destination"])],
                sender_apex="x.com",
                organisations={},
            )
        )

    def test_un_second_motif_referme_l_excuse(self) -> None:
        # Le raccourcisseur seul s'explique ; accompagné d'un nom
        # internationalisé ou d'une extension détournée, il ne s'explique plus.
        self.assertFalse(
            excusable_static_risk(
                [
                    self._facts(
                        "t.co",
                        [
                            "raccourcisseur masquant la destination",
                            "extension fréquemment détournée",
                        ],
                    )
                ],
                sender_apex="x.com",
                organisations={
                    "x.com": {"ns:twtrdns.net"},
                    "t.co": {"ns:twtrdns.net"},
                },
            )
        )

    def test_une_seule_url_etrangere_referme_l_excuse(self) -> None:
        self.assertFalse(
            excusable_static_risk(
                [
                    self._facts("t.co", ["raccourcisseur masquant la destination"]),
                    self._facts("bit.ly", ["raccourcisseur masquant la destination"]),
                ],
                sender_apex="x.com",
                organisations={
                    "x.com": {"ns:twtrdns.net"},
                    "t.co": {"ns:twtrdns.net"},
                },
            )
        )

    def test_sans_motif_enregistre_rien_n_est_excuse(self) -> None:
        # Les dossiers analysés avant l'enregistrement des motifs ne portent
        # pas l'information : on ne prend pas de raccourci sur du vide.
        self.assertFalse(
            excusable_static_risk(
                [{"apex": "t.co", "reason_count": 1}],
                sender_apex="x.com",
                organisations={
                    "x.com": {"ns:twtrdns.net"},
                    "t.co": {"ns:twtrdns.net"},
                },
            )
        )

    def test_sans_aucune_url_risquee_il_n_y_a_rien_a_excuser(self) -> None:
        self.assertFalse(
            excusable_static_risk([], sender_apex="x.com", organisations={})
        )


class MotifsEnregistresTests(unittest.TestCase):
    """Le motif du risque doit être écrit, pas seulement compté."""

    def test_le_hook_enregistre_les_motifs(self) -> None:
        import inspect

        from sentimail_v3.observation.dossier.hooks import urls

        source = inspect.getsource(urls)
        self.assertIn('"reasons"', source)



class ReferencesResoluesTests(unittest.TestCase):
    """Un nom non defini ne se voit qu'a l'execution, en production.

    Le 18 aout, un import manquant a fait rendre une erreur 500 a la console :
    les tests unitaires appellent les fonctions directement et ne traversent
    pas le module. Ce test verifie que tout ce que la voie rapide nomme existe
    reellement.
    """

    def test_tout_ce_que_la_voie_rapide_nomme_existe(self) -> None:
        from sentimail_v3.judgment import verdict_engine

        for nom in (
            "_facts_of",
            "excusable_static_risk",
            "_domain_organisations",
            "authentication_signature",
            "express_delivery_reason",
        ):
            with self.subTest(nom=nom):
                self.assertTrue(hasattr(verdict_engine, nom), f"{nom} absent")

if __name__ == "__main__":
    unittest.main()
