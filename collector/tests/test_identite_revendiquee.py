from __future__ import annotations

import unittest


class SupervisionTests(unittest.TestCase):
    """Un enquêteur non supervisé peut cesser de tourner sans que rien ne le dise."""

    def test_l_enqueteur_est_inscrit_au_registre(self) -> None:
        from sentimail_v3.observation.deep_hooks import DEEP_HOOKS

        self.assertIn("sender_relation", [hook.name for hook in DEEP_HOOKS])

    def test_la_sonde_exige_son_passage(self) -> None:
        from sentimail_v3.supervision.watchdog import REQUIRED_DEEP_HOOKS

        self.assertIn("sender_relation", REQUIRED_DEEP_HOOKS)

    def test_chaque_enqueteur_du_registre_est_exige(self) -> None:
        from sentimail_v3.observation.deep_hooks import DEEP_HOOKS
        from sentimail_v3.supervision.watchdog import REQUIRED_DEEP_HOOKS

        self.assertEqual(
            sorted(hook.name for hook in DEEP_HOOKS), sorted(REQUIRED_DEEP_HOOKS)
        )


class LectureUniqueDuSiteTests(unittest.TestCase):
    """La page d'accueil est lue une fois, pas une fois par enquêteur."""

    def test_aucun_enqueteur_ne_va_chercher_le_site_lui_meme(self) -> None:
        import inspect

        from sentimail_v3.observation import deep_hooks

        source = inspect.getsource(deep_hooks)
        self.assertNotIn("_sender_site(", source)

    def test_l_indice_est_declare_en_mots_simples(self) -> None:
        from sentimail_v3.code.plain_words import _PLAIN

        self.assertIn("IDENTITY_CLAIMED_ORGANISATION_UNRELATED", _PLAIN)

    def test_l_article_a_une_famille(self) -> None:
        from sentimail_v3.code.families import _BY_ARTICLE

        self.assertIn("DEEP-021", _BY_ARTICLE)


if __name__ == "__main__":
    unittest.main()
