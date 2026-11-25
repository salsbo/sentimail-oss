"""Un mot que l'on casse à l'intérieur se lit encore, mais ne se cherche plus.

Le 30 octobre 2026, une arnaque à la carte Améli est partie en boîte de
réception avec un verdict légitime. Son objet écrivait « A′̍meli » (une prime et
un accent combinant au milieu du mot), son corps « com´mands », « T´ermius »,
« pas´swords » : un accent aigu glissé dans presque chaque mot. L'œil lit le
mot ordinaire, le filtre qui cherche « commands » ou « Améli » ne trouve rien.
Un courrier honnête ne fait pas cela ; l'apostrophe tapée avec l'accent aigu
(« l´été », « d´un ») reste, elle, un usage ordinaire.
"""

from __future__ import annotations

import unicodedata
import unittest

from sentimail_v3.observation.dossier.hooks.bruit_dans_les_mots import (
    mots_bruites,
    sans_bruit,
)

OBJET_PIEGE = "Renouvellement Carte A′̍meli: Message [ZQ]"
CORPS_PIEGE = (
    "Even term´inal gurus spe´nd t´ime sear´ching the web for "
    "com´plex com´mands. Enable AI-powered autoc´omplete in "
    "T´ermius. Pas´te sudo pas´swords."
)


class MotsBruitesTests(unittest.TestCase):
    def test_l_objet_piege_releve_un_mot_a_marque_combinante_orpheline(self) -> None:
        releves = mots_bruites(OBJET_PIEGE)
        self.assertEqual(len(releves), 1)
        self.assertTrue(releves[0]["orphan_mark"])
        self.assertIn("meli", releves[0]["word"])

    def test_le_corps_piege_releve_chaque_mot_coupe_par_un_accent_aigu(self) -> None:
        mots = [releve["word"] for releve in mots_bruites(CORPS_PIEGE)]
        self.assertGreaterEqual(len(mots), 8)
        self.assertIn("com´mands", mots)
        self.assertIn("T´ermius", mots)

    def test_l_apostrophe_tapee_avec_un_accent_aigu_ne_releve_rien(self) -> None:
        # Élision : une seule lettre (ou « qu ») avant le signe.
        self.assertEqual(
            mots_bruites("Je n´ai pas l´été d´un autre qu´eux."),
            [],
        )

    def test_aujourd_hui_ecrit_avec_un_accent_aigu_ne_releve_rien(self) -> None:
        self.assertEqual(mots_bruites("Nous sommes le 30, aujourd´hui."), [])

    def test_un_francais_accentue_normal_ne_releve_rien(self) -> None:
        self.assertEqual(
            mots_bruites("Voici le résumé de l'été, café à l'appui, où ça va."),
            [],
        )

    def test_un_texte_decompose_nfd_equivaut_a_son_texte_compose(self) -> None:
        # Les mails écrits sur macOS portent des accents en deux codepoints.
        nfd = unicodedata.normalize("NFD", "Voici le résumé de l'été et ça.")
        self.assertEqual(mots_bruites(nfd), [])

    def test_un_mot_vietnamien_decompose_ne_releve_rien(self) -> None:
        nfd = unicodedata.normalize("NFD", "Chào bạn, Việt Nam")
        self.assertEqual(mots_bruites(nfd), [])

    def test_une_apostrophe_typographique_ne_releve_rien(self) -> None:
        self.assertEqual(mots_bruites("l’assurance, d’abord, aujourd’hui"), [])

    def test_un_trait_d_union_ne_releve_rien(self) -> None:
        self.assertEqual(mots_bruites("c'est-à-dire un porte-monnaie"), [])


class SansBruitTests(unittest.TestCase):
    def test_le_bruit_retire_rend_le_mot_lisible_et_cherchable(self) -> None:
        texte = "com´mands sear´ching pas´swords T´ermius"
        self.assertEqual(sans_bruit(texte), "commands searching passwords Termius")

    def test_l_objet_piege_redevient_un_nom_cherchable(self) -> None:
        self.assertIn("Ameli", sans_bruit(OBJET_PIEGE))

    def test_une_elision_est_laissee_telle_quelle(self) -> None:
        self.assertEqual(sans_bruit("l´été"), "l´été")


class ContentClueTests(unittest.IsolatedAsyncioTestCase):
    async def _codes(self, subject: str, body: str, sender: str = "a@b.c"):
        from sentimail_v3.observation.dossier.hooks.content import ContentHook
        from sentimail_v3.observation.dossier.models import InvestigationContext
        from sentimail_v3.observation.parser import parse_message

        raw = (
            f"From: {sender}\r\nTo: me@mondomaine.example\r\n"
            f"Subject: {subject}\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Content-Transfer-Encoding: 8bit\r\n\r\n" + body + "\r\n"
        ).encode()
        ctx = InvestigationContext(raw, parse_message(raw), "a@b.c", ["me@mondomaine.example"])
        clues, _ = await ContentHook().observe(ctx)
        return {c.clue_code: c for c in clues}

    async def test_un_objet_a_marque_orpheline_declenche(self) -> None:
        codes = await self._codes(OBJET_PIEGE, "Bonjour.")
        self.assertIn("CONTENT_INTRAWORD_NOISE", codes)
        clue = codes["CONTENT_INTRAWORD_NOISE"]
        self.assertEqual(clue.direction, "adverse")
        self.assertEqual(clue.article_code, "CONTENT-017")
        self.assertGreaterEqual(clue.strength, 60)

    async def test_un_nom_affiche_coupe_declenche(self) -> None:
        codes = await self._codes("Bonjour", "Bonjour.", sender='"Cr\u00b4edit Mutuel" <a@b.c>')
        self.assertIn("CONTENT_INTRAWORD_NOISE", codes)

    async def test_un_corps_aux_mots_coupes_declenche(self) -> None:
        codes = await self._codes("Info", CORPS_PIEGE)
        self.assertIn("CONTENT_INTRAWORD_NOISE", codes)
        self.assertEqual(codes["CONTENT_INTRAWORD_NOISE"].strength, 80)

    async def test_deux_mots_coupes_dans_le_corps_ne_suffisent_pas(self) -> None:
        codes = await self._codes("Info", "Voici com\u00b4mands et pas\u00b4swords, bonne journ\u00e9e.")
        self.assertNotIn("CONTENT_INTRAWORD_NOISE", codes)

    async def test_un_courrier_francais_ordinaire_ne_declenche_pas(self) -> None:
        codes = await self._codes(
            "R\u00e9union de l\u00b4\u00e9quipe aujourd\u00b4hui",
            "Voici l\u00b4ordre du jour, d\u00b4abord le bilan de l\u00b4\u00e9t\u00e9.",
        )
        self.assertNotIn("CONTENT_INTRAWORD_NOISE", codes)


class LectureDeLOrganisationTests(unittest.TestCase):
    """Le lecteur d'organisation et la recherche reçoivent l'objet nettoyé."""

    def test_l_objet_et_le_nom_affiche_sont_lus_sans_les_signes_parasites(self) -> None:
        from types import SimpleNamespace

        from sentimail_v3.observation.deep_analysis import _display_name_of, _subject_of

        parsed = SimpleNamespace(
            message={
                "subject": OBJET_PIEGE,
                "from_header": '"Cr\u00b4edit Mu\u00b4tuel Ar\u00b4kea Banque" <a@b.c>',
            }
        )
        self.assertIn("Carte Ameli", _subject_of(parsed))
        self.assertNotIn("\u2032", _subject_of(parsed))
        self.assertEqual(_display_name_of(parsed), "Credit Mutuel Arkea Banque")


if __name__ == "__main__":
    unittest.main()
