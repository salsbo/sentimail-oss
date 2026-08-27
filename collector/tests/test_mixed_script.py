"""Un mot qui mélange deux alphabets ne s'écrit pas, il se déguise.

Le 20/08, « Doc 6EM2A8TM8 - … your on-record prіority order documеnt һaѕ been
bookmarked in your portal » est parti en boîte de réception avec un verdict
légitime : le і, le е, le һ et le ѕ sont cyrilliques, indiscernables à l'œil
de leurs sosies latins, et aucun article ne constatait ce mélange. Un texte
entièrement russe ou grec est une langue ; un mot qui alterne latin et
cyrillique est un contournement de filtre, il n'existe dans aucune langue.
"""

from __future__ import annotations

import unittest

from sentimail_v3.observation.dossier.hooks.content import (
    ContentHook,
    _mixed_script_words,
)
from sentimail_v3.observation.dossier.models import InvestigationContext
from sentimail_v3.observation.parser import parse_message

# і U+0456, е U+0435, һ U+04BB, ѕ U+0455 : cyrilliques, sosies de i, e, h, s.
SUJET_PIEGE = (
    "Doc 6EM2A8TM8 - Just now: your on-record prіority order "
    "documеnt һaѕ been bookmarked in your portal"
)


class MelangeDEcrituresTests(unittest.TestCase):
    def test_un_mot_melant_latin_et_cyrillique_est_releve(self) -> None:
        mots = [releve["word"] for releve in _mixed_script_words(SUJET_PIEGE)]
        self.assertIn("prіority", mots)
        self.assertIn("documеnt", mots)
        self.assertIn("һaѕ", mots)

    def test_un_texte_francais_accentue_ne_releve_rien(self) -> None:
        # Les lettres accentuées sont latines : aucune écriture n'est mélangée.
        self.assertEqual(
            _mixed_script_words("Voici le résumé de l'été, café à l'appui."), []
        )

    def test_un_texte_entierement_cyrillique_ne_releve_rien(self) -> None:
        # Une langue entière n'est pas un déguisement.
        self.assertEqual(
            _mixed_script_words("Здравствуйте, это обычное письмо о встрече"), []
        )

    def test_un_texte_entierement_grec_ne_releve_rien(self) -> None:
        self.assertEqual(_mixed_script_words("Καλημέρα σας, τι κάνετε σήμερα"), [])

    def test_un_mot_melant_latin_et_grec_est_releve(self) -> None:
        # ρ U+03C1 : rho grec, sosie du p latin.
        mots = [releve["word"] for releve in _mixed_script_words("payρal support")]
        self.assertIn("payρal", mots)

    def test_deux_ecritures_dans_deux_mots_distincts_ne_relevent_rien(self) -> None:
        # Une citation bilingue alterne les écritures ENTRE les mots.
        self.assertEqual(_mixed_script_words("Bonjour привет hello"), [])


class ClueDuHookTests(unittest.IsolatedAsyncioTestCase):
    async def _codes(self, subject: str) -> dict[str, str]:
        raw = (
            "From: Alex Exemple <stephan@example.org>\r\n"
            "To: Me <me@mondomaine.example>\r\n"
            f"Subject: {subject}\r\n"
            "Date: Thu, 20 Aug 2026 16:00:00 +0000\r\n"
            "Message-ID: <one@example.org>\r\n"
            "\r\n"
            "corps ordinaire\r\n"
        ).encode()
        context = InvestigationContext(
            raw, parse_message(raw), "stephan@example.org", ["me@mondomaine.example"]
        )
        clues, _ = await ContentHook().observe(context)
        return {clue.clue_code: clue.direction for clue in clues}

    async def test_le_sujet_piege_pose_un_indice_adverse(self) -> None:
        codes = await self._codes(SUJET_PIEGE)
        self.assertEqual(codes.get("CONTENT_MIXED_SCRIPT"), "adverse")

    async def test_un_sujet_ordinaire_ne_pose_rien(self) -> None:
        codes = await self._codes("Votre commande est prête")
        self.assertNotIn("CONTENT_MIXED_SCRIPT", codes)


if __name__ == "__main__":
    unittest.main()
