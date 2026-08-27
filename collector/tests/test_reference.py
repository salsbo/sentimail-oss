"""La référence courte, et le nom qu'elle donne aux lignes de journal."""

from __future__ import annotations

import unittest

from sentimail_v3.code.reference import lire_reference, nommer_dossier, reference


class ReferenceTests(unittest.TestCase):
    _UUID = "e9e8f2cd-5c48-411b-87de-5b022f7b4f03"

    def test_la_reference_derive_de_l_identifiant(self) -> None:
        self.assertEqual(reference("M", self._UUID), "M-e9e8f2")

    def test_la_console_et_le_moteur_disent_la_meme_chose(self) -> None:
        # Les deux images n'ont pas de source commune : une référence citée
        # dans un avis doit se retrouver telle quelle dans la console.
        from pathlib import Path

        racine = Path(__file__).resolve().parents[2]
        moteur = (racine / "collector/src/sentimail_v3/code/reference.py").read_text(
            encoding="utf-8"
        )
        console = (racine / "admin/src/sentimail_admin/reference.py").read_text(
            encoding="utf-8"
        )
        for fonction in ("def reference(", "def lire_reference(", "def nommer_dossier("):
            with self.subTest(fonction=fonction):
                self.assertIn(fonction, moteur)
                self.assertIn(fonction, console)
        self.assertIn("LONGUEUR = 6", moteur)
        self.assertIn("LONGUEUR = 6", console)

    def test_une_reference_se_relit(self) -> None:
        self.assertEqual(lire_reference("M-e9e8f2"), ("M", "e9e8f2"))
        self.assertIsNone(lire_reference("pas une reference"))

    def test_le_journal_nomme_le_dossier_sans_perdre_l_identifiant(self) -> None:
        # L'identifiant reste parce qu'il est exact ; la référence vient à
        # côté parce que c'est elle qu'on lit.
        ligne = nommer_dossier({"event": "verdict.complete", "message_id": self._UUID})
        self.assertEqual(ligne["dossier"], "M-e9e8f2")
        self.assertEqual(ligne["message_id"], self._UUID)

    def test_une_capture_de_plusieurs_messages_les_nomme_tous(self) -> None:
        ligne = nommer_dossier(
            {"event": "message.captured", "message_ids": [self._UUID, self._UUID]}
        )
        self.assertEqual(ligne["dossier"], ["M-e9e8f2", "M-e9e8f2"])

    def test_une_ligne_sans_message_n_est_pas_touchee(self) -> None:
        ligne = {"event": "watchdog.cycle", "duration_ms": 12}
        self.assertEqual(nommer_dossier(dict(ligne)), ligne)

    def test_un_identifiant_illisible_ne_fabrique_pas_de_reference(self) -> None:
        ligne = {"event": "x", "message_id": "-"}
        self.assertNotIn("dossier", nommer_dossier(dict(ligne)))


if __name__ == "__main__":
    unittest.main()
