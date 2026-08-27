from __future__ import annotations

import pathlib
import re
import unittest

from sentimail_v3.code.attachment_facts import MATERIAL_ARTICLES, attachment_clues


def _piece(code: str, severity: str = "critical") -> dict[str, object]:
    return {
        "filename": "facture.docm",
        "findings": [{"code": code, "severity": severity}],
    }


class BarriereMaterielleTests(unittest.TestCase):
    """DEEP-004 portait la barrière ; les constats nommés l'ont remplacé.

    En nommant les constats, l'article global a disparu du dossier - et avec
    lui la barrière de livraison qu'il portait. Un document à macro shell
    produisait donc une charge de 95 sans plus rien interdire.
    """

    def test_une_macro_qui_lance_un_shell_est_materielle(self) -> None:
        clue = attachment_clues([_piece("OFFICE_SHELL_EXEC")])[0]
        self.assertIn(clue["article_code"], MATERIAL_ARTICLES)

    def test_une_signature_de_code_malveillant_est_materielle(self) -> None:
        clue = attachment_clues([_piece("YARA_suspicious_macro")])[0]
        self.assertIn(clue["article_code"], MATERIAL_ARTICLES)

    def test_un_executable_dans_une_archive_est_materiel(self) -> None:
        clue = attachment_clues([_piece("ARCHIVE_DANGEROUS_MEMBER_EXTENSION", "high")])[0]
        self.assertIn(clue["article_code"], MATERIAL_ARTICLES)

    def test_une_macro_a_execution_automatique_est_materielle(self) -> None:
        clue = attachment_clues([_piece("OFFICE_AUTO_EXEC", "high")])[0]
        self.assertIn(clue["article_code"], MATERIAL_ARTICLES)

    def test_un_document_a_macros_ordinaire_n_est_pas_materiel(self) -> None:
        # Les macros sont banales en entreprise : poser une barrière ici
        # ferait demander un avis sur du courrier de travail courant.
        clue = attachment_clues([_piece("OFFICE_HAS_MACROS", "medium")])[0]
        self.assertNotIn(clue["article_code"], MATERIAL_ARTICLES)

    def test_une_archive_chiffree_n_est_pas_materielle(self) -> None:
        # Un mot de passe empêche de vérifier ; il n'établit aucun dommage.
        clue = attachment_clues([_piece("ARCHIVE_ENCRYPTED_ENTRY", "high")])[0]
        self.assertNotIn(clue["article_code"], MATERIAL_ARTICLES)

    def test_une_limite_d_analyse_n_est_jamais_materielle(self) -> None:
        clue = attachment_clues([_piece("PDF_PARSE_ERROR", "medium")])[0]
        self.assertNotIn(clue["article_code"], MATERIAL_ARTICLES)


class MigrationTests(unittest.TestCase):
    def test_la_barriere_est_declaree_en_base_pour_ces_articles(self) -> None:
        """Une barrière que la base ignore ne barre rien."""
        racine = pathlib.Path(__file__).resolve().parents[2] / "database" / "init"
        declares: set[str] = set()
        for fichier in sorted(racine.glob("*.sql")):
            texte = fichier.read_text("utf-8")
            if "material_danger" not in texte:
                continue
            for bloc in re.findall(r"WHERE article_code IN \(([^)]*)\)", texte):
                declares.update(re.findall(r"'([A-Z][A-Z0-9-]*)'", bloc))
        manquants = sorted(MATERIAL_ARTICLES - declares)
        self.assertEqual(manquants, [], f"barrière non déclarée en base : {manquants}")


if __name__ == "__main__":
    unittest.main()
