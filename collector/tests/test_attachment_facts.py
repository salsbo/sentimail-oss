from __future__ import annotations

import unittest

from sentimail_v3.code.attachment_facts import attachment_clues


def _piece(**champs: object) -> dict[str, object]:
    base: dict[str, object] = {
        "filename": "document.pdf",
        "mime": "application/pdf",
        "content_type": "application/pdf",
        "findings": [],
        "score": 0.0,
    }
    base.update(champs)
    return base


class MacroTests(unittest.TestCase):
    def test_un_document_a_macros_est_nomme(self) -> None:
        """Écrasé jusqu'ici dans un booléen, avec tout le reste."""
        clues = attachment_clues(
            [_piece(findings=[{"code": "OFFICE_HAS_MACROS", "severity": "medium"}])]
        )
        codes = {c["clue_code"] for c in clues}
        self.assertIn("ATTACHMENT_MACRO", codes)

    def test_une_macro_a_execution_automatique_pese_plus_lourd(self) -> None:
        auto = attachment_clues(
            [_piece(findings=[{"code": "OFFICE_AUTO_EXEC", "severity": "high"}])]
        )
        simple = attachment_clues(
            [_piece(findings=[{"code": "OFFICE_HAS_MACROS", "severity": "medium"}])]
        )
        self.assertGreater(int(auto[0]["strength"]), int(simple[0]["strength"]))

    def test_une_macro_qui_lance_un_shell_est_materielle(self) -> None:
        clues = attachment_clues(
            [_piece(findings=[{"code": "OFFICE_SHELL_EXEC", "severity": "critical"}])]
        )
        self.assertEqual(clues[0]["clue_code"], "ATTACHMENT_MACRO_SHELL")
        self.assertGreaterEqual(int(clues[0]["strength"]), 90)


class DocumentActifTests(unittest.TestCase):
    def test_un_pdf_avec_javascript_est_nomme(self) -> None:
        clues = attachment_clues(
            [_piece(findings=[{"code": "PDF_JAVASCRIPT", "severity": "high"}])]
        )
        self.assertEqual(clues[0]["clue_code"], "ATTACHMENT_ACTIVE_DOCUMENT")

    def test_un_pdf_qui_lance_un_programme_est_nomme(self) -> None:
        clues = attachment_clues(
            [_piece(findings=[{"code": "PDF_LAUNCH_ACTION", "severity": "critical"}])]
        )
        self.assertEqual(clues[0]["clue_code"], "ATTACHMENT_ACTIVE_DOCUMENT")


class ArchiveTests(unittest.TestCase):
    def test_une_archive_chiffree_est_nommee(self) -> None:
        """Le mot de passe empêche l'analyse : c'est le but recherché."""
        clues = attachment_clues(
            [_piece(findings=[{"code": "ARCHIVE_ENCRYPTED_ENTRY", "severity": "high"}])]
        )
        self.assertEqual(clues[0]["clue_code"], "ATTACHMENT_ENCRYPTED_ARCHIVE")

    def test_un_executable_dans_une_archive_est_nomme(self) -> None:
        clues = attachment_clues(
            [
                _piece(
                    findings=[
                        {"code": "ARCHIVE_DANGEROUS_MEMBER_EXTENSION", "severity": "high"}
                    ]
                )
            ]
        )
        self.assertEqual(clues[0]["clue_code"], "ATTACHMENT_EXECUTABLE_MEMBER")

    def test_un_taux_de_compression_anormal_est_nomme(self) -> None:
        clues = attachment_clues(
            [
                _piece(
                    findings=[
                        {"code": "ARCHIVE_COMPRESSION_RATIO_EXCEEDED", "severity": "high"}
                    ]
                )
            ]
        )
        self.assertEqual(clues[0]["clue_code"], "ATTACHMENT_COMPRESSION_ANOMALY")


class YaraTests(unittest.TestCase):
    def test_une_regle_yara_severe_est_materielle(self) -> None:
        clues = attachment_clues(
            [_piece(findings=[{"code": "YARA_suspicious_macro", "severity": "critical"}])]
        )
        self.assertEqual(clues[0]["clue_code"], "ATTACHMENT_YARA_MATCH")
        self.assertGreaterEqual(int(clues[0]["strength"]), 90)

    def test_une_regle_yara_informative_n_accuse_pas(self) -> None:
        # Le bac à sable émet des findings « info » pour tracer son travail :
        # les compter accuserait des pièces jointes parfaitement ordinaires.
        self.assertEqual(
            attachment_clues(
                [_piece(findings=[{"code": "YARA_base64_blob", "severity": "info"}])]
            ),
            [],
        )


class UrlEtQrTests(unittest.TestCase):
    def test_des_liens_dans_un_document_sont_constates(self) -> None:
        clues = attachment_clues(
            [_piece(extracted_urls=["https://exemple.fr/a"], extracted_urls_total=1)]
        )
        self.assertEqual(clues[0]["clue_code"], "ATTACHMENT_EMBEDDED_URL")
        self.assertEqual(clues[0]["direction"], "neutral")

    def test_un_document_sans_lien_ne_produit_rien(self) -> None:
        self.assertEqual(attachment_clues([_piece(extracted_urls=[])]), [])


class IncompletudeTests(unittest.TestCase):
    def test_une_analyse_impossible_est_une_limite_pas_une_charge(self) -> None:
        clues = attachment_clues([_piece(analysis_incomplete=True)])
        self.assertEqual(clues[0]["clue_code"], "ATTACHMENT_ANALYSIS_BLOCKED")
        self.assertEqual(clues[0]["direction"], "neutral")


class RobustesseTests(unittest.TestCase):
    def test_une_reponse_vide_ne_produit_rien(self) -> None:
        for valeur in ([], None, [{}], ["texte"]):
            with self.subTest(valeur=valeur):
                self.assertEqual(attachment_clues(valeur), [])

    def test_chaque_indice_cite_la_piece_concernee(self) -> None:
        clues = attachment_clues(
            [
                _piece(
                    filename="facture.docm",
                    findings=[{"code": "OFFICE_HAS_MACROS", "severity": "medium"}],
                )
            ]
        )
        self.assertEqual(clues[0]["facts"]["filename"], "facture.docm")

    def test_un_meme_constat_sur_deux_pieces_ne_double_pas_l_indice(self) -> None:
        # Deux documents à macros décrivent le même fait : un indice suffit,
        # et il compte les pièces concernées.
        clues = attachment_clues(
            [
                _piece(findings=[{"code": "OFFICE_HAS_MACROS", "severity": "medium"}]),
                _piece(
                    filename="autre.docm",
                    findings=[{"code": "OFFICE_HAS_MACROS", "severity": "medium"}],
                ),
            ]
        )
        self.assertEqual(len(clues), 1)
        self.assertEqual(clues[0]["facts"]["occurrences"], 2)


if __name__ == "__main__":
    unittest.main()


class BranchementTests(unittest.TestCase):
    """Une traduction non branchée ne sert à rien : la leçon d'hier."""

    def test_les_constats_arrivent_dans_les_signaux(self) -> None:
        from sentimail_v3.observation.deep_analysis import _signals

        signals = _signals(
            [],
            [
                {
                    "filename": "facture.docm",
                    "findings": [{"code": "OFFICE_AUTO_EXEC", "severity": "high"}],
                }
            ],
            {},
            True,
        )
        codes = {str(s.get("clue_code")) for s in signals}
        self.assertIn("ATTACHMENT_MACRO_AUTO", codes)

    def test_l_ancien_constat_global_ne_double_pas_les_nouveaux(self) -> None:
        # DEEP-004 disait « quelque chose de matériel » sans dire quoi. Les
        # constats nommés le remplacent : le garder ferait compter deux fois.
        from sentimail_v3.observation.deep_analysis import _signals

        signals = _signals(
            [],
            [
                {
                    "filename": "x.docm",
                    "score": 0.9,
                    "findings": [{"code": "OFFICE_SHELL_EXEC", "severity": "critical"}],
                }
            ],
            {},
            True,
        )
        articles = [str(s.get("article_code")) for s in signals]
        self.assertNotIn("DEEP-004", articles)
