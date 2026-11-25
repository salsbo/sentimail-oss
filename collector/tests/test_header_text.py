"""Un en-tête d'origine se relit sur une ligne, quoi que cache son encodage.

Un mot encodé (RFC 2047) peut se décoder en saut de ligne. La bibliothèque
refuse alors de reposer la valeur dans un autre courrier, et refuse même de
lire une adresse qui en contient. L'enveloppe des indésirables échouait ainsi
sans rien dire.
"""

from __future__ import annotations

import unittest
from email import policy
from email.parser import BytesParser

from sentimail_v3.execution.header_text import header_text, une_ligne


def _message(*lines: bytes):
    raw = b"".join(line + b"\r\n" for line in lines) + b"\r\ncorps\r\n"
    return BytesParser(policy=policy.default).parsebytes(raw)


class UneLigneTests(unittest.TestCase):
    def test_les_sauts_de_ligne_deviennent_des_blancs(self) -> None:
        self.assertEqual(une_ligne("Facture\r\nX-Injected: 1\n\n"), "Facture X-Injected: 1")

    def test_une_valeur_non_textuelle_se_lit_en_texte(self) -> None:
        self.assertEqual(une_ligne(42), "42")


class HeaderTextTests(unittest.TestCase):
    def test_un_objet_encode_en_saut_de_ligne_se_lit_sur_une_ligne(self) -> None:
        message = _message(b"Subject: =?utf-8?q?Voyage_sans_limites=0A=0A?=")
        self.assertEqual(header_text(message, "subject"), "Voyage sans limites")

    def test_une_adresse_piegee_se_relit_brute_et_decodee(self) -> None:
        # La lecture normale lève pour une adresse : c'est la relecture brute
        # qui la rend, décodée puis remise sur une ligne.
        message = _message(b"From: =?utf-8?q?Desk=0D=0AX:_1?= <a@exp.example>")
        valeur = header_text(message, "from")
        self.assertIsNotNone(valeur)
        self.assertIn("a@exp.example", str(valeur))
        self.assertNotIn("\r", str(valeur))
        self.assertNotIn("\n", str(valeur))

    def test_le_nom_de_l_en_tete_ne_depend_pas_de_la_casse(self) -> None:
        message = _message(b"REPLY-TO: =?utf-8?q?Desk=0D=0AX:_1?= <a@exp.example>")
        self.assertIn("a@exp.example", str(header_text(message, "reply-to")))

    def test_un_en_tete_absent_rend_none(self) -> None:
        message = _message(b"Subject: bonjour")
        self.assertIsNone(header_text(message, "reply-to"))

    def test_un_charset_inconnu_se_rend_tel_quel(self) -> None:
        # Ni la lecture normale ni le décodage ne savent faire : la valeur
        # brute reste, sur une ligne, plutôt que rien.
        message = _message(b"From: =?x-bogus?q?Desk=0D=0AX:_1?= <a@exp.example>")
        self.assertEqual(
            header_text(message, "from"),
            "=?x-bogus?q?Desk=0D=0AX:_1?= <a@exp.example>",
        )

    def test_un_en_tete_ordinaire_passe_inchange(self) -> None:
        message = _message(b"Subject: Bonjour =?utf-8?q?=C3=A0_tous?=")
        self.assertEqual(header_text(message, "subject"), "Bonjour à tous")


if __name__ == "__main__":
    unittest.main()
