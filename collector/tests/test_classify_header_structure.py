from __future__ import annotations

import unittest
from email import policy
from email.parser import BytesParser

from sentimail_v3.execution.delivery import classify_header

BRUT = (
    b"From: expediteur@exemple.fr\r\n"
    b"To: operateur@mondomaine.example\r\n"
    b"Subject: Votre facture\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"\r\n"
    b"<html><body><p>Bonjour</p></body></html>\r\n"
)


class StructureTests(unittest.TestCase):
    """Un en-tête ajouté ne doit pas clore le bloc d'en-têtes.

    En insérant un séparateur complet, la fonction terminait les en-têtes
    aussitôt commencés : From, Subject et Content-Type basculaient dans le
    corps. Le message livré perdait son objet, son expéditeur, et son HTML
    n'était plus interprété - il arrivait sous forme de texte brut.
    """

    def _parse(self, verdict: str = "spam"):
        return BytesParser(policy=policy.default).parsebytes(
            classify_header(BRUT, verdict, reasons=["Motif."], techniques=["QUISHING"])
        )

    def test_l_objet_reste_un_entete(self) -> None:
        self.assertEqual(str(self._parse().get("subject")), "Votre facture")

    def test_l_expediteur_reste_un_entete(self) -> None:
        self.assertEqual(str(self._parse().get("from")), "expediteur@exemple.fr")

    def test_le_type_de_contenu_est_preserve(self) -> None:
        self.assertEqual(self._parse().get_content_type(), "text/html")

    def test_le_corps_ne_contient_pas_les_entetes(self) -> None:
        corps = self._parse().get_content()
        self.assertNotIn("Subject:", corps)
        self.assertNotIn("X-Sentimail-Verdict", corps)

    def test_le_verdict_est_lisible_comme_entete(self) -> None:
        self.assertEqual(str(self._parse().get("X-Sentimail-Verdict")), "spam")

    def test_le_motif_et_la_technique_sont_des_entetes(self) -> None:
        message = self._parse()
        self.assertIn("Motif.", str(message.get("X-Sentimail-Classification-Reason")))
        self.assertIn("QUISHING", str(message.get("X-Sentimail-Attack-Techniques")))

    def test_les_sauts_de_ligne_simples_fonctionnent_aussi(self) -> None:
        brut = b"From: a@b.test\nSubject: bonjour\n\nCorps.\n"
        message = BytesParser(policy=policy.default).parsebytes(
            classify_header(brut, "malicious")
        )
        self.assertEqual(str(message.get("subject")), "bonjour")
        self.assertIn("Corps.", message.get_content())

    def test_un_message_sans_corps_ne_casse_pas(self) -> None:
        message = BytesParser(policy=policy.default).parsebytes(
            classify_header(b"From: a@b.test\r\nSubject: x\r\n", "spam")
        )
        self.assertEqual(str(message.get("subject")), "x")


if __name__ == "__main__":
    unittest.main()
