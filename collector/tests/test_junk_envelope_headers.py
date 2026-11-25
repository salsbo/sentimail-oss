"""L'enveloppe des indésirables se compose quels que soient les en-têtes d'origine.

Un mot encodé qui se décode en saut de ligne faisait échouer l'enveloppe : la
bibliothèque refuse de reposer un tel objet, et refuse même de lire une adresse
qui en contient. Le message partait alors annoté, liens actifs, sans trace.
"""

from __future__ import annotations

import unittest
from email import policy
from email.parser import BytesParser

from sentimail_v3.execution.delivery import build_junk_envelope

LIEN = "https://payer.exp.example/regler?id=1"


def _brut(**entetes: bytes) -> bytes:
    valeurs = {
        b"From": b"Service <service@exp.example>",
        b"To": b"personne@dest.example",
        b"Reply-To": b"retour@exp.example",
        b"Subject": b"Votre facture",
        b"Message-ID": b"<abc@exp.example>",
    }
    for nom, valeur in entetes.items():
        valeurs[nom.replace("_", "-").encode()] = valeur
    lignes = b"".join(nom + b": " + valeur + b"\r\n" for nom, valeur in valeurs.items())
    return (
        lignes
        + b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        + f'<html><body><p>Reglez ici.</p><a href="{LIEN}">Payer</a></body></html>\r\n'.encode()
    )


def _rendu(raw: bytes) -> bytes:
    return build_junk_envelope(
        raw,
        "malicious",
        reasons=["Authentification : échec"],
        lessons=[],
        preview=None,
        action_address="maia@sentinel.dest.example",
        assistant_sender="MAIA - SentiMail <maia@dest.example>",
        recipient="personne@dest.example",
    )


def _enveloppe(raw: bytes):
    return BytesParser(policy=policy.default).parsebytes(_rendu(raw))


class EnTetesPiegesTests(unittest.TestCase):
    def test_un_objet_finissant_par_un_saut_de_ligne_ne_fait_plus_echouer_l_enveloppe(
        self,
    ) -> None:
        enveloppe = _enveloppe(_brut(Subject=b"=?utf-8?q?Voyage_sans_limites=0A=0A?="))
        self.assertEqual(
            str(enveloppe["Subject"]), "[SentiMail] Indésirable - Voyage sans limites"
        )

    def test_un_objet_crlf_n_injecte_aucun_en_tete(self) -> None:
        enveloppe = _enveloppe(_brut(Subject=b"=?utf-8?q?Facture=0D=0AX-Injected:_1?="))
        self.assertIsNone(enveloppe["X-Injected"])
        self.assertIn("Facture", str(enveloppe["Subject"]))

    def test_chaque_adresse_piegee_passe(self) -> None:
        piege = b"=?utf-8?q?Desk=0D=0AX-Injected:_1?= <a@exp.example>"
        for nom in ("From", "Reply_To", "To", "Cc"):
            with self.subTest(en_tete=nom):
                enveloppe = _enveloppe(_brut(**{nom: piege}))
                self.assertIsNone(enveloppe["X-Injected"])
                self.assertEqual(enveloppe["X-SentiMail-Modified"], "junk-envelope")
                original = enveloppe["X-SentiMail-Original-" + nom.replace("_", "-").title()]
                self.assertIn("a@exp.example", str(original))
                self.assertNotIn("\n", str(original))

    def test_un_message_id_piege_reste_sur_une_ligne(self) -> None:
        enveloppe = _enveloppe(_brut(Message_ID=b"=?utf-8?q?abc=0D=0AX-Injected:_1?="))
        self.assertIsNone(enveloppe["X-Injected"])
        valeur = str(enveloppe["X-SentiMail-Original-Message-Id"])
        self.assertIn("abc", valeur)
        self.assertNotIn("\n", valeur)
        self.assertNotIn("\r", valeur)

    def test_le_lien_d_origine_n_est_pas_transmis(self) -> None:
        rendu = _rendu(_brut(Subject=b"=?utf-8?q?Voyage_sans_limites=0A=0A?="))
        self.assertNotIn(LIEN.encode(), rendu)
        self.assertNotIn(b"payer.exp.example", rendu)


if __name__ == "__main__":
    unittest.main()
