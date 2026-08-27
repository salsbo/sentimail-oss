from __future__ import annotations

import unittest
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

from sentimail_v3.execution.smtp_sender import require_sender


def _brut(entetes: str) -> bytes:
    return (entetes + "\r\nContent-Type: text/plain\r\n\r\nCorps\r\n").encode()


class AucunCourrierAnonymeTests(unittest.TestCase):
    """Aucun email ne doit partir sans expéditeur. Aucun, par aucun chemin.

    Deux fois dans la même journée, du courrier est parti de personne : les
    lettres de contrôle qualité, puis les avis d'indésirables, par deux chemins
    différents. Corriger chaque appelant l'un après l'autre laisse le suivant
    libre de recommencer.

    Le contrôle est donc au dernier goulot, celui que tout courrier sortant
    franchit : la remise au relais. Ce qui n'a pas d'expéditeur ne part pas.
    """

    def test_une_enveloppe_sans_from_est_refusee(self) -> None:
        with self.assertRaises(ValueError):
            require_sender(_brut("To: moi@mondomaine.example\r\nSubject: Test"), "moi@mondomaine.example")

    def test_un_from_vide_est_refuse(self) -> None:
        with self.assertRaises(ValueError):
            require_sender(
                _brut("From: \r\nTo: moi@mondomaine.example\r\nSubject: Test"), "moi@mondomaine.example"
            )

    def test_une_enveloppe_complete_passe(self) -> None:
        brut = _brut("From: MAIA <maia@mondomaine.example>\r\nTo: moi@mondomaine.example\r\nSubject: Test")
        self.assertEqual(require_sender(brut, "moi@mondomaine.example"), brut)

    def test_un_objet_email_est_accepte_comme_une_enveloppe_brute(self) -> None:
        # Les deux chemins d'envoi ne passent pas le meme type : l'un un
        # EmailMessage, l'autre des octets. Le controle vaut pour les deux.
        message = EmailMessage()
        message["From"] = "MAIA <maia@mondomaine.example>"
        message["To"] = "moi@mondomaine.example"
        message["Subject"] = "Test"
        message.set_content("Corps")
        self.assertIs(require_sender(message, "moi@mondomaine.example"), message)

    def test_un_objet_email_sans_from_est_refuse(self) -> None:
        message = EmailMessage()
        message["To"] = "moi@mondomaine.example"
        message.set_content("Corps")
        with self.assertRaises(ValueError):
            require_sender(message, "moi@mondomaine.example")

    def test_un_destinataire_manquant_est_refuse(self) -> None:
        brut = _brut("From: MAIA <maia@mondomaine.example>\r\nSubject: Test")
        with self.assertRaises(ValueError):
            require_sender(brut, "")

    def test_le_message_n_est_jamais_modifie(self) -> None:
        # Le controle refuse ou laisse passer ; il ne repare pas. Poser un
        # expediteur par defaut masquerait le defaut au lieu de le montrer.
        brut = _brut("From: MAIA <maia@mondomaine.example>\r\nTo: moi@mondomaine.example")
        rendu = require_sender(brut, "moi@mondomaine.example")
        self.assertEqual(
            str(BytesParser(policy=policy.default).parsebytes(rendu)["From"]),
            "MAIA <maia@mondomaine.example>",
        )


class BranchementTests(unittest.TestCase):
    """Le controle doit etre au goulot, pas seulement disponible."""

    def test_l_avis_d_indesirable_passe_par_le_controle(self) -> None:
        import inspect

        from sentimail_v3.execution import delivery

        self.assertIn("require_sender", inspect.getsource(delivery))

    def test_le_message_d_origine_n_est_jamais_refuse(self) -> None:
        """Un courrier entrant mal formé se relaie quand même.

        Le contrôle porte sur ce que SentiMail compose, pas sur ce qu'il
        transporte. Refuser un rapport de non-remise dépourvu d'en-tête
        « From » reviendrait à le perdre - exactement ce que la chaîne
        s'interdit.
        """
        import inspect

        from sentimail_v3.execution import delivery

        source = inspect.getsource(delivery)
        appel = source.index("await aiosmtplib.send(")
        self.assertNotIn("require_sender", source[appel:appel + 200])

    def test_la_file_de_l_assistante_passe_par_le_controle(self) -> None:
        import inspect

        from sentimail_v3.conversation import assistant

        self.assertIn("require_sender", inspect.getsource(assistant))


if __name__ == "__main__":
    unittest.main()
