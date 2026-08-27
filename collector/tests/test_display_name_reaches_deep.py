"""Le nom affiché doit arriver jusqu'aux enquêteurs qui le jugent.

Deux contrôles reposent entièrement sur lui : l'identité revendiquée, qui
compare ce nom au domaine, et la cohérence d'activité, à qui on le montre
depuis le 21 août pour qu'elle ne juge pas un propos hors de son porteur.

L'analyse profonde le lisait sous une clé que le parseur n'écrit pas : le nom
était donc toujours vide. L'identité revendiquée se déclarait « nom absent » et
n'a jamais posé sa question - aucun indice de sa part en production depuis sa
création - et la cohérence d'activité jugeait sans le nom qu'elle croyait voir.

Le test parse un vrai message plutôt que de vérifier une constante : c'est
l'accord entre celui qui écrit et celui qui lit qui manquait, et lui seul peut
manquer à nouveau.
"""

from __future__ import annotations

import unittest

from sentimail_v3.observation.deep_analysis import _display_name_of
from sentimail_v3.observation.parser import parse_message

MESSAGE = (
    b"From: DISNEY+ RECOVERY <contact@ecole-de-langue.example>\r\n"
    b"To: moi@mondomaine.example\r\n"
    b"Subject: Cher client Are you leaving us already ?\r\n"
    b"Date: Thu, 27 Aug 2026 01:05:00 +0000\r\n"
    b"Message-ID: <un@exemple.test>\r\n"
    b"\r\n"
    b"corps\r\n"
)


class NomAfficheTransmisTests(unittest.TestCase):
    def test_le_nom_affiche_arrive_a_l_analyse_profonde(self) -> None:
        self.assertEqual(_display_name_of(parse_message(MESSAGE)), "DISNEY+ RECOVERY")

    def test_un_message_sans_nom_affiche_rend_une_chaine_vide(self) -> None:
        brut = MESSAGE.replace(
            b"From: DISNEY+ RECOVERY <contact@ecole-de-langue.example>",
            b"From: contact@ecole-de-langue.example",
        )
        self.assertEqual(_display_name_of(parse_message(brut)), "")

    def test_un_nom_encode_est_lu_tel_que_le_destinataire_le_voit(self) -> None:
        brut = MESSAGE.replace(
            b"From: DISNEY+ RECOVERY <contact@ecole-de-langue.example>",
            b"From: =?utf-8?B?U8OpY3VyaXTDqQ==?= <contact@ecole-de-langue.example>",
        )
        self.assertEqual(_display_name_of(parse_message(brut)), "Sécurité")


if __name__ == "__main__":
    unittest.main()
