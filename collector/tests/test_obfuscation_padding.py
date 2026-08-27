from __future__ import annotations

import unittest

from sentimail_v3.observation.dossier.hooks.content import (
    _obfuscation_markers,
    _splits_a_word,
)

ZWNJ = "‌"
BOM = "﻿"
RLO = "‮"


def _invisibles(markers: list[dict[str, object]]) -> int:
    return sum(m["type"] == "zero_width" for m in markers)


def _remplissage(markers: list[dict[str, object]]) -> int:
    return sum(m["type"] == "zero_width_padding" for m in markers)


class RemplissageDePreEnteteTests(unittest.TestCase):
    """Un caractère invisible entre deux mots ne cache rien.

    Tout emailing commercial intercale des caractères de largeur nulle après
    le texte d'aperçu, pour empêcher la boîte de réception de déborder sur le
    corps du message. Mesuré sur les 68 messages concernés : 5 636 caractères
    invisibles, dont 31 seulement coupaient un mot. Les autres pesaient une
    charge adverse jusqu'à 80 sur du courrier ordinaire, fermaient la voie
    rapide et faisaient demander un avis pour rien.
    """

    def test_le_remplissage_ordinaire_n_est_pas_de_l_offuscation(self) -> None:
        texte = "Bonjour," + (ZWNJ + " ") * 20 + "voici votre commande"
        self.assertEqual(_invisibles(_obfuscation_markers(texte)), 0)

    def test_le_remplissage_reste_compte_a_part(self) -> None:
        # Le fait reste observable : on le requalifie, on ne l'efface pas.
        texte = "Bonjour," + (ZWNJ + " ") * 20 + "voici votre commande"
        self.assertEqual(_remplissage(_obfuscation_markers(texte)), 20)

    def test_des_invisibles_consecutifs_restent_du_remplissage(self) -> None:
        # Certains emetteurs empilent les invisibles sans espace entre eux.
        texte = "Apercu" + ZWNJ * 12 + " suite du message"
        self.assertEqual(_invisibles(_obfuscation_markers(texte)), 0)

    def test_un_invisible_apres_une_espace_insecable_est_du_remplissage(self) -> None:
        texte = "Apercu\xa0" + ZWNJ + "\xa0 suite"
        self.assertEqual(_invisibles(_obfuscation_markers(texte)), 0)


class VraieOffuscationTests(unittest.TestCase):
    """Un caractère invisible au milieu d'un mot casse sa lecture.

    C'est l'attaque réelle : « paypal » écrit avec des invisibles se lit comme
    tel mais ne se cherche plus. La règle doit continuer de l'attraper.
    """

    def test_un_mot_coupe_est_signale(self) -> None:
        texte = "Connectez-vous a votre compte p" + ZWNJ + "a" + ZWNJ + "y" + ZWNJ + "pal"
        self.assertGreaterEqual(_invisibles(_obfuscation_markers(texte)), 3)

    def test_un_domaine_coupe_est_signale(self) -> None:
        texte = "Rendez-vous sur paypal" + ZWNJ + ".com pour verifier"
        self.assertEqual(_invisibles(_obfuscation_markers(texte)), 1)

    def test_un_invisible_entre_deux_ponctuations_est_signale(self) -> None:
        # Deux caractères pleins de part et d'autre, quels qu'ils soient.
        self.assertEqual(_invisibles(_obfuscation_markers("a." + BOM + ".b")), 1)

    def test_le_controle_bidirectionnel_reste_materiel(self) -> None:
        # Renverser le sens de lecture n'a aucun usage de mise en page.
        markers = _obfuscation_markers("facture" + RLO + "gpj.exe")
        self.assertEqual(sum(m["type"] == "bidi_control" for m in markers), 1)


class ClassementTests(unittest.TestCase):
    """La règle se lit toute seule, sur la position de l'invisible."""

    def test_entre_deux_lettres_coupe_un_mot(self) -> None:
        self.assertTrue(_splits_a_word("a" + ZWNJ + "b", 1))

    def test_apres_une_espace_ne_coupe_rien(self) -> None:
        self.assertFalse(_splits_a_word("a " + ZWNJ + "b", 2))

    def test_avant_une_espace_ne_coupe_rien(self) -> None:
        self.assertFalse(_splits_a_word("a" + ZWNJ + " b", 1))

    def test_en_debut_de_texte_ne_coupe_rien(self) -> None:
        self.assertFalse(_splits_a_word(ZWNJ + "abc", 0))

    def test_en_fin_de_texte_ne_coupe_rien(self) -> None:
        self.assertFalse(_splits_a_word("abc" + ZWNJ, 3))

    def test_entre_deux_invisibles_ne_coupe_rien(self) -> None:
        self.assertFalse(_splits_a_word("a" + ZWNJ * 3 + "b", 2))

    def test_entre_deux_ponctuations_coupe(self) -> None:
        # Le critere est « plein », pas « alphanumerique » : « paypal‌.com »
        # doit compter, et son invisible cotoie un point.
        self.assertTrue(_splits_a_word("l" + ZWNJ + ".", 1))


if __name__ == "__main__":
    unittest.main()
