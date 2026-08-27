from __future__ import annotations

import re
import unittest
from urllib.parse import parse_qs, urlsplit

from sentimail_v3.conversation.conversation import strip_quoted_reply
from sentimail_v3.conversation.provider_setup import (
    _provider,
    bootstrap_body,
    bootstrap_choice_links,
)

ADRESSE = "maia@sentinel.mondomaine.example"


def _corps_prerempli(fournisseur: str) -> str:
    lien = bootstrap_choice_links(ADRESSE)[fournisseur]
    return parse_qs(urlsplit(lien).query)["body"][0]


class ReponsePreteTests(unittest.TestCase):
    """La lettre doit porter la réponse, pas seulement la décrire.

    Le 18 août, Alex a répondu en joignant l'archive sans écrire le nom du
    fournisseur. Le collector a refusé en 550, et sa clé est repartie dans un
    rapport de non-remise. Demander à quelqu'un d'écrire exactement un mot
    parmi trois, sans le lui préparer, c'est fabriquer l'erreur.
    """

    def test_chaque_fournisseur_a_son_lien(self) -> None:
        liens = bootstrap_choice_links(ADRESSE)
        self.assertEqual(sorted(liens), ["chatgpt", "claude", "deepseek"])

    def test_le_corps_prerempli_ne_nomme_qu_un_fournisseur(self) -> None:
        # C'est tout l'enjeu : un texte qui cite les trois est refusé aussi,
        # parce que le collector ne sait alors pas lequel choisir.
        for fournisseur in ("deepseek", "claude", "chatgpt"):
            with self.subTest(fournisseur=fournisseur):
                self.assertIsNotNone(_provider(_corps_prerempli(fournisseur)))

    def test_le_fournisseur_reconnu_est_bien_celui_choisi(self) -> None:
        attendus = {"deepseek": "deepseek", "claude": "anthropic", "chatgpt": "openai"}
        for choisi, attendu in attendus.items():
            with self.subTest(choisi=choisi):
                self.assertEqual(_provider(_corps_prerempli(choisi)), attendu)

    def test_le_nom_survit_au_retrait_de_la_citation(self) -> None:
        # Le nom doit être sur les premières lignes : après la citation, il
        # serait effacé avec elle.
        for fournisseur in ("deepseek", "claude", "chatgpt"):
            with self.subTest(fournisseur=fournisseur):
                corps = _corps_prerempli(fournisseur)
                cite = corps + "\n\nLe 18 août 2026, MAIA a écrit :\n> Choisis un moteur.\n"
                self.assertIsNotNone(_provider(strip_quoted_reply(cite)))

    def test_le_corps_rappelle_de_joindre_l_archive(self) -> None:
        # Un lien mailto ne peut pas attacher de fichier : il faut le dire.
        corps = _corps_prerempli("deepseek").casefold()
        self.assertIn("zip", corps)


class LettreSansPiegeTests(unittest.TestCase):
    """Le texte de la lettre ne doit pas saboter la réponse qu'il demande."""

    def _lettre(self) -> str:
        return bootstrap_body(ADRESSE)

    def test_chaque_nom_reste_seul_sur_sa_ligne(self) -> None:
        # C'est ce qui rend la lettre sûre à citer : même recopiée en entier
        # dans une réponse, aucune de ses lignes ne nomme deux fournisseurs,
        # donc aucune ne peut être lue comme un choix ambigu.
        for ligne in self._lettre().splitlines():
            noms = [n for n in ("deepseek", "claude", "chatgpt") if n in ligne.casefold()]
            with self.subTest(ligne=ligne[:40]):
                self.assertLessEqual(len(noms), 1)

    def test_une_ligne_ambigue_n_est_jamais_tranchee(self) -> None:
        self.assertIsNone(_provider("DeepSeek plutôt que Claude"))

    def test_la_premiere_ligne_sans_ambiguite_fait_foi(self) -> None:
        self.assertEqual(_provider("Claude\n\nDeepSeek ou ChatGPT sinon"), "anthropic")

    def test_la_lettre_porte_les_trois_liens(self) -> None:
        lettre = self._lettre()
        for fournisseur in ("deepseek", "claude", "chatgpt"):
            with self.subTest(fournisseur=fournisseur):
                self.assertIn(fournisseur, lettre.casefold())

    def test_la_lettre_dit_encore_quoi_faire_de_la_cle(self) -> None:
        lettre = self._lettre().casefold()
        self.assertIn("cle-api.txt", lettre)
        self.assertIn("mot de passe", lettre)

    def test_la_lettre_reste_lisible_en_texte_seul(self) -> None:
        # Aucun HTML : cette lettre part avant toute mise en forme.
        self.assertNotIn("<", self._lettre())


if __name__ == "__main__":
    unittest.main()
