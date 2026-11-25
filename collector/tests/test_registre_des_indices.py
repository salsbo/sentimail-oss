"""Le registre des phrases ne promet pas un contrôle qui n'existe pas.

La revue du 29 septembre 2026 a trouvé dans `_PLAIN` six codes qu'aucun
détecteur n'émet et dont la base ne garde aucune ligne depuis le 11 août :
« pièce jointe reconnue comme malveillante », « lien répertorié comme
malveillant ». Qui lisait le registre pour savoir ce qui protège croyait à
des contrôles absents. À l'inverse, deux codes émis chaque jour n'avaient pas
de phrase et retombaient sur le repli.

Ce test tient le premier sens : toute phrase traduit un indice qu'un
producteur écrit, et toute pièce d'un faisceau a un producteur. Il ne vérifie
pas l'autre sens (un code émis sans phrase garde le repli, qui dit l'énoncé
du Code).
"""

from __future__ import annotations

import pathlib
import re
import unittest

from sentimail_v3.code import plain_words
from sentimail_v3.code import requested_action
from sentimail_v3.code.correlation import CORRELATIONS

RACINE = pathlib.Path(plain_words.__file__).resolve().parents[1]
# Ces fichiers lisent des codes sans en produire : les compter comme
# émetteurs rendrait le test aveugle à ce qu'il cherche.
_LECTEURS = {
    "code/plain_words.py",
    "code/correlation.py",
    "code/one_time_code.py",
    "judgment/verdict_engine.py",
    "code/families.py",
}
# Plus émis, encore en base jusqu'à la purge de rétention (180 jours) : la
# conversation et le récapitulatif relisent ces dossiers. À retirer après le
# 2027-02-23, avec IDENTITY_BRAND_MISMATCH dans _BORROWED_IDENTITY.
_HISTORIQUES = {
    "IDENTITY_BRAND_MISMATCH": "2026-08-27",
    "SENDER_SITE_CLAIMS_FOREIGN_BRAND": "2026-08-25",
}
# Retirés le 29 septembre 2026 : aucun émetteur, aucune ligne en base.
_SANS_EMETTEUR = (
    "ATTACHMENT_KNOWN_MALICIOUS",
    "CONTENT_COERCIVE_PRESSURE",
    "HISTORY_CONFIRMED_SENDER",
    "IDENTITY_DISPLAY_NAME_LOOKS_LIKE_ADDRESS",
    "URL_CLOAKING",
    "URL_KNOWN_MALICIOUS",
)
_LITTERAL = re.compile(r"[\"']([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)[\"']")


def _emis() -> set[str]:
    """Les codes qu'un producteur peut écrire au dossier."""
    codes: set[str] = set()
    for fichier in RACINE.rglob("*.py"):
        if fichier.relative_to(RACINE).as_posix() in _LECTEURS:
            continue
        codes |= set(_LITTERAL.findall(fichier.read_text(encoding="utf-8")))
    codes |= {rule.clue_code for rule in CORRELATIONS}
    # Deux familles de codes se composent au lieu de s'écrire en entier.
    codes |= {"ACTION_" + acte.upper() for acte in requested_action._ACTIONS}
    codes |= {f"AUTH_{controle}_INCONCLUSIVE" for controle in ("DMARC", "SPF", "DKIM")}
    return codes


def _registre() -> set[str]:
    pw = plain_words
    return (
        set(pw._PLAIN)
        | set(pw._SHORT)
        | set(pw._TELEGRAPHIQUE)
        | set(pw._PRECISIONS)
        | set(pw._AUTONOMES)
        | set(pw._IDENTITY_CARD_CODES)
        | set(pw._USURPATION)
        | set(pw._ABSORBES)
        | set(pw._OPERATIONAL)
        | set(pw._INCOMPLETENESS)
    )


class RegistreDesIndicesTests(unittest.TestCase):
    def test_la_lecture_des_sources_n_est_pas_aveugle(self) -> None:
        emis = _emis()
        self.assertGreater(len(emis), 100, "codes introuvables : test aveugle")
        self.assertIn("HISTORY_CONFIRMED_LEGITIMATE_SENDER", emis)

    def test_chaque_phrase_traduit_un_indice_emis(self) -> None:
        orphelins = sorted(_registre() - _emis() - set(_HISTORIQUES))
        self.assertEqual(orphelins, [], f"phrases sans émetteur : {orphelins}")

    def test_chaque_piece_d_un_faisceau_a_un_emetteur(self) -> None:
        connus = _emis() | set(_HISTORIQUES)
        for rule in CORRELATIONS:
            pieces = {code for famille in rule.requires for code in famille}
            pieces |= set(rule.excludes)
            with self.subTest(faisceau=rule.article_code):
                self.assertEqual(sorted(pieces - connus), [])

    def test_une_entree_historique_n_est_plus_emise(self) -> None:
        # S'il renaît, il sort de la liste : il n'est plus un souvenir.
        emis = _emis()
        for code in _HISTORIQUES:
            with self.subTest(code=code):
                self.assertNotIn(code, emis)

    def test_les_codes_sans_emetteur_ne_reviennent_pas(self) -> None:
        for code in _SANS_EMETTEUR:
            with self.subTest(code=code):
                self.assertNotIn(code, plain_words._PLAIN)
                self.assertNotIn(code, plain_words._SHORT)
                self.assertNotIn(code, plain_words._TELEGRAPHIQUE)


if __name__ == "__main__":
    unittest.main()
