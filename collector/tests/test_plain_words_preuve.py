"""Une phrase montrée à l'utilisateur ne dit pas plus que ce que l'indice prouve.

« Le message contient du code qui s'exécute à l'ouverture » traduisait un
simple comptage de balises <script>, qu'aucune messagerie ne lance. Le défaut
n'était pas dans une phrase mais dans la manière de les écrire : un
dictionnaire rédigé loin des détecteurs dérive vers la conséquence imaginée.

Ce test tient la règle pour toutes les surfaces. Une expression de conséquence
ou d'intention est soit interdite partout, soit réservée aux indices dont le
détecteur l'établit, avec la raison écrite à côté.
"""

from __future__ import annotations

import re
import unittest

from sentimail_v3.code.attachment_facts import _FINDING_RULES
from sentimail_v3.code.plain_words import _PLAIN, _SHORT, _TELEGRAPHIQUE

# Aucune analyse de SentiMail n'exécute ni n'observe l'exécution d'un code :
# tout est statique (balises, mots-clés, extensions, OCR). Ces expressions
# affirmeraient donc toujours plus que la preuve.
_INTERDITES = {
    "exécution affirmée": re.compile(r"s[’']exécute|se lance tout seul", re.I),
    "prise de contrôle": re.compile(r"prend\w* la main", re.I),
    "intention prêtée": re.compile(
        r"\b(?:pour|à) (?:cacher|échapper|empêcher|masquer)\b|créée? pour", re.I
    ),
    "lecture automatique niée": re.compile(r"lecture automatique", re.I),
}

# Une capacité d'exécution se dit seulement quand le détecteur a reconnu un
# type de fichier exécutable, pas un mot dans un texte.
_CAPACITE = re.compile(r"(?:capable d[’']|peut |à )exécuter", re.I)
_CAPACITE_PROUVEE = {
    # Extension exécutable reconnue (hooks/attachments.py).
    "ATTACHMENT_EXECUTABLE",
    # Membre d'archive à extension exécutable (file-sandbox).
    "ATTACHMENT_EXECUTABLE_MEMBER",
    # Faisceau qui exige une pièce active parmi les précédentes (correlation.py).
    "CORRELATION_MALICIOUS_ATTACHMENT",
}


def _phrases() -> list[tuple[str, str, str]]:
    phrases = [("_PLAIN", code, texte) for code, texte in _PLAIN.items()]
    phrases += [("_SHORT", code, texte) for code, texte in _SHORT.items()]
    phrases += [("_TELEGRAPHIQUE", code, texte) for code, texte in _TELEGRAPHIQUE.items()]
    phrases += [
        ("attachment_facts", regle[0], regle[4]) for regle in _FINDING_RULES.values()
    ]
    return phrases


class PhrasesSansSurpromesseTests(unittest.TestCase):
    def test_aucune_phrase_n_affirme_ce_qu_aucune_analyse_n_observe(self) -> None:
        for source, code, texte in _phrases():
            for motif, expression in _INTERDITES.items():
                with self.subTest(source=source, code=code, motif=motif):
                    self.assertNotRegex(texte, expression)

    def test_la_capacite_d_executer_est_reservee_aux_executables(self) -> None:
        for source, code, texte in _phrases():
            if _CAPACITE.search(texte):
                with self.subTest(source=source, code=code):
                    self.assertIn(code, _CAPACITE_PROUVEE)

    def test_le_balisage_actif_ne_se_dit_plus_execute(self) -> None:
        self.assertIn("ne les exécute pas", _PLAIN["CONTENT_ACTIVE_HTML"])


if __name__ == "__main__":
    unittest.main()
