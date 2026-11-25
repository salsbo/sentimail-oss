"""La réponse préremplie se lit comme un message écrit par son expéditeur.

Le clic sur A, B ou C ouvrait un message dont le corps commençait par une
ligne interne (« S3-ACTION:jeton ») suivie d'une lettre nue. Celui qui
l'envoyait voyait un contenu qu'il n'aurait jamais écrit, sans comprendre ce
qui partait ni pourquoi - au point de croire à un problème.

Le corps est désormais une réponse rédigée pour un humain, et la séquence
machine vit dans l'objet du message : le serveur la lit déjà là
(conversation.record_inbound cherche le marqueur dans objet + corps), et
personne ne retouche l'objet d'un mail. Un mailto: ne transporte que du texte
brut - ni couleur ni texte invisible n'y sont possibles : déplacer la séquence
hors de la zone de saisie est la seule façon de la soustraire au regard.
"""

from __future__ import annotations

import unittest
from urllib.parse import parse_qs, urlsplit

from sentimail_v3.conversation.action_tokens import ACTION_MARKER_RE
from sentimail_v3.conversation.assistant import _preformatted_choice
from sentimail_v3.conversation.directive_policy import evaluate_directive
from sentimail_v3.conversation.directive_receipt import _links as receipt_links
from sentimail_v3.conversation.junk_notice import (
    JUNK_TOKEN_PLACEHOLDER,
    junk_choice_links,
)
from sentimail_v3.conversation.review_notice import (
    ACTION_TOKEN_PLACEHOLDER,
    choice_links,
)

ADRESSE = "maia@sentinel.mondomaine.example"
JETON = "j" * 43


def _champs(lien: str) -> dict[str, str]:
    champs = parse_qs(urlsplit(lien).query)
    return {nom: valeurs[0] for nom, valeurs in champs.items()}


def _surfaces() -> dict[str, tuple[dict[str, str], str]]:
    """Chaque surface, ses liens et le marqueur qu'elle emploie."""
    return {
        "avis retenu": (choice_links(ADRESSE), ACTION_TOKEN_PLACEHOLDER),
        "avis classé": (junk_choice_links(ADRESSE), JUNK_TOKEN_PLACEHOLDER),
        "accusé de directive": (
            receipt_links(ADRESSE, True),
            ACTION_TOKEN_PLACEHOLDER,
        ),
    }


class SequenceHorsDuCorpsTests(unittest.TestCase):
    """La zone où l'on écrit ne contient plus aucune ligne machine."""

    def test_aucun_corps_ne_porte_la_sequence(self) -> None:
        for surface, (liens, marqueur) in _surfaces().items():
            for lettre, lien in liens.items():
                with self.subTest(surface=surface, lettre=lettre):
                    corps = _champs(lien)["body"]
                    self.assertNotIn(marqueur, corps)
                    self.assertNotIn("S3-ACTION", corps)

    def test_chaque_objet_porte_la_sequence(self) -> None:
        for surface, (liens, marqueur) in _surfaces().items():
            for lettre, lien in liens.items():
                with self.subTest(surface=surface, lettre=lettre):
                    self.assertIn(marqueur, _champs(lien)["subject"])

    def test_l_objet_reste_lisible_par_le_serveur(self) -> None:
        # conversation.record_inbound cherche le marqueur dans objet + corps :
        # une fois le jeton substitué, l'objet doit suffire au rattachement.
        for surface, (liens, marqueur) in _surfaces().items():
            for lettre, lien in liens.items():
                with self.subTest(surface=surface, lettre=lettre):
                    sujet = _champs(lien)["subject"].replace(
                        marqueur, f"S3-ACTION:{JETON}"
                    )
                    trouve = ACTION_MARKER_RE.search(sujet)
                    self.assertIsNotNone(trouve)
                    self.assertEqual(trouve.group(1), JETON)


class CorpsRedigeTests(unittest.TestCase):
    """Le message part comme une réponse écrite, pas comme une trame interne."""

    def test_chaque_corps_s_adresse_a_maia(self) -> None:
        for surface, (liens, _) in _surfaces().items():
            for lettre, lien in liens.items():
                with self.subTest(surface=surface, lettre=lettre):
                    corps = _champs(lien)["body"]
                    self.assertTrue(corps.startswith("Bonjour MAIA,"))
                    self.assertIn("Merci", corps)

    def test_aucune_lettre_nue_sur_sa_ligne(self) -> None:
        # Une lettre isolée est l'ancienne trame : si elle subsiste, le corps
        # n'est pas une phrase mais un code.
        for surface, (liens, _) in _surfaces().items():
            for lettre, lien in liens.items():
                with self.subTest(surface=surface, lettre=lettre):
                    lignes = [
                        ligne.strip()
                        for ligne in _champs(lien)["body"].splitlines()
                    ]
                    self.assertNotIn(lettre, lignes)


class InterpretationConserveeTests(unittest.TestCase):
    """Les phrases restent lues sans modèle, comme les lettres l'étaient."""

    def test_les_acceptations_demandent_la_livraison(self) -> None:
        for surface, (liens, _) in _surfaces().items():
            if "A" not in liens:
                continue
            with self.subTest(surface=surface):
                corps = _champs(liens["A"])["body"]
                verdict = evaluate_directive(
                    corps, {"requested_action": "release_original"}
                )
                self.assertEqual(verdict["explicit_action"], "release_original")
                self.assertEqual(verdict["explicit_classification"], "legitimate")
                self.assertEqual(verdict["conflicts"], [])
                self.assertEqual(_preformatted_choice(corps)[0], "A")

    def test_les_refus_bloquent_les_prochains(self) -> None:
        # L'avis d'indésirable n'offre pas de B : le classement est acquis.
        for surface, (liens, _) in _surfaces().items():
            if "B" not in liens:
                continue
            with self.subTest(surface=surface):
                corps = _champs(liens["B"])["body"]
                verdict = evaluate_directive(
                    corps, {"requested_action": "suppress_future"}
                )
                self.assertEqual(verdict["explicit_action"], "suppress_future")
                self.assertEqual(verdict["explicit_classification"], "spam")
                self.assertEqual(verdict["conflicts"], [])
                self.assertEqual(_preformatted_choice(corps)[0], "B")

    def test_autre_chose_ne_decide_rien(self) -> None:
        for surface, (liens, _) in _surfaces().items():
            if "C" not in liens:
                continue
            with self.subTest(surface=surface):
                corps = _champs(liens["C"])["body"]
                verdict = evaluate_directive(
                    corps, {"requested_action": "suppress_future"}
                )
                self.assertIsNone(verdict["explicit_action"])
                self.assertIsNone(verdict["explicit_classification"])
                self.assertEqual(_preformatted_choice(corps), ("C_TEXT", ""))

    def test_le_texte_ajoute_a_c_est_seul_envoye_au_llm(self) -> None:
        corps = _champs(_surfaces()["avis retenu"][0]["C"])["body"]
        corps = corps.replace(
            "Tapez ici vos demandes ou remarques",
            "Ce message vient de mon comptable, mais ne le livre pas encore.",
        )
        self.assertEqual(
            _preformatted_choice(corps),
            (
                "C_TEXT",
                "Ce message vient de mon comptable, mais ne le livre pas encore.",
            ),
        )

    def test_une_phrase_contradictoire_ne_devient_jamais_un_choix(self) -> None:
        self.assertIsNone(
            _preformatted_choice(
                "Ce message est légitime, mais ne le livre pas et bloque les prochains."
            )[0]
        )


if __name__ == "__main__":
    unittest.main()
