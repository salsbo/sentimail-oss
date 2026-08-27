from __future__ import annotations

import unittest
from urllib.parse import unquote, urlsplit

from sentimail_v3.conversation.directive_policy import evaluate_directive
from sentimail_v3.conversation.review_notice import choice_links


def _corps(lien: str) -> str:
    return unquote(urlsplit(lien).query.split("body=", 1)[1])


# Les boutons écrivent désormais des phrases rédigées, jeton dans l'objet :
# ce contrat vit dans test_reponse_humaine. Ici reste la lecture de la lettre
# seule, qui couvre le secours « réponds simplement A, B ou C » d'une réponse
# écrite à la main, rattachée par In-Reply-To.
class LectureDeLaLettreTests(unittest.TestCase):
    """La lettre doit être comprise sans consulter un modèle."""

    def _verdict(self, corps: str, action: str = "none"):
        return evaluate_directive(corps, {"requested_action": action})

    def test_A_demande_la_livraison(self) -> None:
        verdict = self._verdict("S3-ACTION:JETON\n\nA\n", "release_original")
        self.assertEqual(verdict["explicit_action"], "release_original")
        self.assertEqual(verdict["explicit_classification"], "legitimate")
        self.assertEqual(verdict["conflicts"], [])

    def test_B_refuse_et_bloque(self) -> None:
        verdict = self._verdict("S3-ACTION:JETON\n\nB\n", "suppress_future")
        self.assertEqual(verdict["explicit_action"], "suppress_future")
        self.assertEqual(verdict["explicit_classification"], "spam")
        self.assertEqual(verdict["conflicts"], [])

    def test_les_boutons_reels_sont_compris(self) -> None:
        for lettre, action in (("A", "release_original"), ("B", "suppress_future")):
            with self.subTest(lettre=lettre):
                corps = _corps(choice_links("maia@mondomaine.example")[lettre])
                self.assertEqual(self._verdict(corps, action)["explicit_action"], action)

    def test_une_lettre_contredite_par_le_modele_est_bloquee(self) -> None:
        # Le garde-fou doit continuer de jouer : « B » avec une action de
        # livraison reste une contradiction.
        verdict = self._verdict("S3-ACTION:JETON\n\nB\n", "release_original")
        self.assertEqual(verdict["conflicts"], ["action_contradicts_user_text"])

    def test_C_ne_declenche_aucune_action(self) -> None:
        corps = _corps(choice_links("maia@mondomaine.example")["C"])
        self.assertIsNone(self._verdict(corps)["explicit_action"])

    def test_une_lettre_au_milieu_d_une_phrase_ne_decide_rien(self) -> None:
        # « A » dans « A demain » n'est pas un choix.
        for texte in ("S3-ACTION:X\n\nA demain, merci", "S3-ACTION:X\n\nB comme dans bateau ?"):
            with self.subTest(texte=texte):
                self.assertIsNone(self._verdict(texte)["explicit_action"])

    def test_une_phrase_explicite_fonctionne_toujours(self) -> None:
        verdict = self._verdict(
            "C’est du spam. Ne le livre pas et bloque les prochains de cette adresse.",
            "suppress_future",
        )
        self.assertEqual(verdict["explicit_action"], "suppress_future")

    def test_le_jeton_seul_ne_decide_rien(self) -> None:
        self.assertIsNone(self._verdict("S3-ACTION:JETON\n")["explicit_action"])


if __name__ == "__main__":
    unittest.main()


class AutorisationTests(unittest.TestCase):
    """Une lettre DIT une intention ; elle n'AUTORISE rien.

    L'autorisation repose sur deux choses indépendantes de la lettre :
    le jeton S3-ACTION, unique par dossier, généré à l'envoi et conservé
    haché ; et le filtre d'expéditeur, qui n'accepte que les boîtes protégées.
    Envoyer « A » à MAIA sans jeton ne rattache la réponse à aucun dossier -
    elle déclenche alors un code de confirmation vers la vraie boîte.
    """

    def test_le_jeton_est_unique_par_dossier(self) -> None:
        from sentimail_v3.conversation.action_tokens import action_token, new_nonce

        secret = "secret-de-test"
        premier = action_token(secret, "dossier-1", new_nonce())
        second = action_token(secret, "dossier-2", new_nonce())
        self.assertNotEqual(premier, second)
        self.assertGreater(len(premier), 30)

    def test_un_jeton_ne_vaut_que_pour_son_dossier(self) -> None:
        from sentimail_v3.conversation.action_tokens import action_token

        nonce = "aleatoire"
        self.assertNotEqual(
            action_token("secret", "dossier-1", nonce),
            action_token("secret", "dossier-2", nonce),
        )

    def test_un_jeton_ne_vaut_que_pour_ce_deploiement(self) -> None:
        from sentimail_v3.conversation.action_tokens import action_token

        self.assertNotEqual(
            action_token("secret-a", "dossier", "nonce"),
            action_token("secret-b", "dossier", "nonce"),
        )

    def test_le_jeton_n_est_pas_conserve_en_clair(self) -> None:
        from sentimail_v3.conversation.action_tokens import action_token, token_hash

        jeton = action_token("secret", "dossier", "nonce")
        empreinte = token_hash(jeton)
        self.assertNotIn(jeton, empreinte)
        self.assertEqual(empreinte, token_hash(jeton))
