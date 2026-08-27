from __future__ import annotations

import unittest

from sentimail_v3.code.plain_words import short_conclusion

# Le cas réel : la conclusion reprenait, une à une, les lignes déjà lues
# au-dessus, puis concluait en dernière phrase.
LONGUE = (
    "Le message présente un échec DMARC et un désalignement DKIM, ce qui "
    "indique une possible usurpation du domaine visible printerpoint.co.in. "
    "Cependant, l’envoi via Amazon SES (SPF passe) et le faible score Rspamd "
    "suggèrent qu’il pourrait s’agir d’un envoi légitime via un prestataire. "
    "Le nom affiché 'CIC-Passerelle' imite une banque connue, mais le domaine "
    "réel n’est pas lié à CIC. L’absence de contenu textuel exploitable et de "
    "formulaire ne permet pas de confirmer une intention malveillante. "
    "Le doute subsiste quant à la légitimité de l’expéditeur et à la finalité "
    "du lien, justifiant une demande d’avis à l’utilisateur."
)
LISTE = [
    "L’authentification du domaine a échoué : DMARC.",
    "La signature du message appartient à un autre domaine que celui affiché.",
    "Le nom affiché est celui d’une marque connue, mais le message vient d’ailleurs.",
    "L’envoi est passé par un prestataire dont le SPF est valide.",
    "Le message ne contient aucun texte exploitable ni formulaire.",
]


class ConcisionTests(unittest.TestCase):
    """La conclusion doit conclure, pas répéter les deux colonnes.

    Elle redisait, phrase par phrase, ce qui figurait déjà dans « ce qui me
    gêne » et « ce qui me rassure ». Lire deux fois la même chose n'apporte
    rien et enterre la seule ligne qui répond à « et donc ? ».
    """

    def test_la_conclusion_tient_en_une_phrase(self) -> None:
        # Une motivation expose puis conclut : c'est la fin qui répond à
        # « et donc ? », le reste a déjà été lu au-dessus.
        rendu = short_conclusion(LONGUE, listed=LISTE)
        self.assertLessEqual(rendu.count("."), 1)

    def test_ce_qui_est_deja_dit_ailleurs_dans_l_avis_disparait(self) -> None:
        # « Ce que je n'ai pas pu vérifier » est une section à part.
        rendu = short_conclusion(LONGUE, listed=LISTE)
        self.assertNotIn("formulaire", rendu)

    def test_une_phrase_trop_breve_en_entraine_une_seconde(self) -> None:
        # « Je te demande. » seule ne dit pas pourquoi.
        rendu = short_conclusion(
            "Le domaine a été créé il y a trois jours et réclame un paiement. "
            "Je te demande.",
            listed=[],
        )
        self.assertIn("trois jours", rendu)

    def test_elle_reste_courte(self) -> None:
        self.assertLessEqual(len(short_conclusion(LONGUE, listed=LISTE)), 200)

    def test_la_phrase_qui_conclut_est_gardee(self) -> None:
        rendu = short_conclusion(LONGUE, listed=LISTE)
        self.assertIn("doute", rendu.casefold())

    def test_ce_qui_est_deja_liste_disparait(self) -> None:
        rendu = short_conclusion(LONGUE, listed=LISTE)
        for repete in ("DMARC", "Amazon SES", "Rspamd"):
            with self.subTest(repete=repete):
                self.assertNotIn(repete, rendu)


class RobustesseTests(unittest.TestCase):
    """Une conclusion absente ou déjà brève ne doit pas être abîmée."""

    def test_une_conclusion_deja_breve_est_rendue_telle_quelle(self) -> None:
        breve = "Je préfère te demander plutôt que de décider à ta place."
        self.assertEqual(short_conclusion(breve, listed=[]), breve)

    def test_sans_conclusion_une_phrase_de_repli_est_rendue(self) -> None:
        for vide in ("", None, "   "):
            with self.subTest(valeur=vide):
                self.assertTrue(short_conclusion(vide, listed=LISTE))

    def test_une_conclusion_entierement_redondante_garde_sa_derniere_phrase(self) -> None:
        # Tout couper laisserait un avis sans conclusion du tout.
        redondante = LISTE[0] + " " + LISTE[1]
        rendu = short_conclusion(redondante, listed=LISTE)
        self.assertTrue(rendu.strip())

    def test_les_references_internes_restent_retirees(self) -> None:
        rendu = short_conclusion(
            "Le doute subsiste (AUTH-003, score=42). Je te demande.", listed=[]
        )
        self.assertNotIn("AUTH-003", rendu)
        self.assertNotIn("score=42", rendu)

    def test_aucune_phrase_n_est_coupee_en_son_milieu(self) -> None:
        rendu = short_conclusion(LONGUE, listed=LISTE)
        self.assertTrue(rendu.endswith((".", "!", "?")))


if __name__ == "__main__":
    unittest.main()


# Le cas réel du 21/08 : l'avis sur une alerte de connexion OpenAI concluait
# par « com est expliquée par le contexte de tracking ». Personne ne sait qui
# est « com ».
OPENAI = (
    "L’authentification est solide et le score antispam faible, mais l’indice "
    "SENDER_ACTIVITY_INCOHERENT (force 55) indique que le contenu ne "
    "correspond pas à l’activité publiée d’OpenAI. La redirection inter-apex "
    "vers chatgpt.com est expliquée par le contexte de tracking mais reste à "
    "confirmer. Le doute subsiste quant à la légitimité du message."
)


class UnNomDeDomaineNEstPasUneFinDePhraseTests(unittest.TestCase):
    """Le point d'un domaine ne termine pas une phrase.

    Le découpage coupait à chaque point : « chatgpt.com » devenait deux
    phrases, et la conclusion, qui ne garde que la fin, s'ouvrait sur « com ».
    Le lecteur y voyait un domaine inconnu là où il n'y avait qu'un morceau de
    mot.
    """

    def test_la_conclusion_ne_commence_pas_par_un_bout_de_domaine(self) -> None:
        rendu = short_conclusion(OPENAI)
        self.assertFalse(rendu.startswith("com "), rendu)

    def test_le_domaine_reste_entier_s_il_est_cite(self) -> None:
        rendu = short_conclusion(OPENAI, max_sentences=2)
        if "chatgpt" in rendu:
            self.assertIn("chatgpt.com", rendu)

    def test_les_phrases_restent_separees(self) -> None:
        from sentimail_v3.code.plain_words import _sentences

        phrases = _sentences("Première phrase. Deuxième phrase ! Troisième ?")
        self.assertEqual(len(phrases), 3)

    def test_un_domaine_ne_fabrique_pas_de_phrase(self) -> None:
        from sentimail_v3.code.plain_words import _sentences

        phrases = _sentences("Le lien mène vers chatgpt.com et rien d’autre.")
        self.assertEqual(len(phrases), 1)

    def test_une_decimale_ne_fabrique_pas_de_phrase(self) -> None:
        from sentimail_v3.code.plain_words import _sentences

        self.assertEqual(len(_sentences("Le score atteint 0.85 au total.")), 1)
