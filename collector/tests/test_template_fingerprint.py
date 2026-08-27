"""Une campagne se reconnaît à son squelette, pas à son texte.

Le même gabarit HTML, envoyé à des destinataires différents depuis des comptes
ESP différents, ne varie que par la personnalisation (prénom, liens uniques).
L'empreinte porte sur la structure du DOM - suite des balises, classes, apex
des liens - qui, elle, ne bouge pas : deux exemplaires d'une campagne ont une
similarité de squelette élevée même quand tout le texte visible diffère.
"""

from __future__ import annotations

import unittest

from sentimail_v3.code.template_fingerprint import (
    dom_minhash,
    jaccard,
    subject_template,
)

GABARIT = """
<html><body>
  <table class="wrap"><tr><td>
    <img class="logo" src="https://cdn.evt.com/logo.png">
    <h1 class="title">{TITRE}</h1>
    <p class="lead">Bonjour {NOM}, votre abonnement.</p>
    <div class="card"><span class="amount">69,90</span>
      <span class="status">Activé</span></div>
    <a class="cta" href="https://evt.com/go?u={ID}">Voir</a>
    <ul class="menu"><li>Films</li><li>Séries</li><li>Sport</li></ul>
    <p class="foot">Se désabonner</p>
    <a class="unsub" href="https://evt.com/unsub?u={ID}">Désinscription</a>
  </td></tr></table>
</body></html>
"""


def _exemplaire(nom: str, ident: str, titre: str) -> str:
    return (
        GABARIT.replace("{NOM}", nom).replace("{ID}", ident).replace("{TITRE}", titre)
    )


class SqueletteTests(unittest.TestCase):
    def test_deux_exemplaires_personnalises_se_ressemblent(self) -> None:
        a = dom_minhash(_exemplaire("Alex", "aaa111", "Offre A"))
        b = dom_minhash(_exemplaire("Camille", "zzz999", "Offre B"))
        self.assertIsNotNone(a)
        self.assertIsNotNone(b)
        self.assertGreaterEqual(jaccard(a, b), 0.9)

    def test_un_gabarit_different_ne_se_confond_pas(self) -> None:
        autre = (
            "<html><body><div class='news'><section><article>"
            "<h2>Titre</h2><span>texte</span><ul><li>a</li><li>b</li></ul>"
            "<footer><a href='https://autre.fr'>lien</a></footer>"
            "</article></section></div></body></html>"
        )
        a = dom_minhash(_exemplaire("Alex", "aaa111", "Offre A"))
        b = dom_minhash(autre)
        self.assertLess(jaccard(a, b), 0.5)

    def test_un_message_trop_pauvre_n_a_pas_d_empreinte(self) -> None:
        # Moins de 15 balises : squelette non discriminant, pas d'empreinte.
        self.assertIsNone(dom_minhash("<p>Bonjour</p>"))
        self.assertIsNone(dom_minhash(""))

    def test_l_empreinte_est_stable_et_serialisable(self) -> None:
        a = dom_minhash(_exemplaire("Alex", "aaa111", "Offre A"))
        b = dom_minhash(_exemplaire("Alex", "aaa111", "Offre A"))
        self.assertEqual(a, b)
        self.assertTrue(all(isinstance(x, int) for x in a))


class SujetTemplateTests(unittest.TestCase):
    def test_les_nombres_sont_masques(self) -> None:
        self.assertEqual(
            subject_template("Doc 6EM2A8TM8 - facture 3200 euros"),
            subject_template("Doc 9ZZ1P2QR7 - facture 5100 euros"),
        )

    def test_deux_sujets_de_sens_different_restent_distincts(self) -> None:
        self.assertNotEqual(
            subject_template("Votre colis est arrivé"),
            subject_template("Réinitialisez votre mot de passe"),
        )


class JaccardTests(unittest.TestCase):
    def test_identique_vaut_un(self) -> None:
        a = dom_minhash(_exemplaire("Alex", "aaa111", "Offre A"))
        self.assertEqual(jaccard(a, a), 1.0)


if __name__ == "__main__":
    unittest.main()
