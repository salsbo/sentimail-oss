"""La page d'atterrissage qui ne montre rien sans script, et ce qu'elle vaut.

M-a9e895 (16 septembre 2026, livré à 0,95) et M-373976 (17 septembre, soumis
pour avis) : deux faux reçus « Prime » dont le seul lien d'action menait, sur
un sous-domaine d'hébergement jetable, à une page de 484 octets servie en 200,
sans texte, sans lien, sans formulaire. Le bac à sable l'avait vue et l'avait
lue comme « rien observé » ; le juge y a lu une absence de charge.

Mesuré sur 60 jours (17 septembre 2026), lien d'action servi en 200 en
text/html, vide de texte, de lien et de formulaire, hors du domaine de
l'expéditeur, de 1024 octets au plus : 105 indésirables, 2 dangereux, 24
suspects, 8 légitimes (deux désinscriptions, un jeu, quatre pages de suivi
d'un routeur d'emailing, et le faux reçu lui-même). Trop de légitimes pour une
charge : le constat est neutre, il dit que le contrôle n'a rien pu lire. Réuni
à une finalité de paiement et à une première observation, il ne touchait aucun
message légitime : c'est la convergence CORR-016 qui porte la charge.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from sentimail_v3.code import plain_words
from sentimail_v3.code.correlation import correlations
from sentimail_v3.code.opaque_landing import TAILLE_MAX, is_opaque_landing
from sentimail_v3.observation.deep_analysis import _SIGNAL_RULES, _signals, _url_summary

# Le résultat du bac à sable tel qu'il est en base pour M-373976.
PAGE_M_373976 = {
    "hops": 1,
    "chain": [
        {
            "url": "https://trente-six5.bolt.host/",
            "host": "trente-six5.bolt.host",
            "size": 484,
            "status": 200,
            "content_type": "text/html",
        }
    ],
    "error": None,
    "forms": [],
    "cloaking": False,
    "final_apex": "bolt.host",
    "final_host": "trente-six5.bolt.host",
    "initial_url": "https://trente-six5.bolt.host/",
    "body_excerpt": "",
    "final_status": 200,
    "initial_apex": "bolt.host",
    "initial_host": "trente-six5.bolt.host",
    "visible_links": [],
}
EXPEDITEUR = "thegaragedoorcompany.ltd.uk"


def _opaque(**changes: object) -> bool:
    values: dict[str, object] = {
        "final_status": 200,
        "content_type": "text/html; charset=utf-8",
        "size": 484,
        "body_excerpt": "",
        "visible_link_count": 0,
        "form_count": 0,
        "final_apex": "bolt.host",
        "sender_apex": EXPEDITEUR,
        "link_context": "primary",
    }
    values.update(changes)
    return is_opaque_landing(**values)  # type: ignore[arg-type]


class PageOpaqueTests(unittest.TestCase):
    def test_la_page_de_m_373976_est_opaque(self) -> None:
        self.assertTrue(_opaque())

    def test_une_page_lourde_illisible_n_est_pas_une_coquille(self) -> None:
        # YouTube, Pinterest, la fiche produit Amazon : 262 144 octets dont le
        # bac à sable ne tire aucun texte. Illisible, pas vide.
        self.assertFalse(_opaque(size=262144, final_apex="youtube.com"))
        self.assertFalse(_opaque(size=TAILLE_MAX + 1))
        self.assertTrue(_opaque(size=TAILLE_MAX))

    def test_une_application_avec_son_squelette_n_est_pas_une_coquille(self) -> None:
        # Salesforce Lightning sert 1 845 à 2 883 octets de squelette : au-delà
        # du seuil, et à raison, ce sont des applications légitimes.
        self.assertFalse(_opaque(size=1845, final_apex="salesforce.com"))

    def test_seule_une_page_html_compte(self) -> None:
        # Une feuille de style de polices, un pixel de suivi : pas des pages.
        self.assertFalse(_opaque(content_type="text/css", size=183, final_apex="googleapis.com"))
        self.assertFalse(_opaque(content_type="image/png", size=42))
        self.assertFalse(_opaque(content_type="image/gif", size=43))
        self.assertFalse(_opaque(content_type=None))

    def test_une_page_qui_montre_quelque_chose_n_est_pas_opaque(self) -> None:
        self.assertFalse(_opaque(body_excerpt="Gérer mon abonnement Prime Video"))
        self.assertFalse(_opaque(visible_link_count=1))
        self.assertFalse(_opaque(form_count=1))

    def test_un_refus_ou_un_statut_douteux_ne_conclut_rien(self) -> None:
        self.assertFalse(_opaque(final_status=403))
        self.assertFalse(_opaque(final_status="200"))
        self.assertFalse(_opaque(final_status=None))
        self.assertFalse(_opaque(size=None))
        self.assertFalse(_opaque(size="484"))

    def test_le_propre_domaine_de_l_expediteur_n_est_pas_concerne(self) -> None:
        self.assertFalse(_opaque(final_apex=EXPEDITEUR))
        self.assertFalse(_opaque(final_apex=""))

    def test_seul_un_lien_d_action_compte(self) -> None:
        # La désinscription en pied de page, la navigation secondaire : ce
        # n'est pas là que le message emmène.
        self.assertFalse(_opaque(link_context="footer"))
        self.assertFalse(_opaque(link_context="secondary_navigation"))
        self.assertTrue(_opaque(link_context=None))


class CablageTests(unittest.TestCase):
    def _urls(self, candidate: dict[str, str] | None = None, **changes: object) -> list[dict[str, object]]:
        data = dict(PAGE_M_373976)
        data.update(changes)
        return [
            _url_summary(
                data,
                "cle",
                candidate or {"role": "html_link", "link_context": "primary", "visible_text": "Gérer votre abonnement"},
            )
        ]

    def test_la_page_vue_devient_un_constat_neutre(self) -> None:
        signals = _signals(self._urls(), [], {}, True, sender_apex=EXPEDITEUR)
        opaques = [value for value in signals if value["article_code"] == "DEEP-025"]
        self.assertEqual(len(opaques), 1)
        self.assertEqual(opaques[0]["final_hosts"], ["trente-six5.bolt.host"])
        clue_code, direction, strength, _, statement = _SIGNAL_RULES["DEEP-025"]
        self.assertEqual(clue_code, "URL_OPAQUE_LANDING")
        self.assertEqual(direction, "neutral")
        self.assertEqual(strength, 0)
        self.assertIn("script", statement)

    def test_une_ressource_de_rendu_ne_produit_rien(self) -> None:
        signals = _signals(
            self._urls(candidate={"role": "render_resource", "link_context": "primary"}),
            [],
            {},
            True,
            sender_apex=EXPEDITEUR,
        )
        self.assertFalse([value for value in signals if value["article_code"] == "DEEP-025"])

    def test_une_page_lue_ne_produit_rien(self) -> None:
        signals = _signals(
            self._urls(body_excerpt="Bienvenue sur notre boutique de portes de garage."),
            [],
            {},
            True,
            sender_apex=EXPEDITEUR,
        )
        self.assertFalse([value for value in signals if value["article_code"] == "DEEP-025"])

    def test_un_lien_non_visite_ne_produit_rien(self) -> None:
        signals = _signals(
            [
                _url_summary(
                    {
                        "initial_url": "https://trente-six5.bolt.host/",
                        "analysis_skipped": True,
                        "skip_reason": "protected_single_use_or_side_effect_url",
                    },
                    "cle",
                    {"role": "html_link", "link_context": "primary"},
                )
            ],
            [],
            {},
            True,
            sender_apex=EXPEDITEUR,
        )
        self.assertFalse([value for value in signals if value["article_code"] == "DEEP-025"])


def _codes(observed: set[str]) -> dict[str, dict[str, object]]:
    return {value["clue_code"]: value for value in correlations(observed)}


FAISCEAU = {"CONTENT_FINANCIAL_CONTEXT", "URL_OPAQUE_LANDING", "HISTORY_FIRST_OBSERVATION"}


class ConvergenceTests(unittest.TestCase):
    def test_les_trois_faits_reunis_convergent(self) -> None:
        found = _codes(set(FAISCEAU))
        self.assertIn("CORRELATION_OPAQUE_TRANSACTION_LURE", found)
        clue = found["CORRELATION_OPAQUE_TRANSACTION_LURE"]
        self.assertEqual(clue["direction"], "adverse")
        self.assertEqual(clue["article_code"], "CORR-016")
        self.assertEqual(clue["facts"]["attack_technique"], "FAKE_TRANSACTION_LURE")
        self.assertGreaterEqual(int(clue["strength"]), 50)

    def test_un_paiement_demande_vaut_contexte_financier(self) -> None:
        found = _codes({"ACTION_PAYMENT_TRANSFER", "URL_OPAQUE_LANDING", "HISTORY_FIRST_OBSERVATION"})
        self.assertIn("CORRELATION_OPAQUE_TRANSACTION_LURE", found)

    def test_sans_page_opaque_rien_ne_converge(self) -> None:
        self.assertNotIn(
            "CORRELATION_OPAQUE_TRANSACTION_LURE",
            _codes({"CONTENT_FINANCIAL_CONTEXT", "HISTORY_FIRST_OBSERVATION"}),
        )

    def test_sans_finalite_financiere_rien_ne_converge(self) -> None:
        # Un jeu-concours de La Poste, une désinscription : opaques, en
        # première observation, mais personne ne parle d'argent.
        self.assertNotIn(
            "CORRELATION_OPAQUE_TRANSACTION_LURE",
            _codes({"URL_OPAQUE_LANDING", "HISTORY_FIRST_OBSERVATION"}),
        )

    def test_un_expediteur_deja_vu_ne_converge_pas(self) -> None:
        self.assertNotIn(
            "CORRELATION_OPAQUE_TRANSACTION_LURE",
            _codes({"CONTENT_FINANCIAL_CONTEXT", "URL_OPAQUE_LANDING"}),
        )

    def test_un_apex_etabli_ici_l_exclut(self) -> None:
        self.assertNotIn(
            "CORRELATION_OPAQUE_TRANSACTION_LURE",
            _codes(set(FAISCEAU) | {"HISTORY_APEX_ESTABLISHED_LOCALLY"}),
        )

    def test_le_faux_recu_du_16_reunit_les_deux_leurres(self) -> None:
        """M-a9e895 : sans répondant ET page opaque. Les deux convergences se
        posent, chacune sur ses faits."""
        found = _codes(set(FAISCEAU) | {"SENDER_WITHOUT_PUBLIC_FOOTPRINT"})
        self.assertIn("CORRELATION_FAKE_TRANSACTION_LURE", found)
        self.assertIn("CORRELATION_OPAQUE_TRANSACTION_LURE", found)


class MotsSimplesTests(unittest.TestCase):
    def test_les_deux_indices_ont_leurs_mots(self) -> None:
        for code in ("URL_OPAQUE_LANDING", "CORRELATION_OPAQUE_TRANSACTION_LURE"):
            with self.subTest(code=code):
                self.assertIn(code, plain_words._PLAIN)
                self.assertIn(code, plain_words._SHORT)
                self.assertIn(code, plain_words._TELEGRAPHIQUE)


class MigrationTests(unittest.TestCase):
    def test_la_migration_declare_les_articles_et_la_technique(self) -> None:
        racine = Path(__file__).resolve().parents[2] / "database" / "init"
        fichiers = sorted(racine.glob("088_*.sql"))
        self.assertEqual(len(fichiers), 1, "une migration 088 attendue")
        sql = fichiers[0].read_text(encoding="utf-8")
        for attendu in (
            "'DEEP-025'",
            "'CORR-016'",
            "'neutral', 0",
            "'adverse', 55",
            "URL_OPAQUE_LANDING",
            "CORRELATION_OPAQUE_TRANSACTION_LURE",
            "FAKE_TRANSACTION_LURE",
        ):
            with self.subTest(attendu=attendu):
                self.assertIn(attendu, sql)
        # Pas une barrière matérielle : huit légitimes en 60 jours.
        self.assertNotIn("material_danger", sql)


if __name__ == "__main__":
    unittest.main()
