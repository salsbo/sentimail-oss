"""La fausse page « vérifiez que vous êtes humain », et le vrai mur anti-robot.

M-16ae76, 16 septembre 2026 : un faux « stockage plein » menait, sur
storage.googleapis.com, à « Cloudflare Verification Required. Slide to
verify ». Le bac à sable l'avait vue ; aucun indice n'en était sorti, et le
juge a demandé l'avis du destinataire faute de preuve matérielle.
"""

from __future__ import annotations

import unittest

from sentimail_v3.code.verification_gate import is_fake_verification_gate
from sentimail_v3.judgment.verdict_engine import _material_danger_evidence
from sentimail_v3.observation.deep_analysis import _SIGNAL_RULES, _signals, _url_summary

# Le résultat du bac à sable tel qu'il est en base pour M-16ae76.
PAGE_M_16AE76 = {
    "hops": 1,
    "chain": [
        {
            "url": "https://storage.googleapis.com/jmclldtome/m",
            "host": "storage.googleapis.com",
            "size": 10701,
            "status": 200,
            "content_type": "text/html",
        }
    ],
    "error": None,
    "forms": [],
    "cloaking": False,
    "final_apex": "storage.googleapis.com",
    "final_host": "storage.googleapis.com",
    "initial_url": "https://storage.googleapis.com/jmclldtome/m",
    "body_excerpt": "Cloudflare Verification Required Verify you are human to continue. Slide to verify",
    "final_status": 200,
    "initial_apex": "storage.googleapis.com",
    "initial_host": "storage.googleapis.com",
    "visible_links": [],
}


def _gate(**changes: object) -> bool:
    values: dict[str, object] = {
        "final_status": 200,
        "body_excerpt": PAGE_M_16AE76["body_excerpt"],
        "visible_link_count": 0,
        "final_apex": "storage.googleapis.com",
        "sender_apex": "mundololita.com",
    }
    values.update(changes)
    return is_fake_verification_gate(**values)  # type: ignore[arg-type]


class FauxSasTests(unittest.TestCase):
    def test_la_page_de_m_16ae76_est_un_faux_sas(self) -> None:
        self.assertTrue(_gate())

    def test_un_vrai_mur_refuse_en_403_et_reste_neutre(self) -> None:
        # Cloudflare devant producthunt.com, claude.ai, bricomarche.com.
        self.assertFalse(
            _gate(
                final_status=403,
                body_excerpt="Just a moment... Enable JavaScript and cookies to continue",
                final_apex="producthunt.com",
            )
        )

    def test_un_captcha_d_hebergeur_en_403_reste_neutre(self) -> None:
        self.assertFalse(
            _gate(
                final_status=403,
                body_excerpt="Captcha Page Help us verify real visitors Please complete to continue",
            )
        )

    def test_une_salle_d_attente_avec_ses_liens_n_est_pas_un_decor(self) -> None:
        # La billetterie servie en 200 porte ses liens de langue.
        self.assertFalse(
            _gate(
                body_excerpt="Waiting room Please enable JavaScript... » Button New captcha Input » Submit Deutsch English",
                visible_link_count=10,
                final_apex="secutix.com",
            )
        )

    def test_une_page_longue_dit_autre_chose_qu_une_verification(self) -> None:
        self.assertFalse(
            _gate(body_excerpt="Verify you are human. " + "Notre métier est la vente. " * 20)
        )

    def test_le_vocabulaire_doit_ouvrir_la_page(self) -> None:
        self.assertFalse(
            _gate(body_excerpt="Bienvenue sur notre boutique de vêtements " * 4 + " captcha")
        )

    def test_un_site_qui_protege_sa_propre_page_n_emprunte_rien(self) -> None:
        self.assertFalse(_gate(final_apex="mundololita.com"))

    def test_une_page_en_francais_est_reconnue(self) -> None:
        self.assertTrue(
            _gate(
                body_excerpt="Catpcha Nous vérifions que vous n'êtes pas un robot Validez le captcha svp Vérifier",
                final_apex="netlify.app",
            )
        )

    def test_un_statut_absent_ou_textuel_ne_conclut_rien(self) -> None:
        self.assertFalse(_gate(final_status=None))
        self.assertFalse(_gate(final_status="200"))
        self.assertFalse(_gate(final_status=True))

    def test_une_page_vide_ne_conclut_rien(self) -> None:
        self.assertFalse(_gate(body_excerpt=""))


class SignalFauxSasTests(unittest.TestCase):
    def _urls(self, **changes: object) -> list[dict[str, object]]:
        data = dict(PAGE_M_16AE76)
        data.update(changes)
        return [_url_summary(data, "cle", {"role": "link"})]

    def test_la_page_vue_devient_un_indice_materiel(self) -> None:
        signals = _signals(
            self._urls(), [], {}, True, sender_apex="mundololita.com"
        )
        gates = [value for value in signals if value["article_code"] == "DEEP-024"]
        self.assertEqual(len(gates), 1)
        self.assertEqual(gates[0]["final_hosts"], ["storage.googleapis.com"])
        clue_code, direction, strength, _, _ = _SIGNAL_RULES["DEEP-024"]
        self.assertEqual(clue_code, "URL_FAKE_HUMAN_VERIFICATION")
        self.assertEqual(direction, "adverse")
        self.assertGreaterEqual(strength, 60)

    def test_un_vrai_mur_ne_produit_rien(self) -> None:
        signals = _signals(
            self._urls(
                final_status=403,
                body_excerpt="Just a moment... Enable JavaScript and cookies to continue",
            ),
            [],
            {},
            True,
            sender_apex="mundololita.com",
        )
        self.assertFalse(
            [value for value in signals if value["article_code"] == "DEEP-024"]
        )

    def test_un_lien_non_visite_ne_produit_rien(self) -> None:
        signals = _signals(
            [
                _url_summary(
                    {
                        "initial_url": "https://storage.googleapis.com/x/m",
                        "analysis_skipped": True,
                        "skip_reason": "protected_single_use_or_side_effect_url",
                    },
                    "cle",
                    {"role": "link"},
                )
            ],
            [],
            {},
            True,
            sender_apex="mundololita.com",
        )
        self.assertFalse(
            [value for value in signals if value["article_code"] == "DEEP-024"]
        )


class BarriereMaterielleTests(unittest.TestCase):
    """La barrière se lit dans les paramètres de l'article, tels que la base les rend.

    asyncpg rend une colonne jsonb en texte : les tests qui passaient un
    dictionnaire ont laissé la barrière muette sur tous les jugements.
    """

    def _dossier(self, parameters: object) -> dict[str, object]:
        return {
            "code_articles": [{"article_code": "DEEP-024", "parameters": parameters}],
            "clues": [
                {
                    "article_code": "DEEP-024",
                    "clue_code": "URL_FAKE_HUMAN_VERIFICATION",
                    "direction": "adverse",
                    "strength": 80,
                }
            ],
        }

    def test_des_parametres_en_texte_font_barriere(self) -> None:
        evidence = _material_danger_evidence(
            self._dossier(
                '{"delivery_barrier": "material_danger", '
                '"material_kind": "deceptive_verification_gate"}'
            )
        )
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["material_kind"], "deceptive_verification_gate")
        self.assertEqual(evidence[0]["clue_code"], "URL_FAKE_HUMAN_VERIFICATION")

    def test_des_parametres_illisibles_ne_font_pas_barriere(self) -> None:
        self.assertEqual(_material_danger_evidence(self._dossier("{pas du json")), [])

    def test_un_article_sans_barriere_reste_un_indice(self) -> None:
        self.assertEqual(_material_danger_evidence(self._dossier("{}")), [])


if __name__ == "__main__":
    unittest.main()
