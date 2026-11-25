from __future__ import annotations

import inspect
import unittest

from sentimail_v3.judgment import verdict_engine
from sentimail_v3.judgment.verdict_engine import _express_dossier, _express_judgment

# Un vrai code montré près de son annonce : la condition par défaut des tests,
# pour que chacun ne porte que sur ce qu'il nomme.
TEXTE_AVEC_CODE = "Votre code de vérification : 482913"


class ExpressJudgmentTests(unittest.IsolatedAsyncioTestCase):
    """Le jugement rendu par la voie rapide doit rester un jugement complet."""

    async def _juger(
        self,
        codes,
        sender,
        destinations,
        adverse=(),
        etabli=True,
        texte=TEXTE_AVEC_CODE,
        panne=False,
    ):
        class _Pool:
            async def fetch(self, query, *args):
                if "FROM clues" in query:
                    return [
                        {
                            "clue_code": c,
                            "direction": "adverse" if c in adverse else "favorable",
                        }
                        for c in set(codes) | set(adverse)
                    ]
                return []

            async def fetchrow(self, query, *args):
                if panne:
                    raise RuntimeError("base indisponible")
                if "body_text" in query:
                    return {"subject": "", "body_text": texte, "body_html": ""}
                return None

            async def fetchval(self, query, *args):
                # Chaque requête est routée explicitement. Une requête inconnue
                # rend None : rendre l'expéditeur par défaut ferait passer la
                # requête d'ancienneté pour vraie dans tous les tests.
                if "hook_runs" in query:
                    return {"actionable_apexes": list(destinations)}
                if "delivery_status='delivered'" in query:
                    return etabli
                if "signing_domain" in query:
                    return sender
                if "split_part(from_header" in query:
                    return sender
                return None

        return await _express_judgment(_Pool(), "message-id")  # type: ignore[arg-type]

    async def test_un_code_authentifie_est_juge_legitime_et_livrable(self) -> None:
        jugement = await self._juger(
            {"CONTENT_EXPECTED_ONE_TIME_CODE_INPUT", "AUTH_DMARC_PASS"},
            "openai.com",
            ["openai.com"],
        )
        self.assertIsNotNone(jugement)
        self.assertEqual(jugement["classification"], "legitimate")
        self.assertEqual(jugement["delivery_decision"], "deliver")
        self.assertFalse(jugement["verdict_doubt"])
        # La motivation doit expliquer pourquoi on est allé vite.
        self.assertIn("code", jugement["rationale"].casefold())

    async def test_une_charge_retenue_referme_la_voie(self) -> None:
        """Le faux « DISNEY+ » du 26 août portait du texte masqué par CSS.

        Son article n'existait pas quand la liste des disqualifiants a été
        écrite : c'est la direction de l'indice, et non son nom, qui doit
        renvoyer le message vers l'examen complet.
        """
        jugement = await self._juger(
            {"CONTENT_ONE_TIME_CREDENTIAL_PROVIDED_NOT_REQUESTED", "AUTH_DMARC_PASS"},
            "careerwiseenglish.com.au",
            ["careerwiseenglish.com.au"],
            adverse={"CONTENT_HIDDEN_TEXT_SALTING"},
        )
        self.assertIsNone(jugement)

    async def test_les_hotes_sont_ramenes_a_leur_apex(self) -> None:
        """Les entites portent des hotes complets, la comparaison porte sur l'apex."""
        jugement = await self._juger(
            {"CONTENT_EXPECTED_ONE_TIME_CODE_INPUT", "AUTH_DMARC_PASS"},
            "tm.openai.com",
            ["cdn.openai.com", "url3243.email.openai.com"],
        )
        self.assertIsNotNone(jugement)

    async def test_un_hebergeur_tiers_referme_la_voie(self) -> None:
        # Une image sur un stockage public suffit a renvoyer vers l'examen
        # complet : on prefere une livraison lente a un controle absent.
        jugement = await self._juger(
            {"CONTENT_EXPECTED_ONE_TIME_CODE_INPUT", "AUTH_DMARC_PASS"},
            "tm.openai.com",
            ["cdn.openai.com", "openai-public.s3-us-west-2.amazonaws.com"],
        )
        self.assertIsNone(jugement)

    async def test_un_apex_etranger_referme_la_voie(self) -> None:
        # Le hook d'URL a deja reduit « openai.com.evil.top » a evil.top ;
        # c'est cet apex qui est compare, et il est etranger.
        jugement = await self._juger(
            {"CONTENT_EXPECTED_ONE_TIME_CODE_INPUT", "AUTH_DMARC_PASS"},
            "tm.openai.com",
            ["evil.top"],
        )
        self.assertIsNone(jugement)

    async def test_un_message_ordinaire_ne_prend_pas_la_voie_rapide(self) -> None:
        jugement = await self._juger(
            {"AUTH_DMARC_PASS", "NATURE_BULK_MAILING"}, "exemple.fr", ["exemple.fr"]
        )
        self.assertIsNone(jugement)

    async def test_un_code_vers_un_domaine_etranger_repart_par_le_chemin_normal(self) -> None:
        jugement = await self._juger(
            {"CONTENT_EXPECTED_ONE_TIME_CODE_INPUT", "AUTH_DMARC_PASS"},
            "openai.com",
            ["collecte-inconnue.top"],
        )
        self.assertIsNone(jugement)

    async def test_une_premiere_observation_repart_par_le_chemin_normal(self) -> None:
        """Le faux avis de double authentification du 1er septembre 2026.

        Domaine d'envoi jetable, authentifié pour lui-même, liens chez lui,
        aucun indice adverse : seule l'adresse jamais reçue le distingue d'un
        vrai code. Il doit repartir par l'examen complet, qu'il montre un code
        ou non.
        """
        codes = {"CONTENT_ONE_TIME_CREDENTIAL_PROVIDED_NOT_REQUESTED", "AUTH_DMARC_PASS"}
        sans_code = (
            "Activez la double authentification en demandant un second code de "
            "vérification à chaque connexion. L'équipe Espace client 1999-2026"
        )
        for texte in (sans_code, TEXTE_AVEC_CODE):
            with self.subTest(texte=texte):
                jugement = await self._juger(
                    codes,
                    "sender2.envoi-jetable.top",
                    ["envoi-jetable.top"],
                    etabli=False,
                    texte=texte,
                )
                self.assertIsNone(jugement)
        # Témoin : le même message, d'une adresse déjà reçue et avec un code,
        # passerait. C'est donc bien l'ancienneté qui le renvoie ci-dessus.
        temoin = await self._juger(
            codes,
            "sender2.envoi-jetable.top",
            ["envoi-jetable.top"],
            etabli=True,
            texte=TEXTE_AVEC_CODE,
        )
        self.assertIsNotNone(temoin)

    async def test_un_expediteur_etabli_sans_code_visible_repart(self) -> None:
        jugement = await self._juger(
            {"CONTENT_ONE_TIME_CREDENTIAL_PROVIDED_NOT_REQUESTED", "AUTH_DMARC_PASS"},
            "exemple.fr",
            ["exemple.fr"],
            etabli=True,
            texte=(
                "Code promo à usage unique à saisir en majuscules dans votre "
                "récapitulatif de commande BTS26"
            ),
        )
        self.assertIsNone(jugement)

    async def test_un_constat_en_panne_ferme_la_voie(self) -> None:
        # Fail-soft : un constat qui échoue est absent, et la voie reste
        # fermée. Le message repart par le chemin complet, sans erreur.
        jugement = await self._juger(
            {"CONTENT_EXPECTED_ONE_TIME_CODE_INPUT", "AUTH_DMARC_PASS"},
            "openai.com",
            ["openai.com"],
            panne=True,
        )
        self.assertIsNone(jugement)

    async def test_le_code_n_apparait_dans_aucun_journal(self) -> None:
        # Le code est un secret vivant : le journal ne porte que des booléens.
        with self.assertLogs("sentimail-v3-verdict", level="INFO") as journal:
            jugement = await self._juger(
                {"CONTENT_EXPECTED_ONE_TIME_CODE_INPUT", "AUTH_DMARC_PASS"},
                "openai.com",
                ["openai.com"],
            )
        self.assertIsNotNone(jugement)
        lignes = "\n".join(journal.output)
        self.assertIn("verdict.express_considered", lignes)
        self.assertNotIn("482913", lignes)
        self.assertNotIn("482913", str(jugement))

    def test_l_anciennete_ne_compte_ni_la_voie_rapide_ni_les_indesirables(self) -> None:
        source = inspect.getsource(verdict_engine._sender_established)
        for attendu in (
            "express_path",
            "observation_pipeline",
            "original_filed_as_junk",
            "AUTH_DMARC_PASS",
            "sentimail_same_client",
            "ANCIENNETE_JOURS",
            "sender_policies",
            "action='hold'",
        ):
            with self.subTest(attendu=attendu):
                self.assertIn(attendu, source)


class DossierExpressTests(unittest.IsolatedAsyncioTestCase):
    """Le dossier remis à _complete doit porter les indices que le jugement cite.

    La voie rapide passait un dossier réduit à son seul schéma : _complete
    échouait sur KeyError('clues') à chaque passage - aucun verdict express
    n'a jamais existé en production, et chaque code à usage unique repartait
    vers l'examen complet après trois tentatives, livré en retard.
    """

    _INDICES = [
        {"id": 41, "clue_code": "CONTENT_EXPECTED_ONE_TIME_CODE_INPUT",
         "article_code": "CONTENT-009", "direction": "neutral", "strength": 2,
         "confidence": 0.9, "statement": "Le message attend un code."},
        {"id": 42, "clue_code": "AUTH_DMARC_PASS", "article_code": "AUTH-001",
         "direction": "favorable", "strength": 3, "confidence": 0.95,
         "statement": "DMARC aligné."},
    ]

    def _pool(self):
        indices = self._INDICES

        class _Pool:
            async def fetch(self, query, *args):
                if "FROM clues" in query:
                    return list(indices)
                return []

            async def fetchrow(self, query, *args):
                if "body_text" in query:
                    return {"subject": "", "body_text": TEXTE_AVEC_CODE, "body_html": ""}
                return None

            async def fetchval(self, query, *args):
                if "hook_runs" in query:
                    return {"actionable_apexes": ["openai.com"]}
                if "delivery_status='delivered'" in query:
                    return True
                return "openai.com"

        return _Pool()

    async def test_le_dossier_porte_les_indices_avec_leur_identifiant(self) -> None:
        dossier = await _express_dossier(self._pool(), "message-id")  # type: ignore[arg-type]
        index = {c["clue_code"]: c["id"] for c in dossier["clues"]}
        self.assertEqual(index["CONTENT_EXPECTED_ONE_TIME_CODE_INPUT"], 41)
        self.assertEqual(index["AUTH_DMARC_PASS"], 42)

    async def test_chaque_code_cite_par_le_jugement_a_sa_preuve(self) -> None:
        # C'est exactement le geste de _complete : clues[code] pour chaque code
        # cité. Un code sans preuve refait le KeyError d'origine.
        pool = self._pool()
        jugement = await _express_judgment(pool, "message-id")  # type: ignore[arg-type]
        self.assertIsNotNone(jugement)
        dossier = await _express_dossier(pool, "message-id")  # type: ignore[arg-type]
        index = {str(c["clue_code"]): int(c["id"]) for c in dossier["clues"]}
        cites = list(jugement["supporting_clue_codes"]) + list(
            jugement["contradicting_clue_codes"]
        )
        self.assertTrue(cites, "le jugement express doit citer ses indices")
        for code in cites:
            self.assertIn(code, index)
