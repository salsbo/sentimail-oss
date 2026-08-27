from __future__ import annotations

import unittest

from sentimail_v3.judgment.verdict_engine import _express_dossier, _express_judgment


class ExpressJudgmentTests(unittest.IsolatedAsyncioTestCase):
    """Le jugement rendu par la voie rapide doit rester un jugement complet."""

    async def _juger(self, codes, sender, destinations, adverse=()):
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

            async def fetchval(self, query, *args):
                if "hook_runs" in query:
                    return {"actionable_apexes": list(destinations)}
                return sender

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

            async def fetchval(self, query, *args):
                if "hook_runs" in query:
                    return {"actionable_apexes": ["openai.com"]}
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
