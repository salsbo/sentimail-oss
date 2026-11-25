"""Un déguisement relevé par Rspamd devient un indice, sinon il n'existe pas.

Sur M-490357 (6 septembre 2026), l'objet et l'expéditeur « C I C » étaient
encodés en base64 sans raison, et Rspamd le disait (SUBJ_EXCESS_BASE64,
FROM_EXCESS_BASE64). Personne ne le lisait.
"""

from __future__ import annotations

import unittest


class DeguisementTests(unittest.IsolatedAsyncioTestCase):
    async def _codes(self, resultat: str):
        from sentimail_v3.observation.dossier.hooks.rspamd import RspamdHook
        from sentimail_v3.observation.dossier.models import InvestigationContext
        from sentimail_v3.observation.parser import parse_message

        raw = (
            "From: C I C <contact@exemple.test>\r\nTo: me@mondomaine.example\r\n"
            "Subject: Avis\r\nMessage-ID: <a@exemple.test>\r\n"
            f"X-Spamd-Result: default: False [{resultat}]\r\n\r\ncorps\r\n"
        ).encode()
        context = InvestigationContext(raw, parse_message(raw), "contact@exemple.test", ["me@mondomaine.example"])
        clues, _ = await RspamdHook().observe(context)
        return {c.clue_code: c for c in clues}

    async def test_l_encodage_superflu_est_un_indice(self) -> None:
        codes = await self._codes("4.15 / 100.00];\tSUBJ_EXCESS_BASE64(1.50)[];\tFROM_EXCESS_BASE64(1.50)[];\tZERO_FONT(0.10)[1")
        indice = codes["RSPAMD_OBFUSCATION_SYMBOL"]
        self.assertEqual(indice.direction, "adverse")
        self.assertEqual(indice.article_code, "RSPAMD-009")
        self.assertEqual(indice.facts["symbols"], ["FROM_EXCESS_BASE64", "SUBJ_EXCESS_BASE64"])

    async def test_le_texte_d_apercu_en_taille_zero_n_est_pas_un_deguisement(self) -> None:
        """Les gabarits d'envoi le posent partout : il ne charge rien seul."""
        codes = await self._codes("0.70 / 100.00];\tZERO_FONT(0.20)[1];\tMIME_GOOD(-0.10)[")
        self.assertNotIn("RSPAMD_OBFUSCATION_SYMBOL", codes)

    async def test_un_message_ordinaire_n_en_porte_pas(self) -> None:
        codes = await self._codes("0.50 / 100.00];\tMIME_GOOD(-0.10)[];\tONCE_RECEIVED(0.20)[")
        self.assertNotIn("RSPAMD_OBFUSCATION_SYMBOL", codes)
