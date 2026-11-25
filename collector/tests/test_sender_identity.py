from __future__ import annotations

import json
import unittest
from unittest.mock import AsyncMock

from sentimail_v3.code.rulebook import RuleImportError, set_sender_list_policy
from sentimail_v3.code.sender_identity import proven_identity
from sentimail_v3.conversation.human_decision import block_proven_sender


class CibleDuBannissementTests(unittest.TestCase):
    def test_faux_cic_envoye_de_truc_fr_bannit_truc_fr(self) -> None:
        identity = proven_identity(
            '"CIC" <info@cic.fr>',
            "bounce-42@mail.truc.fr",
            dmarc_pass=False,
            spf_pass=True,
        )
        self.assertEqual(identity.block_target, ("domain", "truc.fr"))
        self.assertNotIn("cic.fr", identity.domains)

    def test_dmarc_aligne_bannit_le_domaine_du_from(self) -> None:
        identity = proven_identity(
            "Promo <news@envoi.boutique.fr>",
            "bounce@amazonses.com",
            dmarc_pass=True,
            spf_pass=True,
        )
        self.assertEqual(identity.block_target, ("domain", "boutique.fr"))

    def test_signature_dkim_sans_dmarc_designe_le_signataire(self) -> None:
        identity = proven_identity(
            "Banque <alerte@banque.fr>",
            "",
            dmarc_pass=False,
            spf_pass=False,
            dkim_domain="relais.spammeur.net",
        )
        self.assertEqual(identity.block_target, ("domain", "spammeur.net"))

    def test_messagerie_publique_garde_l_adresse_exacte(self) -> None:
        identity = proven_identity(
            '"Service client Amazon" <inconnu@gmail.com>',  # audit-ok: boîte fictive, le test exige le domaine réel d'une messagerie publique
            "inconnu@gmail.com",  # audit-ok: boîte fictive, le test exige le domaine réel d'une messagerie publique
            dmarc_pass=True,
            spf_pass=True,
            dkim_domain="gmail.com",
        )
        self.assertEqual(identity.block_target, ("sender", "inconnu@gmail.com"))  # audit-ok: boîte fictive, le test exige le domaine réel d'une messagerie publique

    def test_from_usurpe_depuis_une_messagerie_publique(self) -> None:
        identity = proven_identity(
            '"CIC" <info@cic.fr>',
            "compte.jetable@hotmail.fr",  # audit-ok: boîte fictive, le test exige le domaine réel d'une messagerie publique
            dmarc_pass=False,
            spf_pass=True,
            dkim_domain="hotmail.fr",
        )
        self.assertEqual(
            identity.block_target, ("sender", "compte.jetable@hotmail.fr")  # audit-ok: boîte fictive, le test exige le domaine réel d'une messagerie publique
        )

    def test_plateforme_mutualisee_ne_devient_jamais_un_domaine(self) -> None:
        identity = proven_identity(
            '"Netflix" <info@netflix-support.example>',
            "bounces+123-abc=user=example.org@em123.sendgrid.net",
            dmarc_pass=False,
            spf_pass=True,
            dkim_domain="sendgrid.net",
        )
        self.assertIsNone(identity.block_target)

    def test_locataire_partage_garde_son_sous_domaine(self) -> None:
        identity = proven_identity(
            "X <x@forged.example>",
            "",
            dmarc_pass=False,
            spf_pass=False,
            dkim_domain="tenant123.onmicrosoft.com",
        )
        self.assertEqual(
            identity.block_target, ("domain", "tenant123.onmicrosoft.com")
        )

    def test_sans_authentification_aucune_cible(self) -> None:
        identity = proven_identity(
            "Hello brother <brother@banque.example>",
            "",
            dmarc_pass=False,
            spf_pass=False,
        )
        self.assertIsNone(identity.block_target)
        self.assertFalse(identity.proven)


class RegleDomaineTests(unittest.IsolatedAsyncioTestCase):
    async def test_une_regle_domaine_est_enregistree_en_scope_domain(self) -> None:
        connection = AsyncMock()
        await set_sender_list_policy(
            connection,
            "user@example.org",
            "Truc.FR.",
            "hold",
            source="authenticated_smtp_choice_b",
            scope="domain",
        )
        stored = connection.execute.await_args_list[1].args
        self.assertIn("VALUES ($1,$5,$2,$3,true,$4)", stored[0])
        self.assertEqual(stored[2], "truc.fr")
        self.assertEqual(stored[5], "domain")

    async def test_un_domaine_invalide_est_refuse(self) -> None:
        with self.assertRaises(RuleImportError):
            await set_sender_list_policy(
                AsyncMock(),
                "user@example.org",
                "localhost",
                "hold",
                source="authenticated_smtp_choice_b",
                scope="domain",
            )


class BannissementProuveTests(unittest.IsolatedAsyncioTestCase):
    async def test_identite_non_prouvee_ne_pose_aucune_regle(self) -> None:
        connection = AsyncMock()
        connection.fetchrow.return_value = {
            "from_header": "CIC <info@cic.fr>",
            "envelope_from": "",
            "dmarc": False,
            "spf": False,
            "dkim": None,
        }
        target = await block_proven_sender(
            connection,
            "user@example.org",
            "11111111-1111-1111-1111-111111111111",
            source="authenticated_smtp_choice_b",
        )
        self.assertIsNone(target)
        sql = [call.args[0] for call in connection.execute.await_args_list]
        self.assertFalse(any("sender_policies" in value for value in sql))
        self.assertIn("sender_list.identity_unproven", sql[0])

    async def test_identite_prouvee_bannit_le_domaine_reel(self) -> None:
        connection = AsyncMock()
        connection.fetchrow.return_value = {
            "from_header": "CIC <info@cic.fr>",
            "envelope_from": "bounce@mail.truc.fr",
            "dmarc": False,
            "spf": True,
            "dkim": None,
        }
        target = await block_proven_sender(
            connection,
            "user@example.org",
            "11111111-1111-1111-1111-111111111111",
            source="authenticated_smtp_choice_b",
        )
        self.assertEqual(target, ("domain", "truc.fr"))
        insert = next(
            call
            for call in connection.execute.await_args_list
            if "INSERT INTO sender_policies" in call.args[0]
        )
        self.assertEqual(insert.args[2], "truc.fr")
        audit = connection.execute.await_args_list[-1].args
        self.assertEqual(json.loads(audit[1])["value"], "truc.fr")


if __name__ == "__main__":
    unittest.main()
