from __future__ import annotations

import unittest
import json
from unittest.mock import AsyncMock
from urllib.parse import unquote
from typing import Any

from sentimail_v3.execution.outbox import bind_digest_ballots, queue_response
from sentimail_v3.conversation.action_tokens import ACTION_MARKER_RE, token_hash


class LotsAuthentifiesTests(unittest.IsolatedAsyncioTestCase):
    parent = "11111111-1111-1111-1111-111111111111"
    context = {"purpose": "daily_digest", "conversation_id": "conversation",
               "digest_ref": "D-abcdef", "digest": {"1": "message1", "2": "message2"}}
    html = ('<a href="mailto:maia@example.org?subject=Re%20S3-BALLOT-1-TOKEN-PLACEHOLDER&amp;body=un">1</a>'
            '<a href="mailto:maia@example.org?subject=Re%20S3-BALLOT-2-TOKEN-PLACEHOLDER&amp;body=deux">2</a>')

    async def test_chaque_lot_a_son_jeton_et_seulement_ses_dossiers(self):
        pool = AsyncMock()
        pool.fetchval.side_effect = [json.dumps(self.context), "child1", "child2"]
        rendered = await bind_digest_ballots(pool, self.parent, self.html, "secret-test")
        tokens = ACTION_MARKER_RE.findall(unquote(rendered))
        self.assertEqual(len(set(tokens)), 2)
        writes = pool.fetchval.call_args_list[1:]
        for index, call in enumerate(writes, 1):
            child_context = json.loads(call.args[4])
            self.assertEqual(child_context["digest"], {str(index): f"message{index}"})
            self.assertEqual(child_context["digest_parent_action"], self.parent)
            self.assertEqual(child_context["digest_ref"], "D-abcdef")
            self.assertEqual(call.args[3], token_hash(tokens[index - 1]))
            self.assertNotIn(tokens[index - 1], str(call))
        self.assertNotIn("TOKEN-PLACEHOLDER", rendered)

    async def test_un_essai_smtp_reutilise_les_actions_avec_de_nouveaux_jetons(self):
        ids, tokens = [], []
        for _ in range(2):
            pool = AsyncMock()
            pool.fetchval.side_effect = [self.context, "child1", "child2"]
            rendered = await bind_digest_ballots(pool, self.parent, self.html, "secret-test")
            ids.append([call.args[2] for call in pool.fetchval.call_args_list[1:]])
            tokens.append(ACTION_MARKER_RE.findall(unquote(rendered)))
        self.assertEqual(ids[0], ids[1])
        self.assertNotEqual(tokens[0], tokens[1])

    async def test_un_marqueur_dans_le_texte_ne_cree_pas_d_action(self):
        pool = AsyncMock()
        text = "S3-BALLOT-99-TOKEN-PLACEHOLDER"
        self.assertEqual(await bind_digest_ballots(pool, self.parent, text, "test"), text)
        pool.fetchval.assert_not_called()

    async def test_un_lot_hors_dossier_ou_deja_consomme_bloque_l_envoi(self):
        pool = AsyncMock()
        pool.fetchval.return_value = {**self.context, "digest": {}}
        with self.assertRaisesRegex(ValueError, "étranger"):
            await bind_digest_ballots(pool, self.parent, self.html, "test")
        pool.fetchval.side_effect = [self.context, None]
        with self.assertRaisesRegex(ValueError, "déjà utilisé"):
            await bind_digest_ballots(pool, self.parent, self.html, "test")


class _Connection:
    def __init__(self) -> None:
        self.executed: list[str] = []

    async def fetchval(self, query: str, *args: Any) -> Any:
        self.executed.append(query)
        return 1

    async def execute(self, query: str, *args: Any) -> str:
        self.executed.append(query)
        return "INSERT 1"


class ExpediteurObligatoireTests(unittest.IsolatedAsyncioTestCase):
    """Une lettre sans expéditeur ne peut recevoir aucune réponse.

    Le 18 août, six courriers de contrôle qualité sont partis avec un
    expéditeur et un « Reply-To » vides, vers trois destinataires. Personne ne
    pouvait y répondre : la question posée était sans retour possible.

    L'appelant fautif a été retiré, mais un paramètre vide accepté en silence
    reste un piège pour le prochain. La file refuse désormais de mettre en
    attente ce qu'on ne pourra pas lire ni à quoi on ne pourra pas répondre.
    """

    async def _appel(self, sender: str, reply_to: str) -> None:
        await queue_response(
            _Connection(),  # type: ignore[arg-type]
            "11111111-1111-1111-1111-111111111111",
            1,
            "moi@mondomaine.example",
            sender,
            reply_to,
            "Objet",
            "Corps",
        )

    async def test_un_expediteur_vide_est_refuse(self) -> None:
        with self.assertRaises(ValueError):
            await self._appel("", "maia@sentinel.mondomaine.example")

    async def test_une_adresse_de_reponse_vide_est_refusee(self) -> None:
        with self.assertRaises(ValueError):
            await self._appel("MAIA <maia@mondomaine.example>", "")

    async def test_des_espaces_ne_valent_pas_une_adresse(self) -> None:
        with self.assertRaises(ValueError):
            await self._appel("   ", "maia@sentinel.mondomaine.example")

    async def test_un_destinataire_vide_est_refuse(self) -> None:
        with self.assertRaises(ValueError):
            await queue_response(
                _Connection(),  # type: ignore[arg-type]
                "11111111-1111-1111-1111-111111111111",
                1,
                "",
                "MAIA <maia@mondomaine.example>",
                "maia@sentinel.mondomaine.example",
                "Objet",
                "Corps",
            )

    async def test_un_appel_complet_passe(self) -> None:
        connection = _Connection()
        await queue_response(
            connection,  # type: ignore[arg-type]
            "11111111-1111-1111-1111-111111111111",
            1,
            "moi@mondomaine.example",
            "MAIA <maia@mondomaine.example>",
            "maia@sentinel.mondomaine.example",
            "Objet",
            "Corps",
        )
        self.assertTrue(connection.executed)


if __name__ == "__main__":
    unittest.main()
