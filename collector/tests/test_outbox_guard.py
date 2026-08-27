from __future__ import annotations

import unittest
from typing import Any

from sentimail_v3.execution.outbox import queue_response


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
