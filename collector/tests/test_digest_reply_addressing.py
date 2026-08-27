"""L'accusé d'un récapitulatif revient à qui a répondu, à personne d'autre.

Le 26 août, une destinataire a renvoyé son bulletin sans cocher de case. Aucune
décision n'étant lue, le destinataire de l'accusé n'était plus déduit d'aucun
dossier et retombait sur l'adresse de l'exploitant : elle n'a jamais eu de
réponse, et l'exploitant a reçu un reproche sur une réponse qu'il n'avait pas
écrite. Le courrier suit désormais l'auteur de la réponse, et lui seul.
"""

from __future__ import annotations

import unittest
from typing import Any
from unittest.mock import patch

from sentimail_v3.conversation import assistant
from sentimail_v3.identity import reset_cache

AUTEUR = "destinataire@mondomaine.example"
EXPLOITANT = "exploitant@mondomaine.example"


class _Settings:
    operator_address = EXPLOITANT
    operator_addresses = (EXPLOITANT,)
    action_address = "maia@sentinel.mondomaine.example"
    action_aliases: tuple[str, ...] = ()
    assistant_sender = "MAIA <maia@mondomaine.example>"
    probe_recipient = "sonde@sentinel.mondomaine.example"


class _Connection:
    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple[Any, ...]]] = []

    def transaction(self):
        return _Async(None)

    async def execute(self, sql: str, *args: Any) -> None:
        self.executed.append((sql, args))


class _Async:
    """Contexte asynchrone minimal, pour `acquire()` comme pour `transaction()`."""

    def __init__(self, value: Any) -> None:
        self._value = value

    async def __aenter__(self) -> Any:
        return self._value

    async def __aexit__(self, *_: Any) -> bool:
        return False


class _Pool:
    def __init__(self, dossiers: dict[str, dict[str, Any]], auteur: str = AUTEUR):
        self._dossiers = dossiers
        self._auteur = auteur
        self.connection = _Connection()
        self.remaining_args: tuple[Any, ...] = ()

    async def fetchval(self, sql: str, *args: Any) -> Any:
        if "participant_email FROM conversations" in sql:
            return self._auteur or None
        if "count(*)" in sql:
            self.remaining_args = args
            return 0
        return None

    async def fetchrow(self, sql: str, *args: Any) -> Any:
        if "instance_identity" in sql:
            return None
        if "delivery_cases" in sql:
            return self._dossiers.get(str(args[0]))
        return None

    async def execute(self, sql: str, *args: Any) -> None:
        self.connection.executed.append((sql, args))

    def acquire(self):
        return _Async(self.connection)


def _message(texte: str, corps: str | None = None) -> dict[str, Any]:
    return {
        "id": "11111111-1111-1111-1111-111111111111",
        "conversation_id": "22222222-2222-2222-2222-222222222222",
        "user_text": texte,
        "body_text": corps if corps is not None else texte,
    }


BULLETIN_VIERGE = (
    "Bonjour MAIA,\n\nVoici mes réponses. Récapitulatif D-e96119\n"
    "Je mets une croix dans une seule case par message.\n\n"
    "1. Premium Watch... Premium Band???\n[ ] A [ ] B [ ] C :\n\n"
    "2. New Dress. Fall Arrivals\n[ ] A [ ] B [ ] C :\n\nMerci !\n"
)


class AccuseSuitLAuteurTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        reset_cache()

    async def _repondre(
        self,
        pool: _Pool,
        message: dict[str, Any],
        mapping: dict[str, str],
    ) -> list[Any]:
        envois: list[Any] = []

        async def _queue(connection, *args, **kwargs):
            envois.append(args)

        async def _pas_de_modele(*_: Any, **__: Any):
            return [], None

        with (
            patch.object(assistant, "queue_response", _queue),
            patch.object(assistant, "_understand_digest_reply", _pas_de_modele),
        ):
            await assistant._process_digest_reply(
                pool, None, _Settings(), message, mapping, "D-e96119"
            )
        return envois

    async def test_un_bulletin_sans_croix_repond_a_son_auteur(self) -> None:
        pool = _Pool({})
        envois = await self._repondre(
            pool, _message("", BULLETIN_VIERGE), {"1": "uuid-1", "2": "uuid-2"}
        )
        self.assertEqual(len(envois), 1)
        # queue_response(conversation_id, case_id, participant, ...)
        self.assertEqual(envois[0][2], AUTEUR)

    async def test_le_decompte_restant_porte_sur_l_auteur(self) -> None:
        pool = _Pool({})
        await self._repondre(
            pool, _message("", BULLETIN_VIERGE), {"1": "uuid-1", "2": "uuid-2"}
        )
        self.assertEqual(pool.remaining_args, (AUTEUR,))

    async def test_sans_auteur_connu_aucune_lettre_ne_part(self) -> None:
        pool = _Pool({}, auteur="")
        envois = await self._repondre(
            pool, _message("", BULLETIN_VIERGE), {"1": "uuid-1"}
        )
        self.assertEqual(envois, [])

    async def test_un_dossier_d_un_autre_ne_se_decide_pas_d_ici(self) -> None:
        pool = _Pool(
            {
                "uuid-1": {
                    "subject": "Facture",
                    "from_header": "compta@exemple.fr",
                    "envelope_from": "compta@exemple.fr",
                    "delivery_status": "held",
                    "case_id": "33333333-3333-3333-3333-333333333333",
                    "participant_email": "quelqu-un-d-autre@mondomaine.example",
                }
            }
        )
        envois = await self._repondre(pool, _message("1 A"), {"1": "uuid-1"})
        self.assertEqual(len(envois), 1)
        self.assertEqual(envois[0][2], AUTEUR)
        corps = envois[0][6]
        self.assertNotIn("Facture", corps)
        self.assertIn("ne correspondent à rien", corps)


if __name__ == "__main__":
    unittest.main()
