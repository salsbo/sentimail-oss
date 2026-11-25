"""Quand l'enveloppe des indésirables échoue, le repli se dit, et un dangereux reste retenu.

Le repli annotait l'original - liens actifs, pièces jointes intactes - sans
rien écrire : ni journal, ni audit, ni marque sur l'événement de livraison. Un
message que le Code tient pour dangereux partait ainsi intact, au seul motif
qu'on n'avait pas su composer l'avis qui devait le remplacer.
"""

from __future__ import annotations

import inspect
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from sentimail_v3 import identity
from sentimail_v3.execution import delivery
from sentimail_v3.execution.delivery import release_original

BRUT = (
    b"From: Service <service@exp.example>\r\n"
    b"To: personne@dest.example\r\n"
    b"Subject: Votre facture\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n\r\n"
    b'<html><body><a href="https://payer.exp.example/x">Payer</a></body></html>\r\n'
)


class _Connection:
    def __init__(self, pool: "_Pool") -> None:
        self.pool = pool

    def transaction(self) -> "_Connection":
        return self

    async def __aenter__(self) -> "_Connection":
        return self

    async def __aexit__(self, *args: object) -> bool:
        return False

    async def fetchrow(self, query: str, *args: object) -> dict[str, object]:
        self.pool.calls.append((query, args))
        return {
            "delivery_status": "held",
            "raw_eml": self.pool.raw,
            "envelope_from": "rebond@exp.example",
            "envelope_recipients": ["personne@dest.example"],
            "case_id": "case-id",
            "participant_email": "personne@dest.example",
        }

    async def execute(self, query: str, *args: object) -> str:
        self.pool.calls.append((query, args))
        return "UPDATE 1"


class _Pool:
    def __init__(self, raw: bytes = BRUT) -> None:
        self.raw = raw
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    def acquire(self) -> _Connection:
        return _Connection(self)

    async def execute(self, query: str, *args: object) -> str:
        self.calls.append((query, args))
        return "UPDATE 1"

    def wrote(self, fragment: str) -> list[tuple[str, tuple[object, ...]]]:
        return [call for call in self.calls if fragment in call[0]]


def _settings() -> SimpleNamespace:
    return SimpleNamespace(
        raw_eml_key_file=None,
        assistant_token_secret="",
        render_sandbox_url=None,
        relay_host="relay",
        relay_port=25,
        action_address="maia@sentinel.dest.example",
        action_aliases=(),
        assistant_sender="MAIA <maia@dest.example>",
        probe_recipient="sonde@sentinel.dest.example",
    )


def _payload(call: tuple[str, tuple[object, ...]]) -> dict[str, object]:
    return json.loads(str(call[1][-1]))


class RepliDEnveloppeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        identity.reset_cache()

    async def _livrer(self, pool: _Pool, classify_as: str, *, casse: bool) -> tuple[str, AsyncMock]:
        smtp = AsyncMock(return_value=({}, "250 2.0.0 Ok: queued as ABC123"))
        patches = [patch("sentimail_v3.execution.delivery.aiosmtplib.send", new=smtp)]
        if casse:
            patches.append(
                patch(
                    "sentimail_v3.execution.delivery.build_junk_envelope",
                    side_effect=ValueError("en-tête illisible"),
                )
            )
        for p in patches:
            p.start()
        try:
            result = await release_original(
                pool,  # type: ignore[arg-type]
                _settings(),  # type: ignore[arg-type]
                "message-id",
                reason="final_judgment_junk",
                classify_as=classify_as,
                classify_reasons=["Authentification : échec"],
            )
        finally:
            for p in patches:
                p.stop()
        return result, smtp

    async def test_un_dangereux_dont_l_enveloppe_echoue_reste_retenu(self) -> None:
        for classement in ("malicious", "dangerous"):
            with self.subTest(classement=classement):
                pool = _Pool()
                result, smtp = await self._livrer(pool, classement, casse=True)

                self.assertEqual(result, "held_envelope_failed")
                smtp.assert_not_awaited()
                transitions = pool.wrote("UPDATE messages")
                self.assertEqual(transitions[-1][1][1], "held")
                dossiers = [
                    call
                    for call in pool.wrote("UPDATE delivery_cases")
                    if "original_delivery_allowed=false" in call[0]
                ]
                self.assertEqual(len(dossiers), 1)
                self.assertNotIn("state=", dossiers[0][0])
                details = _payload(dossiers[0])
                self.assertEqual(details["review_guard"], "fail_closed")
                self.assertEqual(details["review_guard_reason"], "junk_envelope_failed")
                self.assertEqual(details["review_guard_error"], "ValueError")
                self.assertEqual(details["unfiled_classification"], classement)
                audits = pool.wrote("delivery.junk_envelope_failed_held")
                self.assertEqual(len(audits), 1)
                self.assertEqual(pool.wrote("INSERT INTO delivery_events"), [])

    async def test_un_indesirable_dont_l_enveloppe_echoue_part_annote_et_le_dit(self) -> None:
        pool = _Pool()
        result, smtp = await self._livrer(pool, "spam", casse=True)

        self.assertEqual(result, "released")
        smtp.assert_awaited_once()
        envoye = smtp.await_args.args[0]
        self.assertIn(b"X-Sentimail-Verdict: spam", envoye)
        evenements = pool.wrote("INSERT INTO delivery_events")
        self.assertEqual(len(evenements), 1)
        self.assertEqual(evenements[0][1][1], "original_filed_as_junk")
        details = _payload(evenements[0])
        self.assertEqual(details["junk_envelope"], "annotated_original")
        self.assertEqual(details["junk_envelope_error"], "ValueError")
        audits = pool.wrote("delivery.junk_envelope_fallback")
        self.assertEqual(len(audits), 1)
        audit = _payload(audits[0])
        self.assertEqual(audit["classify_as"], "spam")
        self.assertEqual(audit["error_type"], "ValueError")

    async def test_une_enveloppe_reussie_est_dite_neutralisee(self) -> None:
        pool = _Pool()
        result, smtp = await self._livrer(pool, "spam", casse=False)

        self.assertEqual(result, "released")
        details = _payload(pool.wrote("INSERT INTO delivery_events")[0])
        self.assertEqual(details["junk_envelope"], "neutralized")
        self.assertNotIn("junk_envelope_error", details)
        self.assertEqual(pool.wrote("delivery.junk_envelope_fallback"), [])
        self.assertIn(b"X-SentiMail-Modified: junk-envelope", smtp.await_args.args[0])

    async def test_un_objet_piege_part_sous_enveloppe_neutralisee(self) -> None:
        pool = _Pool(
            BRUT.replace(
                b"Subject: Votre facture",
                b"Subject: =?utf-8?q?Voyage_sans_limites=0A=0A?=",
            )
        )
        result, smtp = await self._livrer(pool, "malicious", casse=False)

        self.assertEqual(result, "released")
        smtp.assert_awaited_once()
        envoye = smtp.await_args.args[0]
        self.assertIn(b"X-SentiMail-Modified: junk-envelope", envoye)
        self.assertNotIn(b"payer.exp.example", envoye)

    async def test_un_message_livre_normalement_ne_porte_aucune_cle_d_enveloppe(self) -> None:
        pool = _Pool()
        smtp = AsyncMock(return_value=({}, "250 2.0.0 Ok: queued as ABC123"))
        with patch("sentimail_v3.execution.delivery.aiosmtplib.send", new=smtp):
            await release_original(
                pool,  # type: ignore[arg-type]
                _settings(),  # type: ignore[arg-type]
                "message-id",
                reason="final_judgment_deliver",
            )
        details = _payload(pool.wrote("INSERT INTO delivery_events")[0])
        self.assertNotIn("junk_envelope", details)

    def test_la_reprise_garde_le_classement_du_secours(self) -> None:
        source = inspect.getsource(delivery.retry_one_release)
        self.assertIn("coalesce(", source)
        self.assertIn("'fail_open_classify_as'", source)


if __name__ == "__main__":
    unittest.main()
