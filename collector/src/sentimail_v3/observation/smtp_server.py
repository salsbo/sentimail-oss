from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

import aiosmtplib
import asyncpg
from aiosmtpd.smtp import SMTP, Envelope, Session

from sentimail_v3.config import Settings, load_settings
from sentimail_v3.conversation.conversation import ConversationStore
from sentimail_v3.crypto import load_key
from sentimail_v3.identity import instance_identity
from sentimail_v3.conversation.provider_setup import ProviderSetup
from sentimail_v3.observation.recipient_check import (
    UNKNOWN_RECIPIENT_REPLY,
    UNVERIFIED_PROBE_REPLY,
    ProbeResult,
    is_probe,
    probe_outcome,
)
from sentimail_v3.observation.storage import CaptureResult, Store
from sentimail_v3.code.reference import nommer_dossier

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("sentimail-v3")
logging.getLogger("mail.log").setLevel(logging.WARNING)
logging.getLogger("aiosmtpd.smtp").setLevel(logging.WARNING)


def _log(event: str, **fields: object) -> None:
    fields = nommer_dossier(dict(fields))
    if event.endswith((".error", "_failed")):
        level = logging.ERROR
    elif event.endswith("_deferred") or event == "database.wait":
        level = logging.WARNING
    else:
        level = logging.INFO
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": logging.getLevelName(level).lower(),
        "event": event,
        **fields,
    }
    logger.log(level, json.dumps(payload, default=str, ensure_ascii=False))


async def _connect_database(url: str) -> asyncpg.Pool[Any]:
    last_error: Exception | None = None
    for attempt in range(1, 31):
        try:
            return await asyncpg.create_pool(url, min_size=1, max_size=10)
        except Exception as exc:  # noqa: BLE001 - attente de toute panne DB
            last_error = exc
            _log("database.wait", attempt=attempt, error=type(exc).__name__)
            await asyncio.sleep(2)
    raise RuntimeError("database unavailable") from last_error


def recipient_groups(
    recipients: list[str], *, decision_mode: bool, action_recipient: bool
) -> list[list[str]]:
    if decision_mode and not action_recipient:
        return [[recipient] for recipient in recipients]
    return [recipients]


class Handler:
    def __init__(
        self,
        store: Store,
        conversations: ConversationStore,
        provider_setup: ProviderSetup,
        settings: Settings,
    ) -> None:
        self.store = store
        self.conversations = conversations
        self.provider_setup = provider_setup
        self.settings = settings

    async def _relay(self, raw: bytes, sender: str, recipients: list[str]) -> None:
        await aiosmtplib.send(
            raw,
            sender=sender,
            recipients=recipients,
            hostname=self.settings.relay_host,
            port=self.settings.relay_port,
            start_tls=False,
            timeout=30,
        )

    async def handle_RCPT(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        address: str,
        rcpt_options: list[str],
    ) -> str:
        # Seule la sonde de vérification du MX peut être refusée ou reportée
        # ici (voir recipient_check) ; tout autre destinataire est accepté
        # comme avant.
        del server, session
        sender = envelope.mail_from or ""
        try:
            result = await probe_outcome(
                self.store.pool,
                self.conversations,
                sender=sender,
                address=address,
                relay_host=self.settings.relay_host,
                relay_port=self.settings.relay_port,
            )
        except Exception as exc:  # noqa: BLE001 - une exception ne doit jamais devenir un 5xx
            result = ProbeResult(
                "error" if is_probe(sender) else "not_probe", type(exc).__name__
            )
        if result.outcome != "not_probe":
            event = {
                "error": "recipient_probe.error",
                "unverified": "recipient_probe_deferred",
            }.get(result.outcome, "recipient_probe.checked")
            _log(
                event,
                outcome=result.outcome,
                detail=result.detail,
                recipient_domain=address.rpartition("@")[2].casefold(),
            )
        if result.outcome == "unknown":
            return UNKNOWN_RECIPIENT_REPLY
        if result.outcome in {"error", "unverified"}:
            return UNVERIFIED_PROBE_REPLY
        envelope.rcpt_tos.append(address)
        envelope.rcpt_options.extend(rcpt_options)
        return "250 OK"

    async def handle_DATA(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
    ) -> str:
        del server
        request_started = time.perf_counter()
        raw = envelope.original_content or envelope.content
        if not isinstance(raw, bytes):
            return "451 4.3.0 contenu SMTP non binaire"
        sender = envelope.mail_from or ""
        recipients = list(envelope.rcpt_tos)
        sender_domain = sender.rsplit("@", 1)[-1].casefold() if "@" in sender else ""
        peer = session.peer if isinstance(session.peer, tuple) else (None, None)
        smtp = {
            "peer_ip": peer[0],
            "peer_port": peer[1],
            "helo": session.host_name,
            "protocol": "ESMTP" if session.extended_smtp else "SMTP",
            "tls": session.ssl or {},
            "authenticated": bool(session.authenticated),
            "mail_options": list(envelope.mail_options),
            "rcpt_options": {
                str(index): value for index, value in enumerate(envelope.rcpt_options)
            },
        }

        # Une seule lecture par message : les trois branches ci-dessous doivent
        # voir la même adresse d'action, même si l'admin la change pendant le
        # traitement.
        is_action = await self.conversations.is_action_recipient(recipients)

        if is_action:
            try:
                credential_status = await self.provider_setup.handle(raw, sender)
            except ValueError as exc:
                _log(
                    "credential_setup.rejected",
                    error=type(exc).__name__,
                    detail=str(exc)[:200],
                    sender_domain=sender_domain,
                )
                return f"550 5.6.0 configuration MAIA refusée: {str(exc)[:120]}"
            except Exception as exc:  # noqa: BLE001 - ne jamais archiver un secret en repli
                _log(
                    "credential_setup.error",
                    error=type(exc).__name__,
                    detail=str(exc)[:200],
                    sender_domain=sender_domain,
                )
                return "451 4.3.0 configuration MAIA temporairement indisponible"
            if credential_status is not None:
                _log("credential_setup.received", status=credential_status)
                return "250 2.0.0 configuration transmise à MAIA"

        capture: CaptureResult | None = None
        captures: list[CaptureResult] = []
        capture_started = time.perf_counter()
        try:
            groups = recipient_groups(
                recipients,
                decision_mode=self.settings.decision_mode,
                action_recipient=is_action,
            )
            for recipient_group in groups:
                captures.append(
                    await self.store.capture(raw, sender, recipient_group, smtp)
                )
            capture = captures[0]
            _log(
                "message.captured",
                message_ids=[item.message_id for item in captures],
                inserted=sum(item.inserted for item in captures),
                previous_delivery_statuses=[item.delivery_status for item in captures],
                sender_domain=sender_domain,
                recipient_count=len(recipients),
                size_bytes=len(raw),
                duration_ms=round((time.perf_counter() - capture_started) * 1000, 2),
            )
            if not self.settings.decision_mode and capture.delivery_status == "delivered":
                _log("message.duplicate_acknowledged", message_id=capture.message_id)
                return "250 2.0.0 deja livre"
        except Exception as exc:  # noqa: BLE001 - capture fail-open
            _log(
                "message.capture_failed",
                error=type(exc).__name__,
                detail=str(exc)[:500],
                sender_domain=sender_domain,
                recipient_count=len(recipients),
                size_bytes=len(raw),
                duration_ms=round((time.perf_counter() - capture_started) * 1000, 2),
            )
            if self.settings.decision_mode:
                return "451 4.3.0 analyse SentiMail temporairement indisponible"

        if is_action:
            if capture is None:
                return "451 4.3.0 directive non enregistrée, réessayer"
            try:
                status = await self.conversations.record_inbound(capture.message_id)
                _log(
                    "directive.received",
                    message_id=capture.message_id,
                    status=status,
                )
                return "250 2.0.0 directive transmise à MAIA"
            except Exception as exc:  # noqa: BLE001 - Postfix doit retenter
                _log(
                    "directive.capture_failed",
                    message_id=capture.message_id,
                    error=type(exc).__name__,
                    detail=str(exc)[:500],
                )
                return "451 4.3.0 directive temporairement indisponible"

        if self.settings.decision_mode:
            if capture is None:
                return "451 4.3.0 message non enregistre"
            _log(
                "message.accepted_for_analysis",
                message_ids=[item.message_id for item in captures],
                sender_domain=sender_domain,
                recipients=len(recipients),
                size_bytes=len(raw),
                duration_ms=round((time.perf_counter() - request_started) * 1000, 2),
            )
            return "250 2.0.0 stocke pour analyse par MAIA"

        try:
            relay_started = time.perf_counter()
            await self._relay(raw, sender, recipients)
            relay_duration_ms = round(
                (time.perf_counter() - relay_started) * 1000, 2
            )
        except Exception as exc:  # noqa: BLE001 - tout echec SMTP est temporaire
            if capture is not None:
                await self.store.mark_deferred(capture.message_id, str(exc))
            _log(
                "message.relay_deferred",
                message_id=capture.message_id if capture else None,
                error=type(exc).__name__,
                sender_domain=sender_domain,
                duration_ms=round((time.perf_counter() - request_started) * 1000, 2),
            )
            return "451 4.4.1 livraison SMTP temporairement impossible"

        if capture is not None:
            try:
                await self.store.mark_delivered(capture.message_id)
            except Exception as exc:  # noqa: BLE001 - livraison deja acceptee
                _log(
                    "message.delivery_mark_failed",
                    message_id=capture.message_id,
                    error=type(exc).__name__,
                )
        _log(
            "message.delivered",
            message_id=capture.message_id if capture else None,
            captured=capture is not None,
            recipients=len(recipients),
            size_bytes=len(raw),
            sender_domain=sender_domain,
            relay_duration_ms=relay_duration_ms,
            duration_ms=round((time.perf_counter() - request_started) * 1000, 2),
        )
        return "250 2.0.0 stocke et relaye"


async def main() -> None:
    settings = load_settings()
    pool = await _connect_database(settings.database_url)
    encryption_key = load_key(settings.raw_eml_key_file)
    identite = await instance_identity(pool, settings)
    # `settings=settings` fait relire l'identité à chaud (cache 60 s) à chaque
    # message : le routage entrant (is_action_recipient) et la composition des
    # avis (queue_invitation, challenge give_directive) suivent une adresse
    # d'action changée en admin sans redémarrage de ce process.
    conversations = ConversationStore(
        pool,
        identite.action_address,
        identite.assistant_sender,
        settings.render_sandbox_url,
        identite.action_aliases,
        encryption_key,
        settings=settings,
    )
    provider_setup = ProviderSetup(pool, settings)
    await provider_setup.ensure_bootstrap()
    handler = Handler(
        Store(pool, encryption_key), conversations, provider_setup, settings
    )
    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        lambda: SMTP(
            handler,
            hostname="sentimail-v3-collector",
            enable_SMTPUTF8=True,
            decode_data=False,
        ),
        host=settings.smtp_host,
        port=settings.smtp_port,
    )
    _log(
        "smtp.started",
        component="collector",
        host=settings.smtp_host,
        port=settings.smtp_port,
        relay_host=settings.relay_host,
        relay_port=settings.relay_port,
        conversation_enabled=settings.conversation_enabled,
        decision_mode=settings.decision_mode,
    )
    try:
        async with server:
            await server.serve_forever()
    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
