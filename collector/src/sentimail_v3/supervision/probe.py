"""La sonde de bout en bout : un vrai message qui traverse, et disparaît.

Le pré-vol SMTP du watchdog frappe à la porte - EHLO, MAIL, RCPT - sans jamais
entrer : il dit que le collecteur écoute, pas qu'il traite. Un pipeline peut
accepter la connexion et pourtant ne plus rien capturer, analyser ni juger.

Cette sonde envoie un message réel vers un destinataire protégé et vérifie
qu'il est capturé et mis en analyse, dans un délai. Puis elle le supprime
aussitôt - avant que le verdict n'aboutisse, donc avant qu'aucun avis ne parte
et sans rien laisser au corpus. Elle mesure ce que le trafic réel subit :
réception, capture, entrée dans le pipeline. Le verdict lui-même est surveillé
ailleurs, par le compteur d'erreurs.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from uuid import uuid4

import aiosmtplib
import asyncpg

from sentimail_v3.config import Settings
from sentimail_v3.identity import instance_identity

MARKER = "[SENTINEL-PROBE]"


def _message(marker: str, sender: str, recipient: str) -> str:
    return (
        f"From: SentiMail Probe <{sender}>\r\n"
        f"To: {recipient}\r\n"
        f"Subject: {MARKER} {marker}\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "X-Sentinel-Probe: heartbeat\r\n\r\n"
        "Sonde de bout en bout SentiMail V3. Ce message se supprime seul.\r\n"
    )


async def _capture_seen(pool: asyncpg.Pool[Any], marker: str) -> str | None:
    return await pool.fetchval(
        "SELECT id::text FROM messages WHERE subject = $1 LIMIT 1",
        f"{MARKER} {marker}",
    )


async def _cleanup(pool: asyncpg.Pool[Any], marker: str) -> None:
    # ON DELETE CASCADE emporte investigations, clues, delivery_cases et
    # conversations : ne rien laisser derrière, jamais.
    await pool.execute(
        "DELETE FROM messages WHERE subject = $1", f"{MARKER} {marker}"
    )


async def run_probe(pool: asyncpg.Pool[Any], settings: Settings) -> dict[str, Any]:
    """Envoie un message, confirme sa capture, puis l'efface.

    Le résultat est un état exploitable par le watchdog : ok si le message a
    été capturé dans le délai, sinon la cause (envoi refusé, jamais capturé).
    Toute issue passe par le nettoyage - une sonde ne laisse pas de trace même
    quand elle échoue à mi-chemin.
    """
    if not settings.probe_enabled:
        return {"status": "disabled"}
    identite = await instance_identity(pool, settings)
    marker = uuid4().hex[:16]
    sender = identite.action_address
    recipient = identite.probe_recipient
    if not recipient:
        return {"status": "unknown", "error": "probe_recipient_missing"}
    started = time.perf_counter()
    try:
        await aiosmtplib.send(
            _message(marker, sender, recipient).encode(),
            sender=sender,
            recipients=[recipient],
            hostname=settings.watchdog_ingress_host,
            port=settings.watchdog_ingress_port,
            start_tls=False,
            timeout=15,
        )
    except Exception as exc:  # noqa: BLE001 - un envoi refusé est un résultat
        return {"status": "down", "phase": "send", "error": type(exc).__name__}

    message_id: str | None = None
    deadline = time.perf_counter() + settings.probe_timeout_seconds
    try:
        while time.perf_counter() < deadline:
            message_id = await _capture_seen(pool, marker)
            if message_id is not None:
                break
            await asyncio.sleep(1.0)
        latency_ms = round((time.perf_counter() - started) * 1000, 1)
        if message_id is None:
            return {
                "status": "down",
                "phase": "capture",
                "error": "not_captured_in_time",
                "latency_ms": latency_ms,
            }
        return {"status": "ok", "latency_ms": latency_ms}
    finally:
        # Avant tout retour : le message part, réussite ou échec.
        await _cleanup(pool, marker)
