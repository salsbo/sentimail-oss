"""Répondre à la sonde du MX : ce destinataire existe-t-il ?

Le MX public vérifie chaque destinataire avant d'accepter un message
(``reject_unverified_recipient``). Sa sonde suit la route normale du courrier,
arrive ici avec l'expéditeur ``PROBE_LOCAL_PART`` et s'arrête après RCPT. Le
collecteur ne connaît pas les boîtes : il pose la même question, sans message,
au serveur qui les tient (le relais de livraison) et ne rapporte qu'un refus
définitif d'adresse (5xx avec un statut 5.1.x).

Trois règles :

- seule la sonde peut être refusée. Un message réel, déjà accepté par le MX,
  n'est jamais refusé ici : le MX renverrait sinon un avis de non-remise à un
  expéditeur souvent faux ou injoignable ;
- seuls les domaines protégés actifs sont vérifiés, jamais une adresse de
  SentiMail lui-même (adresse d'action et ses alias) ;
- toute autre issue (délai, refus temporaire ou de politique, exception, base
  ou relais injoignable) laisse passer, comme avant la vérification : une
  panne ne fait jamais refuser du courrier légitime. La sonde reçoit alors un
  report (``UNVERIFIED_PROBE_REPLY``), pour que le MX ne retienne pas l'adresse
  comme connue.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any, Protocol

import aiosmtplib

# Partie locale de l'expéditeur des sondes, fixée par ``address_verify_sender``
# dans infra/postfix/main.cf.tmpl. Les deux valeurs doivent rester identiques
# (test_recipient_check le vérifie).
PROBE_LOCAL_PART = "sentimail-verification"
# Échange complet borné sous la fenêtre d'attente de Postfix (trois relevés
# espacés de 3 s) : passé ce délai, la sonde laisse passer.
PROBE_TIMEOUT_SECONDS = 4.0
UNKNOWN_RECIPIENT_REPLY = "550 5.1.1 destinataire inconnu"
# Sonde sans réponse sûre : un report, jamais un 250. Le MX accepte quand même
# le message (unverified_recipient_defer_code = 250) mais ne garde ce résultat
# qu'une heure ; un 250 l'aurait tenu pour une adresse connue pendant 31 jours.
UNVERIFIED_PROBE_REPLY = "450 4.4.3 verification du destinataire indisponible"


class ActionRecipients(Protocol):
    async def is_action_recipient(self, recipients: list[str]) -> bool: ...


@dataclass(frozen=True)
class ProbeResult:
    outcome: str
    detail: str = ""


def is_probe(sender: str) -> bool:
    return sender.partition("@")[0].casefold() == PROBE_LOCAL_PART


async def _ask(address: str, host: str, port: int, timeout: float) -> tuple[int, str]:
    client = aiosmtplib.SMTP(
        hostname=host,
        port=port,
        timeout=timeout,
        start_tls=False,
        local_hostname="sentimail-v3-collector",
    )
    answered = False
    try:
        await client.connect()
        await client.mail("")
        try:
            response = await client.rcpt(address)
        except aiosmtplib.SMTPRecipientRefused as exc:
            answered = True
            return exc.code, exc.message
        answered = True
        return response.code, response.message
    finally:
        # QUIT poli après une vraie réponse : une coupure sèche après RCPT
        # ressemble, dans le journal du relais, à un balayage d'adresses.
        # Sans réponse (délai, annulation), on coupe aussitôt pour tenir la
        # borne de temps.
        if client.is_connected:
            if answered:
                try:
                    await client.quit()
                except (aiosmtplib.SMTPException, OSError, asyncio.TimeoutError):
                    client.close()
            else:
                client.close()


async def downstream_answer(
    address: str,
    *,
    host: str,
    port: int,
    timeout: float = PROBE_TIMEOUT_SECONDS,
) -> tuple[int, str] | None:
    """Réponse RCPT du relais (code, texte), ou None s'il n'a pas répondu."""
    if not address.isascii():
        # Une adresse internationalisée exigerait SMTPUTF8 de bout en bout ;
        # sans certitude, elle n'est pas vérifiée.
        return None
    try:
        return await asyncio.wait_for(_ask(address, host, port, timeout), timeout)
    except (aiosmtplib.SMTPException, OSError, asyncio.TimeoutError, UnicodeError):
        return None


_ENHANCED_STATUS = re.compile(r"^[245]\.\d{1,3}\.\d{1,3}$")


def _is_unknown_address(code: int, message: str) -> bool:
    return 500 <= code < 600 and message.lstrip().startswith("5.1.")


def _detail(code: int, message: str) -> str:
    """Code et statut étendu seulement : jamais un mot qui pourrait être l'adresse."""
    first = message.split(" ", 1)[0] if message else ""
    return f"{code} {first}" if _ENHANCED_STATUS.match(first) else str(code)


async def probe_outcome(
    pool: Any,
    conversations: ActionRecipients,
    *,
    sender: str,
    address: str,
    relay_host: str,
    relay_port: int,
) -> ProbeResult:
    """Issue de la vérification ; seul ``unknown`` fait refuser le destinataire."""
    if not is_probe(sender):
        return ProbeResult("not_probe")
    domain = address.rpartition("@")[2].casefold()
    try:
        protected = await pool.fetchval(
            "SELECT 1 FROM mx_relay_domains WHERE fqdn = lower($1)", domain
        )
        own_address = await conversations.is_action_recipient([address])
    except Exception as exc:  # noqa: BLE001 - une vérification en panne laisse passer
        return ProbeResult("error", type(exc).__name__)
    if not protected:
        return ProbeResult("not_protected")
    if own_address:
        return ProbeResult("own_address")
    answer = await downstream_answer(address, host=relay_host, port=relay_port)
    if answer is None:
        return ProbeResult("unverified", "no_answer")
    code, message = answer
    detail = _detail(code, message)
    if 200 <= code < 300:
        return ProbeResult("known", detail)
    if _is_unknown_address(code, message):
        return ProbeResult("unknown", detail)
    return ProbeResult("unverified", detail)
