"""Santé du MX : maître Postfix actif et file entrante sans blocage ancien.

Ce MX ne relaie que vers les domaines protégés. Un message en file qui ne va
vers aucun d'eux ne peut être qu'une notification rédigée par Postfix lui-même
(expéditeur vide) : elle est comptée à part et ne rend pas le MX malade. Le
3 novembre 2026, un accusé de livraison pour un faux « Interactive Brokers »,
coincé 5 jours faute de serveur chez le fraudeur, a rougi l'inventaire du serveur.
Dans le doute (domaine impossible à vérifier), le message compte comme entrant.
"""

from __future__ import annotations

import json
import math
import os
import selectors
import subprocess
import time
from typing import Any, Callable, Optional

MAX_QUEUE_AGE_SECONDS = 600
POSTFIX_TIMEOUT_SECONDS = 1.0
QUEUE_TIMEOUT_SECONDS = 2.0
MAX_QUEUE_BYTES = 4 * 1024 * 1024
MAX_QUEUE_MESSAGES = 10_000
LOOKUP_TIMEOUT_SECONDS = 1.0
# Le healthcheck Docker coupe à 5 s : postfix status (1 s) et la file (2 s)
# laissent 1,5 s à toutes les vérifications de domaine réunies.
LOOKUP_BUDGET_SECONDS = 1.5
MAX_DOMAIN_LOOKUPS = 20

RelayLookup = Callable[[str], Optional[bool]]
# postqueue -j écrit « MAILER-DAEMON » pour un expéditeur vide (constaté le
# 3 novembre 2026). Un expéditeur réel « MAILER-DAEMON » sans domaine est
# refusé à l'arrivée par reject_non_fqdn_sender.
_NULL_SENDERS = frozenset({"", "MAILER-DAEMON"})


class ProbeFailure(RuntimeError):
    """Raison technique fixe ; jamais de sortie brute de Postfix."""


def _outbound_notice(record: dict[str, Any], is_relay_domain: RelayLookup | None) -> bool:
    """Une notification du MX vers l'extérieur, et rien d'autre ?

    Expéditeur vide et aucun destinataire dans un domaine protégé. Sans moyen
    de vérifier, ou sur un domaine dont la vérification échoue, la réponse est
    non : le message compte comme entrant.
    """
    if is_relay_domain is None or record.get("sender") not in _NULL_SENDERS:
        return False
    recipients = record.get("recipients")
    if not isinstance(recipients, list) or not recipients:
        return False
    for recipient in recipients:
        address = recipient.get("address") if isinstance(recipient, dict) else None
        if not isinstance(address, str) or "@" not in address:
            return False
        if is_relay_domain(address.rsplit("@", 1)[1].lower()) is not False:
            return False
    return True


def queue_snapshot(
    data: bytes, *, now: float, threshold_seconds: int = MAX_QUEUE_AGE_SECONDS,
    max_messages: int = MAX_QUEUE_MESSAGES, is_relay_domain: RelayLookup | None = None,
) -> dict[str, Any]:
    messages = blocked = future = outbound = 0
    oldest = oldest_outbound = 0.0
    for line in data.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ProbeFailure("invalid_queue_json") from exc
        if not isinstance(record, dict):
            raise ProbeFailure("invalid_queue_record")
        arrived = record.get("arrival_time")
        if (not isinstance(arrived, (int, float)) or isinstance(arrived, bool)
            or not math.isfinite(arrived) or arrived < 0):
            raise ProbeFailure("invalid_queue_timestamp")
        messages += 1
        if messages > max_messages:
            raise ProbeFailure("queue_message_limit")
        age = max(0.0, now-arrived)
        oldest = max(oldest, age)
        future += arrived > now
        if age <= threshold_seconds:
            continue
        if _outbound_notice(record, is_relay_domain):
            outbound += 1
            oldest_outbound = max(oldest_outbound, age)
        else:
            blocked += 1
    reason = (
        "inbound_queue_stalled" if blocked
        else "outbound_notices_deferred" if outbound
        else "queue_within_deadline"
    )
    return {
        "status": "blocked" if blocked else "ok",
        "reason": reason,
        "queue_messages": messages,
        "blocked_messages": blocked,
        "oldest_age_seconds": round(oldest, 3),
        "outbound_notices_deferred": outbound,
        "oldest_outbound_notice_age_seconds": round(oldest_outbound, 3),
        "future_timestamps": future,
        "threshold_seconds": threshold_seconds,
    }


def _relay_tables(timeout_seconds: float) -> tuple[set[str], list[str]] | None:
    """Les domaines écrits en clair et les tables de relay_domains, ou None."""
    try:
        listing = subprocess.run(
            ["postconf", "-h", "relay_domains"], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=timeout_seconds, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = getattr(listing, "stdout", None)
    if listing.returncode != 0 or not isinstance(output, bytes):
        return None
    tokens = output.decode("utf-8", "replace").replace(",", " ").split()
    literals = {t.lower() for t in tokens if ":" not in t and not t.startswith("/")}
    return literals, [t for t in tokens if ":" in t]


def _in_table(domain: str, table: str, timeout_seconds: float) -> Optional[bool]:
    try:
        found = subprocess.run(
            ["postmap", "-q", domain, table], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=timeout_seconds, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return True if found.returncode == 0 else False if found.returncode == 1 else None


def relay_domain_lookup(
    *, timeout_seconds: float = LOOKUP_TIMEOUT_SECONDS,
    budget_seconds: float = LOOKUP_BUDGET_SECONDS,
) -> RelayLookup:
    """Interroge les tables relay_domains de Postfix, avec les mêmes réponses
    que le MX lui-même : vrai, faux, ou None si une table ne répond pas ou si
    le budget de temps est épuisé. Rien n'est lu tant qu'aucun vieux message à
    expéditeur vide ne le demande."""
    loaded: list[tuple[set[str], list[str]] | None] = []
    cache: dict[str, Optional[bool]] = {}
    deadline: list[float] = []

    def remaining() -> float:
        if not deadline:
            deadline.append(time.monotonic()+budget_seconds)
        return min(timeout_seconds, deadline[0]-time.monotonic())

    def lookup(domain: str) -> Optional[bool]:
        domain = domain.lower()
        if domain in cache:
            return cache[domain]
        if len(cache) >= MAX_DOMAIN_LOOKUPS or remaining() <= 0:
            return None
        if not loaded:
            loaded.append(_relay_tables(remaining()))
        tables = loaded[0]
        answer: Optional[bool] = None
        if tables is not None:
            literals, maps = tables
            answer = True if domain in literals else False
            for table in maps:
                if answer:
                    break
                budget = remaining()
                found = _in_table(domain, table, budget) if budget > 0 else None
                answer = found
                if found is None:
                    break
        cache[domain] = answer
        return answer

    return lookup


def read_queue(
    *, timeout_seconds: float = QUEUE_TIMEOUT_SECONDS,
    max_bytes: int = MAX_QUEUE_BYTES,
) -> bytes:
    """Lit le protocole JSON ligne par ligne sous plafond de temps et mémoire."""
    try:
        process = subprocess.Popen(
            ["postqueue", "-j"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise ProbeFailure("postqueue_unavailable") from exc
    deadline = time.monotonic()+timeout_seconds
    output = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline-time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise ProbeFailure("postqueue_timeout")
                chunk = os.read(process.stdout.fileno(), min(65536, max_bytes-len(output)+1))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > max_bytes:
                    raise ProbeFailure("queue_output_limit")
        try:
            code = process.wait(timeout=max(0.001, deadline-time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise ProbeFailure("postqueue_timeout") from exc
        if code != 0:
            raise ProbeFailure("postqueue_failed")
        return bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=0.5)
        process.stdout.close()


def main() -> int:
    try:
        try:
            status = subprocess.run(
                ["postfix", "status"], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=POSTFIX_TIMEOUT_SECONDS, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProbeFailure("postfix_status_unavailable") from exc
        if status.returncode != 0:
            raise ProbeFailure("postfix_not_running")
        snapshot = queue_snapshot(
            read_queue(), now=time.time(), is_relay_domain=relay_domain_lookup(),
        )
    except ProbeFailure as exc:
        snapshot = {"status": "error", "reason": str(exc)}
    except Exception:
        snapshot = {"status": "error", "reason": "queue_probe_failed"}
    print(json.dumps(snapshot, separators=(",", ":")))
    return 0 if snapshot["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
