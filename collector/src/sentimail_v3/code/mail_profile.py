"""Mémoire d'une série de courriers, rattachée à son identité authentifiée.

Le nom affiché ne sert jamais de clé. Sur une infrastructure partagée,
l'adresse exacte reste nécessaire : le relais ne prouve pas la marque.
"""

from __future__ import annotations

import json
from email.utils import parseaddr
from typing import Any

import tldextract

from sentimail_v3.code.organisation import PUBLIC_MAILBOXES
from sentimail_v3.code.sender_identity import SHARED_TENANT_APEXES
from sentimail_v3.code.shared_esp import shared_esp_provider

# Référentiel des relais de confidentialité, dont le domaine ne désigne pas
# un correspondant. Ce sont des infrastructures, jamais des autorisations.
PRIVACY_RELAY_APEXES = frozenset({
    "appleid.com", "duck.com", "mozmail.com", "simplelogin.com", "simplelogin.co",
    "aleeas.com", "slmail.me", "passmail.net", "passinbox.com",
})
_extract = tldextract.TLDExtract(suffix_list_urls=())


def shared_sender_domain(domain: str) -> bool:
    """Le métier de cette infrastructure n'est pas celui de ses utilisateurs."""
    extracted = _extract(domain.casefold())
    apex = ".".join(p for p in (extracted.domain, extracted.suffix) if p)
    return (
        apex in PUBLIC_MAILBOXES or apex in SHARED_TENANT_APEXES
        or apex in PRIVACY_RELAY_APEXES or bool(shared_esp_provider(domain))
    )


def crowd_mailbox_domain(domain: str) -> bool:
    """Ce domaine réunit-il des comptes d'inconnus sans lien entre eux ?

    Messagerie publique (outlook.com, gmail.com...) ou espace partagé
    (onmicrosoft.com) : n'importe qui y ouvre une adresse, donc le passé du
    domaine ne dit rien d'une adresse nouvelle. Un relais de confidentialité
    n'en fait pas partie : chaque adresse relais naît d'une inscription du
    destinataire à un seul service.
    """
    extracted = _extract(domain.casefold())
    apex = ".".join(p for p in (extracted.domain, extracted.suffix) if p)
    return apex in PUBLIC_MAILBOXES or apex in SHARED_TENANT_APEXES


def mail_profile(
    sender: str, *, dmarc: bool, sending_mode: str,
    subject: str, list_id: str = "",
) -> dict[str, str] | None:
    """Décrit une série authentifiée, sans élargir une liste blanche."""
    address = parseaddr(sender)[1].strip().lower()
    if not dmarc or sending_mode != "bulk" or address.count("@") != 1:
        return None
    domain = address.rsplit("@", 1)[-1]
    extracted = _extract(domain)
    apex = ".".join(p for p in (extracted.domain, extracted.suffix) if p)
    if not extracted.suffix:
        return None
    shared = shared_sender_domain(domain)
    # Un List-ID distingue les listes d'une organisation. À défaut, conserver
    # l'objet exact normalisé : aucune approximation ni suppression de date.
    kind = "list_id" if list_id else "subject"
    value = " ".join((list_id or subject).lower().split())
    if not value or len(value) > 300:
        return None
    return {
        "version": "1", "identity_kind": "sender" if shared else "domain",
        "identity": address if shared else domain, "sending_mode": sending_mode,
        "type_kind": kind, "type_value": value,
    }


async def read_mail_profile(connection: Any, message_id: str) -> dict[str, str] | None:
    """Relit les faits de capture, jamais une identité fournie par le modèle."""
    row = await connection.fetchrow(
        """
        SELECT m.from_header, m.subject,
               EXISTS (
                   SELECT 1 FROM investigations i JOIN clues c ON c.investigation_id=i.id
                   WHERE i.message_id=m.id AND c.clue_code='AUTH_DMARC_PASS'
               ) AS dmarc,
               (SELECT h.facts->>'sending_mode' FROM investigations i
                JOIN hook_runs h ON h.investigation_id=i.id
                WHERE i.message_id=m.id AND h.hook_name='nature'
                ORDER BY h.created_at DESC LIMIT 1) AS sending_mode,
               (SELECT CASE WHEN count(*)=1 THEN min(value_decoded) ELSE '' END
                FROM headers WHERE message_id=m.id AND name_normalized='list-id') AS list_id
        FROM messages m WHERE m.id=$1::uuid
        """,
        message_id,
    )
    if row is None:
        return None
    return mail_profile(
        str(row.get("from_header") or ""), dmarc=bool(row.get("dmarc")),
        sending_mode=str(row.get("sending_mode") or ""),
        subject=str(row.get("subject") or ""), list_id=str(row.get("list_id") or ""),
    )


async def profile_history(connection: Any, message_id: str, participant: str) -> dict[str, object]:
    """Compte les décisions de ce client sur cette série, même après purge."""
    profile = await read_mail_profile(connection, message_id)
    if profile is None:
        return {}
    rows = await connection.fetch(
        """
        SELECT label, count(DISTINCT coalesce(message_id::text,
                   context->>'mail_profile_message_id')) AS count
        FROM labels
        WHERE active=true AND is_ground_truth=true AND source='smtp_feedback_user'
          AND sentimail_same_client(participant_email,$1)
          AND md5((context->'mail_profile')::text)=md5(($2::jsonb)::text)
          AND context->'mail_profile'=$2::jsonb
          AND coalesce(message_id::text,context->>'mail_profile_message_id')<>$3
        GROUP BY label
        """,
        participant, json.dumps(profile, ensure_ascii=False), message_id,
    )
    counts = {str(r["label"]): int(r["count"]) for r in rows}
    return {"profile": profile, "labels": counts}
