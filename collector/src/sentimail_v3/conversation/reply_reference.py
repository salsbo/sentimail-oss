"""Retrouver le message auquel une réponse à MAIA fait suite.

Un message livré ne porte plus de bouton : pour le signaler, on écrit à MAIA
en réponse à ce message. Le client de messagerie recopie alors son identifiant
dans In-Reply-To et References. C'est un rattachement, jamais une preuve : cet
identifiant est connu de tout le fil, expéditeur compris. Le challenge par code
reste exigé avant que la réponse compte.

Le corps, lui, peut citer d'anciens jetons : un fil qui a circulé avant le
retrait du pied de page en porte un par échange. Un jeton du corps ne vaut donc
que s'il est le seul - plusieurs jetons ne désignent plus aucun dossier.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from sentimail_v3.conversation.action_tokens import ACTION_MARKER_RE

MAX_REFERENCES = 20

_BRACKETED = re.compile(r"<([^<>\s]+)>")


def _identifiers(value: str) -> list[str]:
    found = _BRACKETED.findall(value)
    return found if found else value.split()


def referenced_message_ids(
    in_reply_to: Iterable[str], references: Iterable[str]
) -> list[str]:
    """Les identifiants cités, du message parent au plus lointain.

    In-Reply-To nomme le parent. References liste le fil du plus ancien au plus
    récent : on le lit à rebours. Les identifiants des courriers de MAIA
    (« s3. ») ont leur propre voie, par jeton, et sont écartés ici.
    """
    ordered: list[str] = []
    candidates = [
        identifier
        for value in in_reply_to
        for identifier in _identifiers(str(value or ""))
    ]
    chain = [
        identifier
        for value in references
        for identifier in _identifiers(str(value or ""))
    ]
    candidates.extend(reversed(chain))
    for identifier in candidates:
        normalized = identifier.strip().strip("<>").casefold()
        if not normalized or normalized.startswith("s3.") or normalized in ordered:
            continue
        ordered.append(normalized)
        if len(ordered) == MAX_REFERENCES:
            break
    return ordered


def body_action_token(body: str) -> str | None:
    """Le jeton lu dans le corps, à condition qu'il soit seul."""
    tokens = {match.group(1) for match in ACTION_MARKER_RE.finditer(body or "")}
    return tokens.pop() if len(tokens) == 1 else None
